use embednfs_proto::*;

use crate::fs::{FileSystem, FileType, FsError, WriteCapability};

use super::super::handles::join_path;
use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_close(
        &self,
        args: &CloseArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        if self.fs.capabilities().write_capability == WriteCapability::ReplaceOnly
            && let Ok(path) = self.resolve_fh(current_fh)
            && let Err(e) = self.commit_stage(&path).await
        {
            return NfsResop4::Close(e.to_nfsstat4(), Stateid4::default());
        }

        match self.state.close_state(&args.open_stateid).await {
            Ok(stateid) => NfsResop4::Close(NfsStat4::Ok, stateid),
            Err(status) => NfsResop4::Close(status, Stateid4::default()),
        }
    }

    pub(crate) async fn op_commit(
        &self,
        _args: &CommitArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Commit(status, [0u8; 8]),
        };

        let result = if self.fs.capabilities().write_capability == WriteCapability::ReplaceOnly {
            self.commit_stage(&path).await.map(|_| ())
        } else {
            self.fs.sync(&path).await
        };

        match result {
            Ok(()) => NfsResop4::Commit(NfsStat4::Ok, self.state.write_verifier),
            Err(e) => NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
        }
    }

    pub(crate) async fn op_open(
        &self,
        args: &OpenArgs4,
        current_fh: &mut Option<NfsFh4>,
        session_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Open(status, None),
        };

        // Derive clientid from session — server MUST ignore args.owner.clientid
        // (RFC 8881 §18.16.3).
        let clientid = match session_clientid {
            Some(id) => id,
            None => return NfsResop4::Open(NfsStat4::BadStateid, None),
        };

        // Strip the WANT_DELEG hint bits from share_access (RFC 8881 §18.16.3).
        let share_access = args.share_access & !OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
        let share_deny = args.share_deny;

        let (path, created) = match &args.claim {
            OpenClaim4::Null(name) => {
                let path = match join_path(&dir_path, name) {
                    Ok(path) => path,
                    Err(status) => return NfsResop4::Open(status, None),
                };
                match self.fs.metadata(&path).await {
                    Ok(_) => (path, false),
                    Err(FsError::Noent) => match &args.openhow {
                        Openflag4::Create(_) => match self.fs.create_file(&path).await {
                            Ok(()) => (path, true),
                            Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                        },
                        Openflag4::NoCreate => return NfsResop4::Open(NfsStat4::Noent, None),
                    },
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            // CLAIM_FH: current_fh is the file itself, not a directory.
            OpenClaim4::Fh => {
                let path = dir_path.clone();
                match self.fs.metadata(&path).await {
                    Ok(_) => (path, false),
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            OpenClaim4::Previous(_)
            | OpenClaim4::DelegCurFh(_)
            | OpenClaim4::DelegPrevFh => (dir_path.clone(), false),
            _ => return NfsResop4::Open(NfsStat4::Notsupp, None),
        };

        let dir_attr = match self.attr_for_path(&dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
        };
        let fh = self.handles.lock().unwrap().get_or_create(&path);
        let fileid = self.fileid_for_fh(&fh);

        // Check for existing open by same owner (open-owner dedup / upgrade).
        let stateid = if let Some((other, _seq, _access, _deny)) = self
            .state
            .find_open_by_owner(fileid, clientid, &args.owner.owner)
            .await
        {
            self.state
                .upgrade_open_state(&other, share_access, share_deny)
                .await
        } else {
            // Check for share conflicts with existing opens.
            if let Err(status) = self
                .state
                .check_share_conflict(fileid, share_access, share_deny)
                .await
            {
                return NfsResop4::Open(status, None);
            }
            self.state
                .create_open_state(
                    fileid,
                    clientid,
                    &args.owner.owner,
                    share_access,
                    share_deny,
                )
                .await
        };

        *current_fh = Some(fh);

        let cinfo = ChangeInfo4 {
            atomic: true,
            before: dir_attr.change_id.wrapping_sub(if created { 1 } else { 0 }),
            after: dir_attr.change_id,
        };

        NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid,
                cinfo,
                rflags: OPEN4_RESULT_LOCKTYPE_POSIX,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::None,
            }),
        )
    }

    pub(crate) async fn op_read(
        &self,
        args: &ReadArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: &Option<Stateid4>,
        session_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        // Resolve current stateid if used.
        let stateid = Self::resolve_stateid(&args.stateid, current_stateid);
        match self.state.validate_stateid(&stateid, session_clientid).await {
            Ok(vs) => {
                if vs.share_access & OPEN4_SHARE_ACCESS_READ == 0 {
                    return NfsResop4::Read(NfsStat4::Openmode, None);
                }
            }
            Err(status) => return NfsResop4::Read(status, None),
        }

        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Read(status, None),
        };

        let metadata = match self.fs.metadata(&path).await {
            Ok(metadata) => metadata,
            Err(e) => return NfsResop4::Read(e.to_nfsstat4(), None),
        };

        match metadata.file_type {
            FileType::Directory => return NfsResop4::Read(NfsStat4::Isdir, None),
            FileType::Symlink => return NfsResop4::Read(NfsStat4::Symlink, None),
            FileType::Regular => {}
        }

        let stage_len = match self.stage_len(&path).await {
            Ok(stage_len) => stage_len,
            Err(e) => return NfsResop4::Read(e.to_nfsstat4(), None),
        };
        let read_result = if stage_len.is_some() {
            self.read_from_stage(&path, args.offset, args.count).await
        } else {
            self.fs.read(&path, args.offset, args.count).await
        };

        match read_result {
            Ok(data) => {
                let total_size = stage_len.unwrap_or(metadata.size);
                let eof = args.offset.saturating_add(data.len() as u64) >= total_size;
                NfsResop4::Read(NfsStat4::Ok, Some(ReadRes4 { eof, data }))
            }
            Err(e) => NfsResop4::Read(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_readlink(&self, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Readlink(status, None),
        };

        match self.fs.read_symlink(&path).await {
            Ok(target) => NfsResop4::Readlink(NfsStat4::Ok, Some(target)),
            Err(e) => NfsResop4::Readlink(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_write(
        &self,
        args: &WriteArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: &Option<Stateid4>,
        session_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let stateid = Self::resolve_stateid(&args.stateid, current_stateid);
        match self.state.validate_stateid(&stateid, session_clientid).await {
            Ok(vs) => {
                if vs.share_access & OPEN4_SHARE_ACCESS_WRITE == 0 {
                    return NfsResop4::Write(NfsStat4::Openmode, None);
                }
            }
            Err(status) => return NfsResop4::Write(status, None),
        }

        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Write(status, None),
        };

        let capability = self.fs.capabilities().write_capability;
        let write_result = if capability.supports_random_write() {
            self.fs.write_file(&path, args.offset, &args.data).await
        } else if capability.supports_replace() {
            self.stage_write(&path, args.offset, &args.data).await
        } else {
            Err(FsError::Notsupp)
        };

        match write_result {
            Ok(count) => {
                let committed = if capability.supports_replace() && !capability.supports_random_write()
                {
                    if args.stable == UNSTABLE4 {
                        UNSTABLE4
                    } else {
                        match self.commit_stage(&path).await {
                            Ok(_) => FILE_SYNC4,
                            Err(e) => return NfsResop4::Write(e.to_nfsstat4(), None),
                        }
                    }
                } else {
                    if args.stable != UNSTABLE4
                        && let Err(e) = self.fs.sync(&path).await
                    {
                        return NfsResop4::Write(e.to_nfsstat4(), None);
                    }
                    FILE_SYNC4
                };

                NfsResop4::Write(
                    NfsStat4::Ok,
                    Some(WriteRes4 {
                        count,
                        committed,
                        writeverf: self.state.write_verifier,
                    }),
                )
            }
            Err(e) => NfsResop4::Write(e.to_nfsstat4(), None),
        }
    }

    /// Resolve a stateid, substituting the current stateid for the
    /// special "current" value (seqid=1, other=all-zero).
    fn resolve_stateid(stateid: &Stateid4, current: &Option<Stateid4>) -> Stateid4 {
        if stateid.seqid == 1 && stateid.other == [0u8; 12]
            && let Some(cur) = current {
                return *cur;
            }
        *stateid
    }
}

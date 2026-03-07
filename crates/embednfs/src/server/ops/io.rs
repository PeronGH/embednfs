use embednfs_proto::*;

use crate::fs::{FileSystem, FileType, FsError, WriteCapability};

use super::super::handles::{join_path, path_to_fh, synthetic_fileid};
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
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Open(status, None),
        };

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
            OpenClaim4::Fh
            | OpenClaim4::Previous(_)
            | OpenClaim4::DelegCurFh(_)
            | OpenClaim4::DelegPrevFh => (dir_path.clone(), false),
            _ => return NfsResop4::Open(NfsStat4::Notsupp, None),
        };

        let dir_attr = self.attr_for_path(&dir_path).await.unwrap_or_default();
        let stateid = self
            .state
            .create_open_state(
                synthetic_fileid(&path),
                args.owner.clientid,
                args.share_access,
                args.share_deny,
            )
            .await;

        *current_fh = Some(path_to_fh(&path));

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
    ) -> NfsResop4 {
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

        let stage_len = self.stage_len(&path).await;
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
    ) -> NfsResop4 {
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
}

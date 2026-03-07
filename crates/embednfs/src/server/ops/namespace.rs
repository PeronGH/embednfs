use tracing::{debug, trace};

use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileSystem, FsError};

use super::super::handles::{join_path, parent_path};
use super::super::util::{readdir_dir_info_len, readdir_entry_list_item_len, readdir_resok_len};
use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_create(
        &self,
        args: &CreateArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let dir_attr_before = match self.attr_for_path(&dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        };

        let path = match join_path(&dir_path, &args.objname) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let result = match &args.objtype {
            Createtype4::Dir => self.fs.create_dir(&path).await,
            Createtype4::Link(target) => self.fs.create_symlink(&path, target).await,
            _ => Err(FsError::Notsupp),
        };

        match result {
            Ok(()) => {
                let dir_attr_after = match self.attr_for_path(&dir_path).await {
                    Ok(attr) => attr,
                    Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
                };
                *current_fh = Some(self.handles.lock().unwrap().get_or_create(&path));
                let cinfo = ChangeInfo4 {
                    atomic: true,
                    before: dir_attr_before.change_id,
                    after: dir_attr_after.change_id,
                };
                NfsResop4::Create(NfsStat4::Ok, Some(cinfo), args.createattrs.attrmask.clone())
            }
            Err(e) => NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        }
    }

    pub(crate) async fn op_link(
        &self,
        _args: &LinkArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let _source_path = match self.resolve_fh(saved_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Link(status, None),
        };
        let _dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Link(status, None),
        };
        NfsResop4::Link(NfsStat4::Notsupp, None)
    }

    pub(crate) async fn op_lookup(
        &self,
        args: &LookupArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Lookup(status),
        };

        let child_path = match join_path(&dir_path, &args.objname) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Lookup(status),
        };

        match self.fs.metadata(&child_path).await {
            Ok(_) => {
                *current_fh = Some(self.handles.lock().unwrap().get_or_create(&child_path));
                NfsResop4::Lookup(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookup(e.to_nfsstat4()),
        }
    }

    pub(crate) async fn op_lookupp(&self, current_fh: &mut Option<NfsFh4>) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Lookupp(status),
        };

        *current_fh = Some(self.handles.lock().unwrap().get_or_create(&parent_path(&path)));
        NfsResop4::Lookupp(NfsStat4::Ok)
    }

    pub(crate) async fn op_readdir(
        &self,
        args: &ReaddirArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Readdir(status, None),
        };

        let dir_attr = match self.attr_for_path(&dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        let cookieverf = dir_attr.change_id.to_be_bytes();

        debug!(
            "READDIR request: path={dir_path}, cookie={}, cookieverf={:02x?}, dircount={}, maxcount={}, attr_request={:?}",
            args.cookie,
            args.cookieverf,
            args.dircount,
            args.maxcount,
            args.attr_request.0
        );

        if args.cookie != 0 && args.cookieverf != cookieverf {
            debug!(
                "READDIR verifier mismatch: path={dir_path}, cookie={}, request={:02x?}, current={:02x?}",
                args.cookie,
                args.cookieverf,
                cookieverf
            );
            return NfsResop4::Readdir(NfsStat4::NotSame, None);
        }

        match self.fs.list(&dir_path).await {
            Ok(entries) => {
                let cookie_start = match args.cookie {
                    0..=2 => 0,
                    cookie => cookie.saturating_sub(2) as usize,
                };
                let available = &entries[cookie_start.min(entries.len())..];
                let maxcount_limit = args.maxcount as usize;
                let dircount_limit = if args.dircount == 0 {
                    usize::MAX
                } else {
                    args.dircount as usize
                };

                let base_resok_len = readdir_resok_len(&[], false);
                if base_resok_len > maxcount_limit {
                    debug!(
                        "READDIR maxcount too small for reply header: path={dir_path}, maxcount={}, header_bytes={base_resok_len}",
                        args.maxcount
                    );
                    return NfsResop4::Readdir(NfsStat4::Toosmall, None);
                }

                let mut result_entries = Vec::with_capacity(available.len().min(64));
                let mut dir_bytes = 0usize;
                let mut total_resok_bytes = base_resok_len;

                for (i, entry) in available.iter().enumerate() {
                    let entry_path = match join_path(&dir_path, &entry.name) {
                        Ok(path) => path,
                        Err(status) => return NfsResop4::Readdir(status, None),
                    };
                    let (entry_fh, entry_fileid) = {
                        let mut handles = self.handles.lock().unwrap();
                        let fh = handles.get_or_create(&entry_path);
                        let fileid = handles.fileid(&fh).ok();
                        (fh, fileid)
                    };
                    let entry_attr = attrs::synthesize_file_attr(
                        &entry_path,
                        &entry.metadata,
                        &self.fs.capabilities(),
                        entry_fileid,
                    );
                    let entry_fattr = attrs::encode_fattr4(
                        &entry_attr,
                        &args.attr_request,
                        &entry_fh,
                        &self.fs.capabilities().fs_info,
                    );
                    let result_entry = Entry4 {
                        cookie: (cookie_start + i + 3) as u64,
                        name: entry.name.clone(),
                        attrs: entry_fattr,
                    };

                    let dir_entry_size = readdir_dir_info_len(&result_entry);
                    let entry_total = readdir_entry_list_item_len(&result_entry);
                    let exceeds_dircount = dir_bytes + dir_entry_size > dircount_limit;
                    let exceeds_maxcount = total_resok_bytes + entry_total > maxcount_limit;

                    if !result_entries.is_empty() && (exceeds_dircount || exceeds_maxcount) {
                        break;
                    }

                    if result_entries.is_empty() && exceeds_maxcount {
                        debug!(
                            "READDIR maxcount too small for a single entry: path={dir_path}, name={}, maxcount={}, entry_bytes={entry_total}, base_bytes={base_resok_len}",
                            result_entry.name,
                            args.maxcount
                        );
                        return NfsResop4::Readdir(NfsStat4::Toosmall, None);
                    }

                    dir_bytes += dir_entry_size;
                    total_resok_bytes += entry_total;
                    result_entries.push(result_entry);
                }

                let eof = result_entries.len() == available.len();
                debug!(
                    "READDIR response: path={dir_path}, cookie={}, entries={}, eof={}, dir_bytes={}, resok_bytes={}, cookieverf={:02x?}",
                    args.cookie,
                    result_entries.len(),
                    eof,
                    dir_bytes,
                    total_resok_bytes,
                    cookieverf
                );
                for entry in &result_entries {
                    debug!(
                        "READDIR entry: path={dir_path}, cookie={}, name={:?}, returned={:?}, attr_bytes={}",
                        entry.cookie,
                        entry.name,
                        entry.attrs.attrmask.0,
                        entry.attrs.attr_vals.len()
                    );
                    trace!(
                        "READDIR entry payload: path={dir_path}, cookie={}, name={:?}, attr_hex={}",
                        entry.cookie,
                        entry.name,
                        super::super::util::hex_bytes(&entry.attrs.attr_vals)
                    );
                }

                NfsResop4::Readdir(
                    NfsStat4::Ok,
                    Some(ReaddirRes4 {
                        cookieverf,
                        entries: result_entries,
                        eof,
                    }),
                )
            }
            Err(e) => NfsResop4::Readdir(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_remove(
        &self,
        args: &RemoveArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Remove(status, None),
        };

        let dir_attr_before = match self.attr_for_path(&dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
        };

        let target_path = match join_path(&dir_path, &args.target) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Remove(status, None),
        };

        match self.fs.remove(&target_path, None).await {
            Ok(()) => {
                self.drop_stage(&target_path).await;
                self.handles.lock().unwrap().remove(&target_path);
                let dir_attr_after = match self.attr_for_path(&dir_path).await {
                    Ok(attr) => attr,
                    Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
                };
                let cinfo = ChangeInfo4 {
                    atomic: true,
                    before: dir_attr_before.change_id,
                    after: dir_attr_after.change_id,
                };
                NfsResop4::Remove(NfsStat4::Ok, Some(cinfo))
            }
            Err(e) => NfsResop4::Remove(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_rename(
        &self,
        args: &RenameArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let src_dir_path = match self.resolve_fh(saved_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };
        let tgt_dir_path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };

        let src_attr_before = match self.attr_for_path(&src_dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };
        let tgt_attr_before = match self.attr_for_path(&tgt_dir_path).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };

        let from_path = match join_path(&src_dir_path, &args.oldname) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };
        let to_path = match join_path(&tgt_dir_path, &args.newname) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };

        match self.fs.rename(&from_path, &to_path, None).await {
            Ok(()) => {
                self.rename_stage(&from_path, &to_path).await;
                self.handles.lock().unwrap().rename(&from_path, &to_path);
                let src_attr_after = match self.attr_for_path(&src_dir_path).await {
                    Ok(attr) => attr,
                    Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
                };
                let tgt_attr_after = match self.attr_for_path(&tgt_dir_path).await {
                    Ok(attr) => attr,
                    Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
                };
                let src_cinfo = ChangeInfo4 {
                    atomic: true,
                    before: src_attr_before.change_id,
                    after: src_attr_after.change_id,
                };
                let tgt_cinfo = ChangeInfo4 {
                    atomic: true,
                    before: tgt_attr_before.change_id,
                    after: tgt_attr_after.change_id,
                };
                NfsResop4::Rename(NfsStat4::Ok, Some(src_cinfo), Some(tgt_cinfo))
            }
            Err(e) => NfsResop4::Rename(e.to_nfsstat4(), None, None),
        }
    }
}

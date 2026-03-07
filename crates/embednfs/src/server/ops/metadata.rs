use tracing::{debug, trace};

use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileSystem, FileType, FsError, WriteCapability};

use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_access(
        &self,
        args: &AccessArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Access(status, 0, 0),
        };

        match self.attr_for_path(&path).await {
            Ok(attr) => {
                let mut server_supported = ACCESS4_READ
                    | ACCESS4_LOOKUP
                    | ACCESS4_MODIFY
                    | ACCESS4_EXTEND
                    | ACCESS4_DELETE
                    | ACCESS4_EXECUTE;
                if attr.file_type == FileType::Directory {
                    server_supported &= !ACCESS4_EXECUTE;
                }
                let supported = args.access & server_supported;

                // Check actual permissions from metadata (RFC 8881 §18.1).
                let mut granted = supported;
                if attr.mode & 0o222 == 0 {
                    granted &= !(ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE);
                }
                if attr.file_type != FileType::Directory && attr.mode & 0o111 == 0 {
                    granted &= !ACCESS4_EXECUTE;
                }
                NfsResop4::Access(NfsStat4::Ok, supported, granted)
            }
            Err(e) => NfsResop4::Access(e.to_nfsstat4(), 0, 0),
        }
    }

    pub(crate) async fn op_getattr(
        &self,
        args: &GetattrArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Getattr(status, None),
        };
        let fh = current_fh.as_ref().unwrap();

        match self.attr_for_path(&path).await {
            Ok(attr) => {
                let caps = self.fs.capabilities();
                let fattr = attrs::encode_fattr4(&attr, &args.attr_request, fh, &caps.fs_info);
                debug!(
                    "GETATTR response: path={path}, request={:?}, returned={:?}, attr_bytes={}",
                    args.attr_request.0,
                    fattr.attrmask.0,
                    fattr.attr_vals.len()
                );
                trace!(
                    "GETATTR attr payload: path={path}, attr_hex={}",
                    super::super::util::hex_bytes(&fattr.attr_vals)
                );
                NfsResop4::Getattr(NfsStat4::Ok, Some(fattr))
            }
            Err(e) => NfsResop4::Getattr(e.to_nfsstat4(), None),
        }
    }

    pub(crate) async fn op_getfh(&self, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        match current_fh {
            Some(fh) => NfsResop4::Getfh(NfsStat4::Ok, Some(fh.clone())),
            None => NfsResop4::Getfh(NfsStat4::Nofilehandle, None),
        }
    }

    pub(crate) async fn op_setattr(
        &self,
        args: &SetattrArgs4,
        current_fh: &Option<NfsFh4>,
        current_stateid: &Option<Stateid4>,
        session_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        let set_attrs = match attrs::decode_setattr(&args.obj_attributes) {
            Ok(attrs) => attrs,
            Err(_) => return NfsResop4::Setattr(NfsStat4::BadXdr, Bitmap4::new()),
        };
        let mut applied = Bitmap4::new();
        let attrmask = &args.obj_attributes.attrmask;

        if attrmask.is_set(FATTR4_SIZE) {
            // Validate stateid for size changes.
            let stateid = if args.stateid.seqid == 1 && args.stateid.other == [0u8; 12] {
                (*current_stateid).unwrap_or(args.stateid)
            } else {
                args.stateid
            };
            if let Err(status) = self
                .state
                .validate_stateid(&stateid, session_clientid)
                .await
            {
                return NfsResop4::Setattr(status, Bitmap4::new());
            }
            let Some(size) = set_attrs.size else {
                return NfsResop4::Setattr(NfsStat4::BadXdr, Bitmap4::new());
            };
            let result = if self.fs.capabilities().write_capability == WriteCapability::ReplaceOnly {
                self.stage_set_len(&path, size).await
            } else {
                self.fs.set_len(&path, size).await
            };
            match result {
                Ok(()) => applied.set(FATTR4_SIZE),
                Err(FsError::Notsupp) | Err(FsError::AttrNotsupp) => {
                    return NfsResop4::Setattr(NfsStat4::AttrNotsupp, Bitmap4::new());
                }
                Err(e) => return NfsResop4::Setattr(e.to_nfsstat4(), Bitmap4::new()),
            }
        }

        if attrmask.is_set(FATTR4_MODE)
            || attrmask.is_set(FATTR4_OWNER)
            || attrmask.is_set(FATTR4_OWNER_GROUP)
            || attrmask.is_set(FATTR4_TIME_ACCESS_SET)
            || attrmask.is_set(FATTR4_TIME_MODIFY_SET)
            || attrmask.is_set(FATTR4_TIME_CREATE)
            || attrmask.is_set(FATTR4_TIME_BACKUP)
            || attrmask.is_set(FATTR4_ARCHIVE)
            || attrmask.is_set(FATTR4_HIDDEN)
            || attrmask.is_set(FATTR4_SYSTEM)
        {
            return NfsResop4::Setattr(NfsStat4::AttrNotsupp, applied);
        }

        NfsResop4::Setattr(NfsStat4::Ok, applied)
    }
}

use embednfs_proto::*;

use crate::fs::{FileSystem, RequestContext};
use crate::internal::ServerFileType;

use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_lock(
        &self,
        request_ctx: &RequestContext,
        args: &LockArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lock(status, None, None),
        };

        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lock(e.to_nfsstat4(), None, None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lock(NfsStat4::Isdir, None, None);
        }

        match &args.locker {
            Locker4::NewLockOwner(new_owner) => {
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &new_owner.lock_owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        None,
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .create_lock_state(
                        &new_owner.open_stateid,
                        &new_owner.lock_owner,
                        object,
                        args.locktype,
                        args.offset,
                        args.length,
                    )
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
            Locker4::ExistingLockOwner(existing) => {
                let (lock_object, owner) =
                    match self.state.lock_state_info(&existing.lock_stateid).await {
                        Some(info) => info,
                        None => return NfsResop4::Lock(NfsStat4::BadStateid, None, None),
                    };
                if lock_object != object {
                    return NfsResop4::Lock(NfsStat4::BadStateid, None, None);
                }
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        Some(&existing.lock_stateid),
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .update_lock_state(
                        &existing.lock_stateid,
                        args.locktype,
                        args.offset,
                        args.length,
                    )
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
        }
    }

    pub(crate) async fn op_lockt(
        &self,
        request_ctx: &RequestContext,
        args: &LocktArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lockt(status, None),
        };
        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lockt(e.to_nfsstat4(), None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lockt(NfsStat4::Isdir, None);
        }
        match self
            .state
            .find_lock_conflict(
                &object,
                &args.owner,
                args.locktype,
                args.offset,
                args.length,
                None,
            )
            .await
        {
            Some(denied) => NfsResop4::Lockt(NfsStat4::Denied, Some(denied)),
            None => NfsResop4::Lockt(NfsStat4::Ok, None),
        }
    }

    pub(crate) async fn op_locku(&self, args: &LockuArgs4) -> NfsResop4 {
        match self
            .state
            .unlock_state(&args.lock_stateid, args.offset, args.length)
            .await
        {
            Ok(stateid) => NfsResop4::Locku(NfsStat4::Ok, Some(stateid)),
            Err(status) => NfsResop4::Locku(status, None),
        }
    }
}

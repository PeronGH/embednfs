use embednfs_proto::*;

use crate::attrs;
use crate::fs::FileSystem;

use super::super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(crate) async fn op_lock(
        &self,
        args: &LockArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let fh = match current_fh {
            Some(fh) => fh,
            None => return NfsResop4::Lock(NfsStat4::Nofilehandle, None, None),
        };
        let file_id = self.fileid_for_fh(fh);

        // Check for conflicting locks.
        let owner = match &args.locker {
            Locker4::NewLockOwner(new_owner) => &new_owner.lock_owner,
            Locker4::ExistingLockOwner(existing) => {
                // Look up the owner from the existing lock state.
                match self.state.lock_owner(&existing.lock_stateid).await {
                    Some(owner) => return self.do_lock_existing(
                        file_id, args, existing, &owner,
                    ).await,
                    None => return NfsResop4::Lock(NfsStat4::BadStateid, None, None),
                }
            }
        };

        if let Some(denied) = self
            .state
            .find_lock_conflict(file_id, &args.locktype, args.offset, args.length, owner)
            .await
        {
            return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
        }

        let Locker4::NewLockOwner(new_owner) = &args.locker else {
            unreachable!();
        };

        match self
            .state
            .create_lock_state(
                file_id,
                &new_owner.open_stateid,
                &new_owner.lock_owner,
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

    async fn do_lock_existing(
        &self,
        file_id: u64,
        args: &LockArgs4,
        existing: &ExistLockOwner4,
        owner: &StateOwner4,
    ) -> NfsResop4 {
        if let Some(denied) = self
            .state
            .find_lock_conflict(file_id, &args.locktype, args.offset, args.length, owner)
            .await
        {
            return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
        }

        match self
            .state
            .update_lock_state(
                file_id,
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

    pub(crate) async fn op_lockt(
        &self,
        args: &LocktArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let fh = match current_fh {
            Some(fh) => fh,
            None => return NfsResop4::Lockt(NfsStat4::Nofilehandle, None),
        };
        let file_id = self.fileid_for_fh(fh);

        match self
            .state
            .find_lock_conflict(file_id, &args.locktype, args.offset, args.length, &args.owner)
            .await
        {
            Some(denied) => NfsResop4::Lockt(NfsStat4::Denied, Some(denied)),
            None => NfsResop4::Lockt(NfsStat4::Ok, None),
        }
    }

    pub(crate) async fn op_locku(
        &self,
        args: &LockuArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let fh = match current_fh {
            Some(fh) => fh,
            None => return NfsResop4::Locku(NfsStat4::Nofilehandle, None),
        };
        let file_id = self.fileid_for_fh(fh);

        match self
            .state
            .unlock_state(file_id, &args.lock_stateid, args.offset, args.length)
            .await
        {
            Ok(stateid) => NfsResop4::Locku(NfsStat4::Ok, Some(stateid)),
            Err(status) => NfsResop4::Locku(status, None),
        }
    }

    pub(crate) async fn op_verify(
        &self,
        client_fattr: &Fattr4,
        current_fh: &Option<NfsFh4>,
        negate: bool,
    ) -> NfsResop4 {
        let make_res = |status| {
            if negate {
                NfsResop4::Nverify(status)
            } else {
                NfsResop4::Verify(status)
            }
        };

        let path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return make_res(status),
        };
        let fh = current_fh.as_ref().unwrap();

        let attr = match self.attr_for_path(&path).await {
            Ok(attr) => attr,
            Err(e) => return make_res(e.to_nfsstat4()),
        };

        let caps = self.fs.capabilities();
        let server_fattr = attrs::encode_fattr4(&attr, &client_fattr.attrmask, fh, &caps.fs_info);
        let attrs_match = server_fattr.attrmask == client_fattr.attrmask
            && server_fattr.attr_vals == client_fattr.attr_vals;

        if negate {
            if attrs_match {
                make_res(NfsStat4::Same)
            } else {
                make_res(NfsStat4::Ok)
            }
        } else if attrs_match {
            make_res(NfsStat4::Ok)
        } else {
            make_res(NfsStat4::NotSame)
        }
    }
}

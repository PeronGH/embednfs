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
        let _path = match self.resolve_fh(current_fh) {
            Ok(path) => path,
            Err(status) => return NfsResop4::Lock(status, None, None),
        };

        let stateid = match &args.locker {
            Locker4::NewLockOwner(new_owner) => {
                self.state
                    .create_lock_state(&new_owner.open_stateid, &new_owner.lock_owner)
                    .await
            }
            Locker4::ExistingLockOwner(existing) => {
                self.state.update_lock_state(&existing.lock_stateid).await
            }
        };

        match stateid {
            Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
            Err(status) => NfsResop4::Lock(status, None, None),
        }
    }

    pub(crate) async fn op_lockt(
        &self,
        _args: &LocktArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        match self.resolve_fh(current_fh) {
            Ok(_) => NfsResop4::Lockt(NfsStat4::Ok, None),
            Err(status) => NfsResop4::Lockt(status, None),
        }
    }

    pub(crate) async fn op_locku(&self, args: &LockuArgs4) -> NfsResop4 {
        match self.state.unlock_state(&args.lock_stateid).await {
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

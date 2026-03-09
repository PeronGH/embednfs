use crate::internal::ServerObject;

use super::StateManager;

impl StateManager {
    pub(crate) fn alloc_connection_id(&self) -> u64 {
        self.next_connectionid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn object_to_fh(&self, object: &ServerObject) -> embednfs_proto::NfsFh4 {
        if let Some(fh) = self.object_to_fh.get(object) {
            return embednfs_proto::NfsFh4(fh.value().to_vec());
        }
        let fh_num = self
            .next_fh
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let fh = fh_num.to_be_bytes();
        let _ = self.fh_to_object.insert(fh, object.clone());
        let _ = self.object_to_fh.insert(object.clone(), fh);
        embednfs_proto::NfsFh4(fh.to_vec())
    }

    pub(crate) fn fh_to_object(&self, fh: &embednfs_proto::NfsFh4) -> Option<ServerObject> {
        let key: [u8; 8] = fh.0.as_slice().try_into().ok()?;
        self.fh_to_object.get(&key).map(|r| r.value().clone())
    }
}

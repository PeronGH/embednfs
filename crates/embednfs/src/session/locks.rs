use std::sync::atomic::Ordering;

use embednfs_proto::*;

use crate::fs::FileId;

use super::manager::StateManager;
use super::state::{LockFileState, OpenFileState};

impl StateManager {
    /// Create an open state for a file. Returns a stateid.
    pub async fn create_open_state(
        &self,
        file_id: FileId,
        clientid: Clientid4,
        share_access: u32,
        share_deny: u32,
    ) -> Stateid4 {
        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&clientid.to_be_bytes());

        let mut inner = self.inner.write().await;
        inner.open_files.insert(
            other,
            OpenFileState {
                file_id,
                clientid,
                stateid_seq: 1,
                share_access,
                share_deny,
            },
        );

        Stateid4 { seqid: 1, other }
    }

    /// Close an open state.
    pub async fn close_state(&self, stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        inner
            .open_files
            .remove(&stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Ok(Stateid4 {
            seqid: stateid.seqid.wrapping_add(1),
            other: stateid.other,
        })
    }

    /// Free a stateid.
    pub async fn free_stateid(&self, stateid: &Stateid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.open_files.remove(&stateid.other);
        Ok(())
    }

    /// Create a new lock state (LOCK with new lock owner).
    pub async fn create_lock_state(
        &self,
        _open_stateid: &Stateid4,
        owner: &StateOwner4,
    ) -> Result<Stateid4, NfsStat4> {
        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&owner.clientid.to_be_bytes());

        let mut inner = self.inner.write().await;
        inner.lock_files.insert(
            other,
            LockFileState {
                owner: owner.clone(),
                stateid_seq: 1,
            },
        );

        Ok(Stateid4 { seqid: 1, other })
    }

    /// Update an existing lock state (LOCK with existing lock owner).
    pub async fn update_lock_state(&self, lock_stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }

    /// Unlock (LOCKU).
    pub async fn unlock_state(&self, lock_stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }
}

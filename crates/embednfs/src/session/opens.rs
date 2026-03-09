use embednfs_proto::{
    Clientid4, NfsStat4, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_ACCESS_READ,
    OPEN4_SHARE_ACCESS_WANT_DELEG_MASK, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_BOTH,
    OPEN4_SHARE_DENY_NONE, OPEN4_SHARE_DENY_READ, OPEN4_SHARE_DENY_WRITE, Stateid4,
};

use crate::internal::ServerObject;

use super::StateManager;
use super::model::OpenFileState;

impl StateManager {
    /// Create an open state for an object.
    pub(crate) async fn create_open_state(
        &self,
        object: ServerObject,
        clientid: Clientid4,
        share_access: u32,
        share_deny: u32,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        for state in inner.open_files.values() {
            if state.object == object
                && ((state.share_deny & share_access) != 0
                    || (share_deny & state.share_access) != 0)
            {
                return Err(NfsStat4::ShareDenied);
            }
        }

        let seq = self
            .next_stateid
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&clientid.to_be_bytes());

        inner.open_files.insert(
            other,
            OpenFileState {
                object,
                clientid,
                stateid_seq: 1,
                share_access,
                share_deny,
            },
        );

        Ok(Stateid4 { seqid: 1, other })
    }

    pub(super) fn validate_stateid_seq(stored_seq: u32, provided_seq: u32) -> Result<(), NfsStat4> {
        if provided_seq == 0 || provided_seq == stored_seq {
            Ok(())
        } else if provided_seq < stored_seq {
            Err(NfsStat4::OldStateid)
        } else {
            Err(NfsStat4::BadStateid)
        }
    }

    /// Close an open state.
    pub async fn close_state(&self, stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let stored_seq = inner
            .open_files
            .get(&stateid.other)
            .ok_or(NfsStat4::BadStateid)?
            .stateid_seq;
        Self::validate_stateid_seq(stored_seq, stateid.seqid)?;
        inner.open_files.remove(&stateid.other);
        Ok(Stateid4 {
            seqid: stored_seq.wrapping_add(1),
            other: stateid.other,
        })
    }

    /// Free a stateid.
    pub async fn free_stateid(&self, stateid: &Stateid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.open_files.remove(&stateid.other);
        inner.lock_files.remove(&stateid.other);
        Ok(())
    }

    pub async fn test_stateids(&self, stateids: &[Stateid4]) -> Vec<NfsStat4> {
        let inner = self.inner.read().await;
        stateids
            .iter()
            .map(|stateid| {
                if let Some(state) = inner.open_files.get(&stateid.other) {
                    match Self::validate_stateid_seq(state.stateid_seq, stateid.seqid) {
                        Ok(()) => NfsStat4::Ok,
                        Err(status) => status,
                    }
                } else if let Some(state) = inner.lock_files.get(&stateid.other) {
                    match Self::validate_stateid_seq(state.stateid_seq, stateid.seqid) {
                        Ok(()) => NfsStat4::Ok,
                        Err(status) => status,
                    }
                } else {
                    NfsStat4::BadStateid
                }
            })
            .collect()
    }

    pub async fn open_downgrade(
        &self,
        open_stateid: &Stateid4,
        share_access: u32,
        share_deny: u32,
    ) -> Result<Stateid4, NfsStat4> {
        let access_mode = share_access & !OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
        if !matches!(
            access_mode,
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_BOTH
        ) {
            return Err(NfsStat4::Inval);
        }
        if !matches!(
            share_deny,
            OPEN4_SHARE_DENY_NONE
                | OPEN4_SHARE_DENY_READ
                | OPEN4_SHARE_DENY_WRITE
                | OPEN4_SHARE_DENY_BOTH
        ) {
            return Err(NfsStat4::Inval);
        }

        let mut inner = self.inner.write().await;
        let state = inner
            .open_files
            .get_mut(&open_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Self::validate_stateid_seq(state.stateid_seq, open_stateid.seqid)?;

        let current_access = state.share_access & !OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
        if (access_mode & !current_access) != 0 || (share_deny & !state.share_deny) != 0 {
            return Err(NfsStat4::Inval);
        }

        state.share_access = share_access;
        state.share_deny = share_deny;
        state.stateid_seq = state.stateid_seq.wrapping_add(1);
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: open_stateid.other,
        })
    }
}

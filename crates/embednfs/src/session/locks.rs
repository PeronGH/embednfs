use std::sync::atomic::Ordering;

use embednfs_proto::*;

use crate::fs::FileId;

use super::manager::StateManager;
use super::state::{LockFileState, OpenFileState, ValidatedState};

impl StateManager {
    /// Check for share conflicts against existing opens on a file.
    pub async fn check_share_conflict(
        &self,
        file_id: FileId,
        share_access: u32,
        share_deny: u32,
    ) -> Result<(), NfsStat4> {
        let inner = self.inner.read().await;
        if let Some(open_others) = inner.file_opens.get(&file_id) {
            for other in open_others {
                if let Some(existing) = inner.open_files.get(other)
                    && ((share_access & existing.share_deny) != 0
                        || (share_deny & existing.share_access) != 0)
                    {
                        return Err(NfsStat4::ShareDenied);
                    }
            }
        }
        Ok(())
    }

    /// Find an existing open for the same file, client, and owner.
    /// Returns the stateid `other` and current state if found.
    pub async fn find_open_by_owner(
        &self,
        file_id: FileId,
        clientid: Clientid4,
        owner: &[u8],
    ) -> Option<([u8; 12], u32, u32, u32)> {
        let inner = self.inner.read().await;
        if let Some(open_others) = inner.file_opens.get(&file_id) {
            for other in open_others {
                if let Some(existing) = inner.open_files.get(other)
                    && existing.clientid == clientid && existing.owner == owner {
                        return Some((
                            *other,
                            existing.stateid_seq,
                            existing.share_access,
                            existing.share_deny,
                        ));
                    }
            }
        }
        None
    }

    /// Upgrade an existing open state's access/deny bits and bump seqid.
    pub async fn upgrade_open_state(
        &self,
        other: &[u8; 12],
        share_access: u32,
        share_deny: u32,
    ) -> Stateid4 {
        let mut inner = self.inner.write().await;
        let state = inner.open_files.get_mut(other).expect("open must exist");
        state.share_access |= share_access;
        state.share_deny |= share_deny;
        state.stateid_seq += 1;
        Stateid4 {
            seqid: state.stateid_seq,
            other: *other,
        }
    }

    /// Create an open state for a file. Returns a stateid.
    pub async fn create_open_state(
        &self,
        file_id: FileId,
        clientid: Clientid4,
        owner: &[u8],
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
                owner: owner.to_vec(),
                stateid_seq: 1,
                share_access,
                share_deny,
            },
        );
        inner.file_opens.entry(file_id).or_default().push(other);

        Stateid4 { seqid: 1, other }
    }

    /// Close an open state and clean up associated lock states.
    pub async fn close_state(&self, stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let open = inner
            .open_files
            .remove(&stateid.other)
            .ok_or(NfsStat4::BadStateid)?;

        // Remove from file_opens index.
        if let Some(opens) = inner.file_opens.get_mut(&open.file_id) {
            opens.retain(|o| o != &stateid.other);
            if opens.is_empty() {
                inner.file_opens.remove(&open.file_id);
            }
        }

        Ok(Stateid4 {
            seqid: stateid.seqid.wrapping_add(1),
            other: stateid.other,
        })
    }

    /// Free a stateid.
    pub async fn free_stateid(&self, stateid: &Stateid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        if let Some(open) = inner.open_files.remove(&stateid.other)
            && let Some(opens) = inner.file_opens.get_mut(&open.file_id) {
                opens.retain(|o| o != &stateid.other);
                if opens.is_empty() {
                    inner.file_opens.remove(&open.file_id);
                }
            }
        inner.lock_files.remove(&stateid.other);
        Ok(())
    }

    /// Validate a stateid for READ/WRITE/SETATTR operations.
    ///
    /// Returns the share_access bits of the validated open state.
    /// Special stateids (anonymous, bypass) are always valid.
    pub async fn validate_stateid(
        &self,
        stateid: &Stateid4,
        session_clientid: Option<Clientid4>,
    ) -> Result<ValidatedState, NfsStat4> {
        // Anonymous stateid: seqid=0, other=all-zero.
        if stateid.seqid == 0 && stateid.other == [0u8; 12] {
            return Ok(ValidatedState {
                share_access: OPEN4_SHARE_ACCESS_BOTH,
            });
        }
        // Read bypass stateid: seqid=0xffffffff, other=all-0xff.
        if stateid.seqid == 0xffffffff && stateid.other == [0xffu8; 12] {
            return Ok(ValidatedState {
                share_access: OPEN4_SHARE_ACCESS_READ,
            });
        }

        let inner = self.inner.read().await;
        if let Some(open) = inner.open_files.get(&stateid.other) {
            // Verify client ownership.
            if let Some(client) = session_clientid
                && open.clientid != client {
                    return Err(NfsStat4::BadStateid);
                }
            // Verify seqid (0 = don't check).
            if stateid.seqid != 0 && stateid.seqid != open.stateid_seq {
                if stateid.seqid < open.stateid_seq {
                    return Err(NfsStat4::OldStateid);
                }
                return Err(NfsStat4::BadStateid);
            }
            return Ok(ValidatedState {
                share_access: open.share_access,
            });
        }

        if inner.lock_files.contains_key(&stateid.other) {
            // Lock stateids are valid for I/O (inherit open's access).
            return Ok(ValidatedState {
                share_access: OPEN4_SHARE_ACCESS_BOTH,
            });
        }

        Err(NfsStat4::BadStateid)
    }

    /// Check if a stateid exists (for TEST_STATEID).
    pub async fn test_stateid(&self, stateid: &Stateid4) -> NfsStat4 {
        let inner = self.inner.read().await;
        if inner.open_files.contains_key(&stateid.other)
            || inner.lock_files.contains_key(&stateid.other)
        {
            NfsStat4::Ok
        } else {
            NfsStat4::BadStateid
        }
    }

    /// Downgrade an open state's access/deny bits.
    pub async fn open_downgrade(
        &self,
        stateid: &Stateid4,
        share_access: u32,
        share_deny: u32,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .open_files
            .get_mut(&stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        state.share_access = share_access;
        state.share_deny = share_deny;
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: stateid.other,
        })
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

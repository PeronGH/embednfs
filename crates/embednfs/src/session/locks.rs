use std::sync::atomic::Ordering;

use embednfs_proto::*;

use crate::fs::FileId;

use super::manager::StateManager;
use super::state::{LockFileState, LockRange, OpenFileState, ValidatedState};

impl StateManager {
    /// Look up the owner of a lock stateid.
    pub async fn lock_owner(&self, stateid: &Stateid4) -> Option<StateOwner4> {
        let inner = self.inner.read().await;
        inner
            .lock_files
            .get(&stateid.other)
            .map(|ls| ls.owner.clone())
    }

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

    /// Close an open state and clean up associated lock states and ranges.
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

        // Clean up lock states associated with this open.
        let lock_others: Vec<[u8; 12]> = inner
            .lock_files
            .iter()
            .filter(|(_, ls)| ls.open_stateid_other == stateid.other)
            .map(|(other, _)| *other)
            .collect();
        for other in &lock_others {
            inner.lock_files.remove(other);
        }
        // Remove lock ranges belonging to those lock stateids.
        if !lock_others.is_empty()
            && let Some(ranges) = inner.file_locks.get_mut(&open.file_id) {
                ranges.retain(|r| !lock_others.contains(&r.lock_stateid_other));
                if ranges.is_empty() {
                    inner.file_locks.remove(&open.file_id);
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
        if inner.lock_files.remove(&stateid.other).is_some() {
            // Remove lock ranges belonging to this lock stateid.
            for ranges in inner.file_locks.values_mut() {
                ranges.retain(|r| r.lock_stateid_other != stateid.other);
            }
            inner.file_locks.retain(|_, v| !v.is_empty());
        }
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

    /// Check for conflicting byte-range locks on a file.
    ///
    /// Two read locks never conflict. A write lock conflicts with any
    /// overlapping lock held by a different owner.
    pub async fn find_lock_conflict(
        &self,
        file_id: FileId,
        lock_type: &NfsLockType4,
        offset: u64,
        length: u64,
        owner: &StateOwner4,
    ) -> Option<LockDenied4> {
        let inner = self.inner.read().await;
        let ranges = inner.file_locks.get(&file_id)?;
        let is_write = matches!(lock_type, NfsLockType4::WriteLt | NfsLockType4::WritewLt);
        for r in ranges {
            // Same owner never conflicts with itself.
            if r.owner.clientid == owner.clientid && r.owner.owner == owner.owner {
                continue;
            }
            let existing_is_write =
                matches!(r.lock_type, NfsLockType4::WriteLt | NfsLockType4::WritewLt);
            // Two read locks never conflict.
            if !is_write && !existing_is_write {
                continue;
            }
            if ranges_overlap(offset, length, r.offset, r.length) {
                return Some(LockDenied4 {
                    offset: r.offset,
                    length: r.length,
                    locktype: r.lock_type,
                    owner: r.owner.clone(),
                });
            }
        }
        None
    }

    /// Create a new lock state and add a byte-range lock (LOCK with new lock owner).
    pub async fn create_lock_state(
        &self,
        file_id: FileId,
        open_stateid: &Stateid4,
        owner: &StateOwner4,
        lock_type: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        // Verify the open stateid exists.
        let inner_r = self.inner.read().await;
        if !inner_r.open_files.contains_key(&open_stateid.other) {
            return Err(NfsStat4::BadStateid);
        }
        drop(inner_r);

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
                open_stateid_other: open_stateid.other,
            },
        );
        inner.file_locks.entry(file_id).or_default().push(LockRange {
            offset,
            length,
            lock_type,
            owner: owner.clone(),
            lock_stateid_other: other,
        });

        Ok(Stateid4 { seqid: 1, other })
    }

    /// Update an existing lock state and add a byte-range lock (LOCK with existing lock owner).
    pub async fn update_lock_state(
        &self,
        file_id: FileId,
        lock_stateid: &Stateid4,
        lock_type: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        let owner = state.owner.clone();
        state.stateid_seq += 1;
        let new_seqid = state.stateid_seq;

        inner
            .file_locks
            .entry(file_id)
            .or_default()
            .push(LockRange {
                offset,
                length,
                lock_type,
                owner,
                lock_stateid_other: lock_stateid.other,
            });

        Ok(Stateid4 {
            seqid: new_seqid,
            other: lock_stateid.other,
        })
    }

    /// Unlock a byte-range (LOCKU).
    pub async fn unlock_state(
        &self,
        file_id: FileId,
        lock_stateid: &Stateid4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        state.stateid_seq += 1;
        let new_seqid = state.stateid_seq;

        // Remove matching lock ranges for this stateid + range.
        if let Some(ranges) = inner.file_locks.get_mut(&file_id) {
            ranges.retain(|r| {
                !(r.lock_stateid_other == lock_stateid.other
                    && ranges_overlap(r.offset, r.length, offset, length))
            });
            if ranges.is_empty() {
                inner.file_locks.remove(&file_id);
            }
        }

        Ok(Stateid4 {
            seqid: new_seqid,
            other: lock_stateid.other,
        })
    }
}

/// Check if two byte ranges overlap.
/// A length of 0 means "to end of file" (NFS4_UINT64_MAX equivalent).
fn ranges_overlap(off1: u64, len1: u64, off2: u64, len2: u64) -> bool {
    let end1 = if len1 == 0 { u64::MAX } else { off1.saturating_add(len1) };
    let end2 = if len2 == 0 { u64::MAX } else { off2.saturating_add(len2) };
    off1 < end2 && off2 < end1
}

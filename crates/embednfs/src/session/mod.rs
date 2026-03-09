use crate::internal::ServerObject;
use dashmap::DashMap;
/// NFSv4.1 session, object, and server-side state management.
use embednfs_proto::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::sync::RwLock;

mod filehandles;
mod metadata;
#[cfg(test)]
mod tests;

const MAX_FORE_CHAN_SLOTS: u32 = 64;
const MAX_REQUEST_SIZE: u32 = 1_049_620;
const MAX_CACHED_RESPONSE: u32 = 6144;
const SYNTH_FILEID_BASE: u64 = 1u64 << 63;

/// Server-owned metadata tracked for each visible object.
#[derive(Debug, Clone)]
pub(crate) struct SynthMeta {
    pub fileid: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub owner_group: String,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub change_id: u64,
    pub archive: bool,
    pub hidden: bool,
    pub system: bool,
    pub named_attr_count: Option<u64>,
}

#[derive(Debug, Clone)]
struct LockRange {
    locktype: NfsLockType4,
    offset: u64,
    length: u64,
}

#[derive(Debug)]
struct LockFileState {
    object: ServerObject,
    owner: StateOwner4,
    ranges: Vec<LockRange>,
    active: bool,
    stateid_seq: u32,
}

/// Manages all server-side state.
pub struct StateManager {
    inner: Arc<RwLock<StateInner>>,
    /// Lock-free file handle mappings (hot path).
    fh_to_object: DashMap<Vec<u8>, ServerObject>,
    object_to_fh: DashMap<ServerObject, Vec<u8>>,
    next_fh: AtomicU64,
    next_clientid: AtomicU64,
    next_stateid: AtomicU32,
    next_changeid: AtomicU64,
    next_synth_fileid: AtomicU64,
    next_connectionid: AtomicU64,
    /// Server boot verifier (changes each restart).
    pub write_verifier: Verifier4,
    pub server_owner: ServerOwner4,
}

struct StateInner {
    clients: HashMap<Clientid4, ClientState>,
    sessions: HashMap<Sessionid4, SessionState>,
    /// Open file state: stateid.other -> OpenFileState
    open_files: HashMap<[u8; 12], OpenFileState>,
    /// Lock state: stateid.other -> LockFileState
    lock_files: HashMap<[u8; 12], LockFileState>,
    /// Server-owned synthesized metadata.
    metadata: HashMap<ServerObject, SynthMeta>,
}

#[derive(Debug)]
struct ClientState {
    clientid: Clientid4,
    owner: ClientOwner4,
    confirmed: bool,
    reclaim_complete_global: bool,
    sequence_id: Sequenceid4,
    replaced_clientid: Option<Clientid4>,
}

struct SessionState {
    clientid: Clientid4,
    slots: Vec<SlotState>,
    connections: HashSet<u64>,
}

#[derive(Clone)]
struct CachedReplay {
    fingerprint: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone)]
struct SlotState {
    sequence_id: Sequenceid4,
    in_progress: Option<Vec<u8>>,
    cached_reply: Option<CachedReplay>,
}

pub(crate) struct SequenceCacheToken {
    sessionid: Sessionid4,
    slotid: Slotid4,
    fingerprint: Vec<u8>,
}

pub(crate) enum SequenceReplay {
    Execute(SequenceRes4, SequenceCacheToken),
    Replay(Vec<u8>),
    Error(NfsStat4),
}

#[derive(Debug)]
struct OpenFileState {
    object: ServerObject,
    clientid: Clientid4,
    stateid_seq: u32,
    share_access: u32,
    share_deny: u32,
}

impl StateManager {
    pub fn new() -> Self {
        let boot_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let verifier_value =
            boot_time.as_secs().rotate_left(32) ^ u64::from(boot_time.subsec_nanos());
        let mut write_verifier = [0u8; 8];
        write_verifier.copy_from_slice(&verifier_value.to_be_bytes());

        let server_owner = ServerOwner4 {
            minor_id: 0,
            major_id: b"embednfs".to_vec(),
        };

        StateManager {
            inner: Arc::new(RwLock::new(StateInner {
                clients: HashMap::new(),
                sessions: HashMap::new(),
                open_files: HashMap::new(),
                lock_files: HashMap::new(),
                metadata: HashMap::new(),
            })),
            fh_to_object: DashMap::new(),
            object_to_fh: DashMap::new(),
            next_fh: AtomicU64::new(1),
            next_clientid: AtomicU64::new(1),
            next_stateid: AtomicU32::new(1),
            next_changeid: AtomicU64::new(2),
            next_synth_fileid: AtomicU64::new(SYNTH_FILEID_BASE),
            next_connectionid: AtomicU64::new(1),
            write_verifier,
            server_owner,
        }
    }

    /// Handle EXCHANGE_ID.
    pub async fn exchange_id(&self, args: &ExchangeIdArgs4) -> ExchangeIdRes4 {
        let mut inner = self.inner.write().await;

        let (clientid, seq, confirmed) = if let Some(existing) =
            inner.clients.values().find(|client| {
                client.owner.ownerid == args.clientowner.ownerid
                    && client.owner.verifier == args.clientowner.verifier
            }) {
            (existing.clientid, existing.sequence_id, existing.confirmed)
        } else {
            let old_clientid = inner
                .clients
                .values()
                .find(|client| {
                    client.owner.ownerid == args.clientowner.ownerid
                        && client.owner.verifier != args.clientowner.verifier
                        && client.confirmed
                })
                .map(|client| client.clientid);

            let stale_unconfirmed: Vec<_> = inner
                .clients
                .values()
                .filter(|client| {
                    client.owner.ownerid == args.clientowner.ownerid
                        && client.owner.verifier != args.clientowner.verifier
                        && !client.confirmed
                })
                .map(|client| client.clientid)
                .collect();
            for stale_clientid in stale_unconfirmed {
                Self::drop_client_state(&mut inner, stale_clientid);
            }

            let id = self.next_clientid.fetch_add(1, Ordering::Relaxed);
            inner.clients.insert(
                id,
                ClientState {
                    clientid: id,
                    owner: args.clientowner.clone(),
                    confirmed: false,
                    reclaim_complete_global: false,
                    sequence_id: 1,
                    replaced_clientid: old_clientid,
                },
            );
            (id, 1, false)
        };
        let pnfs_role = EXCHGID4_FLAG_USE_NON_PNFS;
        let confirmed_flag = if confirmed {
            EXCHGID4_FLAG_CONFIRMED_R
        } else {
            0
        };

        ExchangeIdRes4 {
            clientid,
            sequenceid: seq,
            flags: pnfs_role | confirmed_flag,
            state_protect: StateProtect4R::None,
            server_owner: self.server_owner.clone(),
            server_scope: b"embednfs".to_vec(),
            server_impl_id: vec![NfsImplId4 {
                domain: "embednfs.local".into(),
                name: "embednfs".into(),
                date: NfsTime4 {
                    seconds: 0,
                    nseconds: 0,
                },
            }],
        }
    }

    /// Handle CREATE_SESSION.
    pub async fn create_session(
        &self,
        args: &CreateSessionArgs4,
        connection_id: u64,
    ) -> Result<CreateSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;

        let (replaced_clientid, client_sequence_id) = {
            let client = inner
                .clients
                .get_mut(&args.clientid)
                .ok_or(NfsStat4::StaleClientid)?;

            if args.sequence != client.sequence_id {
                return Err(NfsStat4::SeqMisordered);
            }
            client.sequence_id += 1;
            client.confirmed = true;
            (client.replaced_clientid.take(), client.sequence_id)
        };

        if let Some(old_clientid) = replaced_clientid {
            Self::drop_client_state(&mut inner, old_clientid);
        }

        let mut sessionid = [0u8; 16];
        sessionid[..8].copy_from_slice(&args.clientid.to_be_bytes());
        sessionid[8..16].copy_from_slice(&(client_sequence_id as u64).to_be_bytes());

        let max_slots = args.fore_chan_attrs.maxrequests.min(MAX_FORE_CHAN_SLOTS) as usize;
        let slots = vec![
            SlotState {
                sequence_id: 1,
                in_progress: None,
                cached_reply: None
            };
            max_slots.max(1)
        ];

        let fore_chan = ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: args.fore_chan_attrs.maxrequestsize.min(MAX_REQUEST_SIZE),
            maxresponsesize: args.fore_chan_attrs.maxresponsesize.min(MAX_REQUEST_SIZE),
            maxresponsesize_cached: args
                .fore_chan_attrs
                .maxresponsesize_cached
                .min(MAX_CACHED_RESPONSE),
            maxoperations: args.fore_chan_attrs.maxoperations.min(MAX_FORE_CHAN_SLOTS),
            maxrequests: max_slots as u32,
            rdma_ird: vec![],
        };

        let back_chan = ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: 4096,
            maxresponsesize: 4096,
            maxresponsesize_cached: 0,
            maxoperations: 2,
            maxrequests: 1,
            rdma_ird: vec![],
        };

        inner.sessions.insert(
            sessionid,
            SessionState {
                clientid: args.clientid,
                slots,
                connections: HashSet::from([connection_id]),
            },
        );

        Ok(CreateSessionRes4 {
            sessionid,
            sequenceid: args.sequence,
            flags: 0,
            fore_chan_attrs: fore_chan,
            back_chan_attrs: back_chan,
        })
    }

    fn sequence_res(session: &SessionState, args: &SequenceArgs4) -> SequenceRes4 {
        let highest_slot = (session.slots.len() - 1) as u32;
        SequenceRes4 {
            sessionid: args.sessionid,
            sequenceid: args.sequenceid,
            slotid: args.slotid,
            highest_slotid: highest_slot,
            target_highest_slotid: highest_slot,
            status_flags: 0,
        }
    }

    /// Prepare forechannel SEQUENCE handling and classify the request as
    /// a new execution, a retry that should replay a cached reply, or an error.
    pub(crate) async fn prepare_sequence(
        &self,
        args: &SequenceArgs4,
        fingerprint: &[u8],
        connection_id: u64,
    ) -> SequenceReplay {
        let mut inner = self.inner.write().await;

        let session = inner
            .sessions
            .get_mut(&args.sessionid)
            .ok_or(NfsStat4::BadSession);
        let session = match session {
            Ok(session) => session,
            Err(status) => return SequenceReplay::Error(status),
        };
        session.connections.insert(connection_id);

        let slot_idx = args.slotid as usize;
        if slot_idx >= session.slots.len() {
            return SequenceReplay::Error(NfsStat4::BadSlot);
        }

        let slot = &mut session.slots[slot_idx];
        let retry_seq = slot.sequence_id.wrapping_sub(1);

        if args.sequenceid == slot.sequence_id {
            slot.sequence_id = slot.sequence_id.wrapping_add(1);
            slot.in_progress = Some(fingerprint.to_vec());
            slot.cached_reply = None;
            let res = Self::sequence_res(session, args);
            return SequenceReplay::Execute(
                res,
                SequenceCacheToken {
                    sessionid: args.sessionid,
                    slotid: args.slotid,
                    fingerprint: fingerprint.to_vec(),
                },
            );
        }

        if args.sequenceid != retry_seq {
            return SequenceReplay::Error(NfsStat4::SeqMisordered);
        }

        if let Some(in_progress) = &slot.in_progress {
            return if in_progress == fingerprint {
                SequenceReplay::Error(NfsStat4::Delay)
            } else {
                SequenceReplay::Error(NfsStat4::SeqFalseRetry)
            };
        }

        if let Some(cached) = &slot.cached_reply {
            return if cached.fingerprint == fingerprint {
                SequenceReplay::Replay(cached.response.clone())
            } else {
                SequenceReplay::Error(NfsStat4::SeqFalseRetry)
            };
        }

        SequenceReplay::Error(NfsStat4::Serverfault)
    }

    /// Complete a forechannel request and store the encoded Compound4Res body
    /// for future retries on the same slot/sequence.
    pub(crate) async fn finish_sequence(
        &self,
        token: SequenceCacheToken,
        response: Vec<u8>,
    ) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;

        let session = inner
            .sessions
            .get_mut(&token.sessionid)
            .ok_or(NfsStat4::BadSession)?;
        let slot_idx = token.slotid as usize;
        let slot = session.slots.get_mut(slot_idx).ok_or(NfsStat4::BadSlot)?;

        slot.in_progress = None;
        slot.cached_reply = Some(CachedReplay {
            fingerprint: token.fingerprint,
            response,
        });
        Ok(())
    }

    /// Handle DESTROY_SESSION.
    pub async fn destroy_session(
        &self,
        sessionid: &Sessionid4,
        connection_id: u64,
    ) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let Some(session) = inner.sessions.get(sessionid) else {
            return Err(NfsStat4::BadSession);
        };
        if !session.connections.contains(&connection_id) {
            return Err(NfsStat4::ConnNotBoundToSession);
        }
        inner.sessions.remove(sessionid);
        Ok(())
    }

    /// Handle DESTROY_CLIENTID.
    pub async fn destroy_clientid(&self, clientid: Clientid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        if Self::client_has_active_state(&inner, clientid) {
            return Err(NfsStat4::ClientidBusy);
        }
        if Self::drop_client_state(&mut inner, clientid) {
            Ok(())
        } else {
            Err(NfsStat4::StaleClientid)
        }
    }

    /// Handle BIND_CONN_TO_SESSION.
    pub async fn bind_conn_to_session(
        &self,
        args: &BindConnToSessionArgs4,
        connection_id: u64,
    ) -> Result<BindConnToSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let Some(session) = inner.sessions.get_mut(&args.sessionid) else {
            return Err(NfsStat4::BadSession);
        };
        session.connections.insert(connection_id);
        Ok(BindConnToSessionRes4 {
            sessionid: args.sessionid,
            dir: args.dir,
            use_conn_in_rdma_mode: false,
        })
    }

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

        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
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

    fn validate_stateid_seq(stored_seq: u32, provided_seq: u32) -> Result<(), NfsStat4> {
        if provided_seq == 0 || provided_seq == stored_seq {
            Ok(())
        } else if provided_seq < stored_seq {
            Err(NfsStat4::OldStateid)
        } else {
            Err(NfsStat4::BadStateid)
        }
    }

    /// Look up the object and owner associated with a lock state.
    pub(crate) async fn lock_state_info(
        &self,
        stateid: &Stateid4,
    ) -> Option<(ServerObject, StateOwner4)> {
        let inner = self.inner.read().await;
        inner
            .lock_files
            .get(&stateid.other)
            .map(|state| (state.object.clone(), state.owner.clone()))
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

    /// Look up the client ID associated with a session.
    pub async fn session_clientid(&self, sessionid: &Sessionid4) -> Option<Clientid4> {
        let inner = self.inner.read().await;
        inner
            .sessions
            .get(sessionid)
            .map(|session| session.clientid)
    }

    fn lock_end(offset: u64, length: u64) -> u128 {
        if length == 0 {
            u128::MAX
        } else {
            offset as u128 + length as u128
        }
    }

    fn locks_overlap(a_offset: u64, a_length: u64, b_offset: u64, b_length: u64) -> bool {
        let a_end = Self::lock_end(a_offset, a_length);
        let b_end = Self::lock_end(b_offset, b_length);
        (a_offset as u128) < b_end && (b_offset as u128) < a_end
    }

    fn range_from_bounds(locktype: NfsLockType4, start: u64, end: u128) -> Option<LockRange> {
        if start as u128 >= end {
            return None;
        }

        Some(LockRange {
            locktype,
            offset: start,
            length: if end == u128::MAX {
                0
            } else {
                (end - start as u128) as u64
            },
        })
    }

    fn is_write_lock(locktype: NfsLockType4) -> bool {
        matches!(locktype, NfsLockType4::WriteLt | NfsLockType4::WritewLt)
    }

    fn same_lock_owner(a: &StateOwner4, b: &StateOwner4) -> bool {
        a.clientid == b.clientid && a.owner == b.owner
    }

    fn drop_client_state(inner: &mut StateInner, clientid: Clientid4) -> bool {
        inner
            .sessions
            .retain(|_, session| session.clientid != clientid);
        inner
            .open_files
            .retain(|_, state| state.clientid != clientid);
        inner
            .lock_files
            .retain(|_, state| state.owner.clientid != clientid);
        inner.clients.remove(&clientid).is_some()
    }

    fn client_has_active_state(inner: &StateInner, clientid: Clientid4) -> bool {
        inner.sessions.values().any(|session| session.clientid == clientid)
            || inner.open_files.values().any(|state| state.clientid == clientid)
            || inner
                .lock_files
                .values()
                .any(|state| state.owner.clientid == clientid)
    }

    pub async fn reclaim_complete(
        &self,
        clientid: Clientid4,
        one_fs: bool,
    ) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let client = inner.clients.get_mut(&clientid).ok_or(NfsStat4::StaleClientid)?;
        if one_fs {
            return Ok(());
        }
        if client.reclaim_complete_global {
            return Err(NfsStat4::CompleteAlready);
        }
        client.reclaim_complete_global = true;
        Ok(())
    }

    pub async fn validate_open_reclaim(
        &self,
        clientid: Clientid4,
        claim: &OpenClaim4,
    ) -> Result<(), NfsStat4> {
        let inner = self.inner.read().await;
        let client = inner.clients.get(&clientid).ok_or(NfsStat4::StaleClientid)?;
        match claim {
            OpenClaim4::Previous(_) if client.reclaim_complete_global => Err(NfsStat4::NoGrace),
            _ => Ok(()),
        }
    }

    pub(crate) async fn find_lock_conflict(
        &self,
        object: &ServerObject,
        owner: &StateOwner4,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
        ignore_stateid: Option<&Stateid4>,
    ) -> Option<LockDenied4> {
        let inner = self.inner.read().await;
        for (other, state) in &inner.lock_files {
            if Some(*other) == ignore_stateid.map(|sid| sid.other) {
                continue;
            }
            if !state.active {
                continue;
            }
            if state.object != *object {
                continue;
            }
            if Self::same_lock_owner(&state.owner, owner) {
                continue;
            }
            for range in &state.ranges {
                if !Self::locks_overlap(range.offset, range.length, offset, length) {
                    continue;
                }
                if !Self::is_write_lock(range.locktype) && !Self::is_write_lock(locktype) {
                    continue;
                }
                return Some(LockDenied4 {
                    offset: range.offset,
                    length: range.length,
                    locktype: range.locktype,
                    owner: state.owner.clone(),
                });
            }
        }
        None
    }

    /// Create a new lock state (LOCK with new lock owner).
    pub(crate) async fn create_lock_state(
        &self,
        open_stateid: &Stateid4,
        owner: &StateOwner4,
        object: ServerObject,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let open = inner
            .open_files
            .get(&open_stateid.other)
            .ok_or(NfsStat4::Openmode)?;
        if open.object != object {
            return Err(NfsStat4::Openmode);
        }

        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&owner.clientid.to_be_bytes());

        inner.lock_files.insert(
            other,
            LockFileState {
                object,
                owner: owner.clone(),
                ranges: vec![LockRange {
                    locktype,
                    offset,
                    length,
                }],
                active: true,
                stateid_seq: 1,
            },
        );

        Ok(Stateid4 { seqid: 1, other })
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

    /// Update an existing lock state (LOCK with existing lock owner).
    pub async fn update_lock_state(
        &self,
        lock_stateid: &Stateid4,
        locktype: NfsLockType4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Self::validate_stateid_seq(state.stateid_seq, lock_stateid.seqid)?;
        state.ranges.push(LockRange {
            locktype,
            offset,
            length,
        });
        state.active = true;
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }

    /// Unlock (LOCKU).
    pub async fn unlock_state(
        &self,
        lock_stateid: &Stateid4,
        offset: u64,
        length: u64,
    ) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner
            .lock_files
            .get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        Self::validate_stateid_seq(state.stateid_seq, lock_stateid.seqid)?;

        if !state
            .ranges
            .iter()
            .any(|range| Self::locks_overlap(range.offset, range.length, offset, length))
        {
            state.stateid_seq += 1;
            return Ok(Stateid4 {
                seqid: state.stateid_seq,
                other: lock_stateid.other,
            });
        }

        let unlock_end = Self::lock_end(offset, length);
        let mut next_ranges = Vec::with_capacity(state.ranges.len() + 1);
        for range in &state.ranges {
            if !Self::locks_overlap(range.offset, range.length, offset, length) {
                next_ranges.push(LockRange {
                    locktype: range.locktype,
                    offset: range.offset,
                    length: range.length,
                });
                continue;
            }

            let range_end = Self::lock_end(range.offset, range.length);
            if let Some(left) =
                Self::range_from_bounds(range.locktype, range.offset, offset as u128)
            {
                next_ranges.push(left);
            }
            if unlock_end != u128::MAX
                && let Some(right) =
                    Self::range_from_bounds(range.locktype, unlock_end as u64, range_end)
            {
                next_ranges.push(right);
            }
        }
        state.ranges = next_ranges;
        state.active = !state.ranges.is_empty();
        state.stateid_seq += 1;
        Ok(Stateid4 {
            seqid: state.stateid_seq,
            other: lock_stateid.other,
        })
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

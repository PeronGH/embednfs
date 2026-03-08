use crate::internal::{ServerFileType, ServerObject, SetAttrRequest, SetTime};
use dashmap::DashMap;
/// NFSv4.1 session, object, and server-side state management.
use embednfs_proto::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::sync::RwLock;

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
    sequence_id: Sequenceid4,
    replaced_clientid: Option<Clientid4>,
}

struct SessionState {
    clientid: Clientid4,
    slots: Vec<SlotState>,
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
    #[allow(dead_code)]
    stateid_seq: u32,
    share_access: u32,
    share_deny: u32,
}

impl StateManager {
    pub fn new() -> Self {
        let boot_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut write_verifier = [0u8; 8];
        write_verifier[..8].copy_from_slice(&boot_time.as_nanos().to_be_bytes()[..8]);

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
            next_synth_fileid: AtomicU64::new(1 << 63),
            write_verifier,
            server_owner,
        }
    }

    /// Get or create a file handle for a server object.
    pub(crate) async fn object_to_fh(&self, object: &ServerObject) -> NfsFh4 {
        if let Some(fh) = self.object_to_fh.get(object) {
            return NfsFh4(fh.value().clone());
        }
        let fh_num = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let fh = fh_num.to_be_bytes().to_vec();
        self.fh_to_object.insert(fh.clone(), object.clone());
        self.object_to_fh.insert(object.clone(), fh.clone());
        NfsFh4(fh)
    }

    /// Resolve a file handle to a server object.
    pub(crate) async fn fh_to_object(&self, fh: &NfsFh4) -> Option<ServerObject> {
        self.fh_to_object.get(&fh.0).map(|r| r.value().clone())
    }

    fn now() -> (i64, u32) {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (dur.as_secs() as i64, dur.subsec_nanos())
    }

    fn default_mode(file_type: ServerFileType) -> u32 {
        match file_type {
            ServerFileType::Regular | ServerFileType::NamedAttr => 0o644,
            ServerFileType::Directory | ServerFileType::NamedAttrDir => 0o755,
            ServerFileType::Symlink => 0o777,
        }
    }

    fn default_nlink(file_type: ServerFileType) -> u32 {
        match file_type {
            ServerFileType::Directory | ServerFileType::NamedAttrDir => 2,
            _ => 1,
        }
    }

    fn ensure_meta_locked(
        &self,
        inner: &mut StateInner,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        if let Some(meta) = inner.metadata.get(object) {
            return meta.clone();
        }

        let (now_s, now_ns) = Self::now();
        let fileid = match object {
            ServerObject::Fs(id) => *id,
            ServerObject::NamedAttrDir(_) | ServerObject::NamedAttrFile { .. } => {
                self.next_synth_fileid.fetch_add(1, Ordering::Relaxed)
            }
        };
        let meta = SynthMeta {
            fileid,
            mode: Self::default_mode(file_type),
            nlink: Self::default_nlink(file_type),
            uid: 0,
            gid: 0,
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: now_s,
            atime_nsec: now_ns,
            mtime_sec: now_s,
            mtime_nsec: now_ns,
            ctime_sec: now_s,
            ctime_nsec: now_ns,
            crtime_sec: now_s,
            crtime_nsec: now_ns,
            change_id: self.next_changeid.fetch_add(1, Ordering::Relaxed),
            archive: false,
            hidden: false,
            system: false,
            named_attr_count: None,
        };
        inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    pub(crate) async fn ensure_meta(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        self.ensure_meta_locked(&mut inner, object, file_type)
    }

    pub(crate) async fn touch_data(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();
        meta.mtime_sec = now_s;
        meta.mtime_nsec = now_ns;
        meta.ctime_sec = now_s;
        meta.ctime_nsec = now_ns;
        meta.change_id = self.next_changeid.fetch_add(1, Ordering::Relaxed);
        inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    pub(crate) async fn named_attr_count(&self, object: &ServerObject) -> Option<u64> {
        let inner = self.inner.read().await;
        inner
            .metadata
            .get(object)
            .and_then(|meta| meta.named_attr_count)
    }

    pub(crate) async fn set_named_attr_count(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
        count: u64,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        meta.named_attr_count = Some(count);
        inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    pub(crate) async fn touch_metadata(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();
        meta.ctime_sec = now_s;
        meta.ctime_nsec = now_ns;
        meta.mtime_sec = now_s;
        meta.mtime_nsec = now_ns;
        meta.change_id = self.next_changeid.fetch_add(1, Ordering::Relaxed);
        inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    pub(crate) async fn apply_setattr(
        &self,
        object: &ServerObject,
        file_type: ServerFileType,
        attrs: &SetAttrRequest,
    ) -> SynthMeta {
        let mut inner = self.inner.write().await;
        let mut meta = self.ensure_meta_locked(&mut inner, object, file_type);
        let (now_s, now_ns) = Self::now();

        if let Some(mode) = attrs.mode {
            meta.mode = mode;
        }
        if let Some(archive) = attrs.archive {
            meta.archive = archive;
        }
        if let Some(hidden) = attrs.hidden {
            meta.hidden = hidden;
        }
        if let Some(uid) = attrs.uid {
            meta.uid = uid;
        }
        if let Some(gid) = attrs.gid {
            meta.gid = gid;
        }
        if let Some(system) = attrs.system {
            meta.system = system;
        }
        if let Some(atime) = attrs.atime {
            match atime {
                SetTime::ServerTime => {
                    meta.atime_sec = now_s;
                    meta.atime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    meta.atime_sec = s;
                    meta.atime_nsec = ns;
                }
            }
        }
        if let Some(mtime) = attrs.mtime {
            match mtime {
                SetTime::ServerTime => {
                    meta.mtime_sec = now_s;
                    meta.mtime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    meta.mtime_sec = s;
                    meta.mtime_nsec = ns;
                }
            }
        }
        if let Some(crtime) = attrs.crtime {
            match crtime {
                SetTime::ServerTime => {
                    meta.crtime_sec = now_s;
                    meta.crtime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    meta.crtime_sec = s;
                    meta.crtime_nsec = ns;
                }
            }
        }

        meta.ctime_sec = now_s;
        meta.ctime_nsec = now_ns;
        meta.change_id = self.next_changeid.fetch_add(1, Ordering::Relaxed);
        inner.metadata.insert(object.clone(), meta.clone());
        meta
    }

    /// Handle EXCHANGE_ID.
    pub async fn exchange_id(&self, args: &ExchangeIdArgs4) -> ExchangeIdRes4 {
        let mut inner = self.inner.write().await;

        let clientid = if let Some(existing) = inner
            .clients
            .values()
            .find(|client| client.owner.ownerid == args.clientowner.ownerid)
            .and_then(|client| {
                (client.owner.verifier == args.clientowner.verifier).then_some(client.clientid)
            }) {
            existing
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
                    sequence_id: 1,
                    replaced_clientid: old_clientid,
                },
            );
            id
        };

        let client = inner.clients.get(&clientid).unwrap();
        let seq = client.sequence_id;
        let confirmed = client.confirmed;
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
    ) -> Result<CreateSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;

        let replaced_clientid = {
            let client = inner
                .clients
                .get_mut(&args.clientid)
                .ok_or(NfsStat4::StaleClientid)?;

            if args.sequence != client.sequence_id {
                return Err(NfsStat4::SeqMisordered);
            }
            client.sequence_id += 1;
            client.confirmed = true;
            client.replaced_clientid.take()
        };

        if let Some(old_clientid) = replaced_clientid {
            Self::drop_client_state(&mut inner, old_clientid);
        }

        let client = inner.clients.get(&args.clientid).unwrap();

        let mut sessionid = [0u8; 16];
        sessionid[..8].copy_from_slice(&args.clientid.to_be_bytes());
        sessionid[8..16].copy_from_slice(&(client.sequence_id as u64).to_be_bytes());

        let max_slots = args.fore_chan_attrs.maxrequests.min(64) as usize;
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
            maxrequestsize: args.fore_chan_attrs.maxrequestsize.min(1049620),
            maxresponsesize: args.fore_chan_attrs.maxresponsesize.min(1049620),
            maxresponsesize_cached: args.fore_chan_attrs.maxresponsesize_cached.min(6144),
            maxoperations: args.fore_chan_attrs.maxoperations.min(64),
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
    pub async fn destroy_session(&self, sessionid: &Sessionid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner
            .sessions
            .remove(sessionid)
            .ok_or(NfsStat4::BadSession)?;
        Ok(())
    }

    /// Handle DESTROY_CLIENTID.
    pub async fn destroy_clientid(&self, clientid: Clientid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
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
    ) -> Result<BindConnToSessionRes4, NfsStat4> {
        let inner = self.inner.read().await;
        if !inner.sessions.contains_key(&args.sessionid) {
            return Err(NfsStat4::BadSession);
        }
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
                && ((state.share_deny & share_access) != 0 || (share_deny & state.share_access) != 0)
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
        inner.lock_files.remove(&stateid.other);
        Ok(())
    }

    pub async fn test_stateids(&self, stateids: &[Stateid4]) -> Vec<NfsStat4> {
        let inner = self.inner.read().await;
        stateids
            .iter()
            .map(|stateid| {
                if inner.open_files.contains_key(&stateid.other)
                    || inner.lock_files.contains_key(&stateid.other)
                {
                    NfsStat4::Ok
                } else {
                    NfsStat4::BadStateid
                }
            })
            .collect()
    }

    /// Look up the client ID associated with a session.
    pub async fn session_clientid(&self, sessionid: &Sessionid4) -> Option<Clientid4> {
        let inner = self.inner.read().await;
        inner.sessions.get(sessionid).map(|session| session.clientid)
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
        inner.sessions.retain(|_, session| session.clientid != clientid);
        inner.open_files.retain(|_, state| state.clientid != clientid);
        inner.lock_files.retain(|_, state| state.owner.clientid != clientid);
        inner.clients.remove(&clientid).is_some()
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
            if let Some(left) = Self::range_from_bounds(range.locktype, range.offset, offset as u128) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange_id_args(ownerid: &[u8], verifier: Verifier4) -> ExchangeIdArgs4 {
        ExchangeIdArgs4 {
            clientowner: ClientOwner4 {
                verifier,
                ownerid: ownerid.to_vec(),
            },
            flags: EXCHGID4_FLAG_USE_NON_PNFS,
            state_protect: StateProtect4A::None,
            client_impl_id: vec![],
        }
    }

    fn create_session_args(clientid: Clientid4, sequence: Sequenceid4) -> CreateSessionArgs4 {
        CreateSessionArgs4 {
            clientid,
            sequence,
            flags: 0,
            fore_chan_attrs: ChannelAttrs4::default(),
            back_chan_attrs: ChannelAttrs4::default(),
            cb_program: 0,
            sec_parms: vec![],
        }
    }

    async fn setup_open_state(
        state: &StateManager,
        object: ServerObject,
        clientid: Clientid4,
    ) -> Stateid4 {
        state
            .create_open_state(object, clientid, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_test_stateids_recognizes_open_and_lock_stateids() {
        let state = StateManager::new();
        let object = ServerObject::Fs(1);
        let open_stateid = setup_open_state(&state, object.clone(), 11).await;
        let owner = StateOwner4 {
            clientid: 11,
            owner: b"lock-owner".to_vec(),
        };
        let lock_stateid = state
            .create_lock_state(
                &open_stateid,
                &owner,
                object,
                NfsLockType4::WriteLt,
                0,
                10,
            )
            .await
            .unwrap();

        let unknown = Stateid4 {
            seqid: 1,
            other: [0x55; 12],
        };
        let results = state
            .test_stateids(&[open_stateid, lock_stateid, unknown])
            .await;
        assert_eq!(results, vec![NfsStat4::Ok, NfsStat4::Ok, NfsStat4::BadStateid]);
    }

    #[tokio::test]
    async fn test_exchange_id_reuses_existing_client_when_verifier_matches() {
        let state = StateManager::new();
        let args = exchange_id_args(b"owner", [0x11; 8]);

        let first = state.exchange_id(&args).await;
        state
            .create_session(&create_session_args(first.clientid, first.sequenceid))
            .await
            .unwrap();

        let second = state.exchange_id(&args).await;

        assert_eq!(second.clientid, first.clientid);
        assert_eq!(second.flags & EXCHGID4_FLAG_CONFIRMED_R, EXCHGID4_FLAG_CONFIRMED_R);
    }

    #[tokio::test]
    async fn test_exchange_id_reboot_drops_old_state_after_new_create_session() {
        let state = StateManager::new();
        let original = state.exchange_id(&exchange_id_args(b"owner", [0x11; 8])).await;
        let original_session = state
            .create_session(&create_session_args(original.clientid, original.sequenceid))
            .await
            .unwrap();

        let object = ServerObject::Fs(1);
        let open_stateid = setup_open_state(&state, object.clone(), original.clientid).await;
        let owner = StateOwner4 {
            clientid: original.clientid,
            owner: b"lock-owner".to_vec(),
        };
        let lock_stateid = state
            .create_lock_state(
                &open_stateid,
                &owner,
                object,
                NfsLockType4::WriteLt,
                0,
                10,
            )
            .await
            .unwrap();

        let rebooted = state.exchange_id(&exchange_id_args(b"owner", [0x22; 8])).await;
        assert_ne!(rebooted.clientid, original.clientid);
        assert_eq!(
            state.session_clientid(&original_session.sessionid).await,
            Some(original.clientid)
        );
        assert_eq!(
            state.test_stateids(&[open_stateid, lock_stateid]).await,
            vec![NfsStat4::Ok, NfsStat4::Ok]
        );

        state
            .create_session(&create_session_args(rebooted.clientid, rebooted.sequenceid))
            .await
            .unwrap();

        assert_eq!(state.session_clientid(&original_session.sessionid).await, None);
        assert_eq!(
            state.test_stateids(&[open_stateid, lock_stateid]).await,
            vec![NfsStat4::BadStateid, NfsStat4::BadStateid]
        );
    }

    #[tokio::test]
    async fn test_existing_lock_owner_tracks_multiple_ranges() {
        let state = StateManager::new();
        let object = ServerObject::Fs(7);
        let open_stateid = setup_open_state(&state, object.clone(), 22).await;
        let owner = StateOwner4 {
            clientid: 22,
            owner: b"owner".to_vec(),
        };

        let lock_stateid = state
            .create_lock_state(
                &open_stateid,
                &owner,
                object.clone(),
                NfsLockType4::WriteLt,
                0,
                10,
            )
            .await
            .unwrap();
        state
            .update_lock_state(&lock_stateid, NfsLockType4::WriteLt, 20, 10)
            .await
            .unwrap();

        let inner = state.inner.read().await;
        let lock = inner.lock_files.get(&lock_stateid.other).unwrap();
        assert!(lock.active);
        assert_eq!(lock.ranges.len(), 2);
        assert_eq!(lock.ranges[0].offset, 0);
        assert_eq!(lock.ranges[1].offset, 20);
    }

    #[tokio::test]
    async fn test_unlock_splits_range_and_conflict_checks_all_ranges() {
        let state = StateManager::new();
        let object = ServerObject::Fs(9);
        let open1 = setup_open_state(&state, object.clone(), 31).await;
        let owner1 = StateOwner4 {
            clientid: 31,
            owner: b"owner1".to_vec(),
        };
        let lock_stateid = state
            .create_lock_state(
                &open1,
                &owner1,
                object.clone(),
                NfsLockType4::WriteLt,
                0,
                100,
            )
            .await
            .unwrap();

        state.unlock_state(&lock_stateid, 40, 20).await.unwrap();

        let inner = state.inner.read().await;
        let lock = inner.lock_files.get(&lock_stateid.other).unwrap();
        assert!(lock.active);
        assert_eq!(lock.ranges.len(), 2);
        assert_eq!(lock.ranges[0].offset, 0);
        assert_eq!(lock.ranges[0].length, 40);
        assert_eq!(lock.ranges[1].offset, 60);
        assert_eq!(lock.ranges[1].length, 40);
        drop(inner);

        let owner2 = StateOwner4 {
            clientid: 32,
            owner: b"owner2".to_vec(),
        };
        let denied_left = state
            .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 10, 5, None)
            .await;
        assert!(denied_left.is_some());
        let denied_middle = state
            .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 45, 5, None)
            .await;
        assert!(denied_middle.is_none());
        let denied_right = state
            .find_lock_conflict(&object, &owner2, NfsLockType4::WriteLt, 70, 5, None)
            .await;
        assert!(denied_right.is_some());
    }
}

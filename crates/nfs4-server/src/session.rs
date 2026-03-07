/// NFSv4.1 session and state management.
///
/// Manages client IDs, sessions, slot tables, open state, and file handle mappings.

use nfs4_proto::*;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::fs::FileId;

/// Lock state for a file.
#[derive(Debug)]
struct LockFileState {
    #[allow(dead_code)]
    owner: StateOwner4,
    stateid_seq: u32,
}

/// Manages all server-side state.
pub struct StateManager {
    inner: Arc<RwLock<StateInner>>,
    /// Lock-free file handle mappings (hot path).
    fh_to_id: DashMap<Vec<u8>, FileId>,
    id_to_fh: DashMap<FileId, Vec<u8>>,
    next_fh: AtomicU64,
    next_clientid: AtomicU64,
    next_stateid: AtomicU32,
    /// Server boot verifier (changes each restart).
    pub write_verifier: Verifier4,
    pub server_owner: ServerOwner4,
}

struct StateInner {
    clients: HashMap<Clientid4, ClientState>,
    sessions: HashMap<Sessionid4, SessionState>,
    /// Open file state: stateid -> OpenFileState
    open_files: HashMap<[u8; 12], OpenFileState>,
    /// Lock state: stateid.other -> LockFileState
    lock_files: HashMap<[u8; 12], LockFileState>,
}

#[derive(Debug)]
struct ClientState {
    clientid: Clientid4,
    #[allow(dead_code)]
    owner: ClientOwner4,
    confirmed: bool,
    sequence_id: Sequenceid4,
}

struct SessionState {
    clientid: Clientid4,
    slots: Vec<SlotState>,
    fore_chan_attrs: ChannelAttrs4,
}

#[derive(Clone)]
struct SlotState {
    sequence_id: Sequenceid4,
    #[allow(dead_code)]
    cached_reply: Option<Vec<u8>>,
}

#[derive(Debug)]
struct OpenFileState {
    #[allow(dead_code)]
    file_id: FileId,
    #[allow(dead_code)]
    clientid: Clientid4,
    #[allow(dead_code)]
    stateid_seq: u32,
    #[allow(dead_code)]
    share_access: u32,
    #[allow(dead_code)]
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
            major_id: b"nfsserve4-rs".to_vec(),
        };

        StateManager {
            inner: Arc::new(RwLock::new(StateInner {
                clients: HashMap::new(),
                sessions: HashMap::new(),
                open_files: HashMap::new(),
                lock_files: HashMap::new(),
            })),
            fh_to_id: DashMap::new(),
            id_to_fh: DashMap::new(),
            next_fh: AtomicU64::new(1),
            next_clientid: AtomicU64::new(1),
            next_stateid: AtomicU32::new(1),
            write_verifier,
            server_owner,
        }
    }

    /// Get or create a file handle for a FileId.
    /// Uses lock-free DashMap — no await contention on hot path.
    pub async fn file_id_to_fh(&self, id: FileId) -> NfsFh4 {
        if let Some(fh) = self.id_to_fh.get(&id) {
            return NfsFh4(fh.value().clone());
        }
        let fh_num = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let fh = fh_num.to_be_bytes().to_vec();
        self.fh_to_id.insert(fh.clone(), id);
        self.id_to_fh.insert(id, fh.clone());
        NfsFh4(fh)
    }

    /// Resolve a file handle to a FileId.
    /// Uses lock-free DashMap — no await contention on hot path.
    pub async fn fh_to_file_id(&self, fh: &NfsFh4) -> Option<FileId> {
        self.fh_to_id.get(&fh.0).map(|r| *r.value())
    }

    /// Handle EXCHANGE_ID.
    pub async fn exchange_id(&self, args: &ExchangeIdArgs4) -> ExchangeIdRes4 {
        let mut inner = self.inner.write().await;

        // Check if we already have this client
        let clientid = {
            let existing = inner.clients.values().find(|c| c.owner.ownerid == args.clientowner.ownerid);
            if let Some(c) = existing {
                c.clientid
            } else {
                let id = self.next_clientid.fetch_add(1, Ordering::Relaxed);
                inner.clients.insert(id, ClientState {
                    clientid: id,
                    owner: args.clientowner.clone(),
                    confirmed: false,
                    sequence_id: 1,
                });
                id
            }
        };

        let client = inner.clients.get(&clientid).unwrap();
        let seq = client.sequence_id;
        let confirmed = client.confirmed;

        // Compute response flags:
        // - pNFS role: AND client's requested pNFS bits with what we support (NON_PNFS only)
        let client_pnfs = args.flags & EXCHGID4_FLAG_MASK_PNFS;
        let pnfs_role = if client_pnfs & EXCHGID4_FLAG_USE_NON_PNFS != 0 {
            EXCHGID4_FLAG_USE_NON_PNFS
        } else if client_pnfs == 0 {
            // Client didn't specify; default to non-pNFS
            EXCHGID4_FLAG_USE_NON_PNFS
        } else {
            // Client only wants pNFS roles we don't support
            EXCHGID4_FLAG_USE_NON_PNFS
        };
        // - CONFIRMED_R: only set if client record is already confirmed
        let confirmed_flag = if confirmed { EXCHGID4_FLAG_CONFIRMED_R } else { 0 };

        ExchangeIdRes4 {
            clientid,
            sequenceid: seq,
            flags: pnfs_role | confirmed_flag,
            state_protect: StateProtect4R::None,
            server_owner: self.server_owner.clone(),
            server_scope: b"nfsserve4-rs".to_vec(),
            server_impl_id: vec![NfsImplId4 {
                domain: "nfsserve4-rs.local".into(),
                name: "nfsserve4-rs".into(),
                date: NfsTime4 { seconds: 0, nseconds: 0 },
            }],
        }
    }

    /// Handle CREATE_SESSION.
    pub async fn create_session(&self, args: &CreateSessionArgs4) -> Result<CreateSessionRes4, NfsStat4> {
        let mut inner = self.inner.write().await;

        let client = inner.clients.get_mut(&args.clientid)
            .ok_or(NfsStat4::StaleClientid)?;

        // Validate sequence
        if args.sequence != client.sequence_id {
            return Err(NfsStat4::SeqMisordered);
        }
        client.sequence_id += 1;
        client.confirmed = true;

        // Generate session ID
        let mut sessionid = [0u8; 16];
        sessionid[..8].copy_from_slice(&args.clientid.to_be_bytes());
        sessionid[8..16].copy_from_slice(&(client.sequence_id as u64).to_be_bytes());

        let max_slots = args.fore_chan_attrs.maxrequests.min(64) as usize;
        let slots = vec![SlotState { sequence_id: 1, cached_reply: None }; max_slots.max(1)];

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

        inner.sessions.insert(sessionid, SessionState {
            clientid: args.clientid,
            slots,
            fore_chan_attrs: fore_chan.clone(),
        });

        Ok(CreateSessionRes4 {
            sessionid,
            sequenceid: args.sequence,
            flags: 0,
            fore_chan_attrs: fore_chan,
            back_chan_attrs: back_chan,
        })
    }

    /// Handle SEQUENCE.
    pub async fn sequence(&self, args: &SequenceArgs4) -> Result<SequenceRes4, NfsStat4> {
        let mut inner = self.inner.write().await;

        let session = inner.sessions.get_mut(&args.sessionid)
            .ok_or(NfsStat4::BadSession)?;

        let slot_idx = args.slotid as usize;
        if slot_idx >= session.slots.len() {
            return Err(NfsStat4::BadSlot);
        }

        let slot = &mut session.slots[slot_idx];

        // Check sequence
        if args.sequenceid == slot.sequence_id {
            // New request
            slot.sequence_id += 1;
        } else if args.sequenceid == slot.sequence_id - 1 {
            // Retry - for now just accept it
        } else {
            return Err(NfsStat4::SeqMisordered);
        }

        let highest_slot = (session.slots.len() - 1) as u32;

        Ok(SequenceRes4 {
            sessionid: args.sessionid,
            sequenceid: args.sequenceid,
            slotid: args.slotid,
            highest_slotid: highest_slot,
            target_highest_slotid: highest_slot,
            status_flags: 0,
        })
    }

    /// Handle DESTROY_SESSION.
    pub async fn destroy_session(&self, sessionid: &Sessionid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.sessions.remove(sessionid)
            .ok_or(NfsStat4::BadSession)?;
        Ok(())
    }

    /// Handle DESTROY_CLIENTID.
    pub async fn destroy_clientid(&self, clientid: Clientid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        // Remove all sessions for this client
        inner.sessions.retain(|_, s| s.clientid != clientid);
        inner.clients.remove(&clientid)
            .ok_or(NfsStat4::StaleClientid)?;
        Ok(())
    }

    /// Handle BIND_CONN_TO_SESSION.
    pub async fn bind_conn_to_session(&self, args: &BindConnToSessionArgs4) -> Result<BindConnToSessionRes4, NfsStat4> {
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

    /// Create an open state for a file. Returns a Stateid4.
    pub async fn create_open_state(&self, file_id: FileId, clientid: Clientid4, share_access: u32, share_deny: u32) -> Stateid4 {
        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&clientid.to_be_bytes());

        let mut inner = self.inner.write().await;
        inner.open_files.insert(other, OpenFileState {
            file_id,
            clientid,
            stateid_seq: 1,
            share_access,
            share_deny,
        });

        Stateid4 { seqid: 1, other }
    }

    /// Close an open state.
    pub async fn close_state(&self, stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.open_files.remove(&stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        // Return a stateid with seqid+1 and all-zeros other (marks as closed)
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

    /// Get the max request size for a session.
    pub async fn get_session_max_request(&self, sessionid: &Sessionid4) -> Option<u32> {
        let inner = self.inner.read().await;
        inner.sessions.get(sessionid).map(|s| s.fore_chan_attrs.maxresponsesize)
    }

    /// Handle SETCLIENTID (NFSv4.0).
    pub async fn set_client_id(&self, args: &SetClientIdArgs4) -> SetClientIdRes4 {
        let mut inner = self.inner.write().await;

        // Check if we already have this client
        let clientid = {
            let existing = inner.clients.values().find(|c| c.owner.ownerid == args.client.ownerid);
            if let Some(c) = existing {
                c.clientid
            } else {
                let id = self.next_clientid.fetch_add(1, Ordering::Relaxed);
                inner.clients.insert(id, ClientState {
                    clientid: id,
                    owner: args.client.clone(),
                    confirmed: false,
                    sequence_id: 1,
                });
                id
            }
        };

        // Generate a verifier for confirmation
        let mut verifier = [0u8; 8];
        verifier[..8].copy_from_slice(&clientid.to_be_bytes());

        SetClientIdRes4 { clientid, verifier }
    }

    /// Handle SETCLIENTID_CONFIRM (NFSv4.0).
    pub async fn set_client_id_confirm(&self, args: &SetClientIdConfirmArgs4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        let client = inner.clients.get_mut(&args.clientid)
            .ok_or(NfsStat4::StaleClientid)?;
        client.confirmed = true;
        Ok(())
    }

    /// Create a new lock state (LOCK with new lock owner).
    pub async fn create_lock_state(&self, _open_stateid: &Stateid4, owner: &StateOwner4) -> Result<Stateid4, NfsStat4> {
        let seq = self.next_stateid.fetch_add(1, Ordering::Relaxed);
        let mut other = [0u8; 12];
        other[..4].copy_from_slice(&seq.to_be_bytes());
        other[4..12].copy_from_slice(&owner.clientid.to_be_bytes());

        let mut inner = self.inner.write().await;
        inner.lock_files.insert(other, LockFileState {
            owner: owner.clone(),
            stateid_seq: 1,
        });

        Ok(Stateid4 { seqid: 1, other })
    }

    /// Update an existing lock state (LOCK with existing lock owner).
    pub async fn update_lock_state(&self, lock_stateid: &Stateid4) -> Result<Stateid4, NfsStat4> {
        let mut inner = self.inner.write().await;
        let state = inner.lock_files.get_mut(&lock_stateid.other)
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
        let state = inner.lock_files.get_mut(&lock_stateid.other)
            .ok_or(NfsStat4::BadStateid)?;
        state.stateid_seq += 1;
        let new_seqid = state.stateid_seq;
        // Keep the state around (may be reused)
        Ok(Stateid4 {
            seqid: new_seqid,
            other: lock_stateid.other,
        })
    }
}

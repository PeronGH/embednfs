//! NFSv4.1 session, object, and server-side state management.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64};

use dashmap::DashMap;
use embednfs_proto::{ServerOwner4, Verifier4};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::internal::ServerObject;

mod clients;
mod filehandles;
mod locks;
mod metadata;
mod model;
mod opens;
mod sequence;
mod stateids;
#[cfg(test)]
mod tests;

const MAX_FORE_CHAN_SLOTS: u32 = 64;
const MAX_REQUEST_SIZE: u32 = 1_049_620;
const MAX_CACHED_RESPONSE: u32 = 6144;
const SYNTH_FILEID_BASE: u64 = 1u64 << 63;

use model::StateInner;
pub(crate) use model::{ResolvedStateid, SequenceReplay, SynthMeta};
pub(crate) use stateids::{CurrentStateidMode, NormalizedStateid};

/// Manages all server-side state.
pub(crate) struct StateManager {
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
    pub(crate) write_verifier: Verifier4,
    pub(crate) server_owner: ServerOwner4,
}

impl StateManager {
    pub(crate) fn new() -> Self {
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

        Self {
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
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

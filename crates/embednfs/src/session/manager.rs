use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64};

use tokio::sync::RwLock;

use embednfs_proto::*;

use super::state::StateInner;

/// Manages all server-side NFS session and state objects.
pub struct StateManager {
    pub(super) inner: Arc<RwLock<StateInner>>,
    pub(super) next_clientid: AtomicU64,
    pub(super) next_stateid: AtomicU32,
    /// Server boot verifier (changes each restart).
    pub write_verifier: Verifier4,
    pub server_owner: ServerOwner4,
}

impl StateManager {
    pub fn new() -> Self {
        let boot_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after UNIX_EPOCH");
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
                file_opens: HashMap::new(),
                file_locks: HashMap::new(),
            })),
            next_clientid: AtomicU64::new(1),
            next_stateid: AtomicU32::new(1),
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

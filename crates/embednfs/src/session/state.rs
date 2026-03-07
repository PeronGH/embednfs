use std::collections::HashMap;

use embednfs_proto::*;

use crate::fs::FileId;

#[derive(Debug)]
pub(super) struct LockFileState {
    pub owner: StateOwner4,
    pub stateid_seq: u32,
}

pub(super) struct StateInner {
    pub clients: HashMap<Clientid4, ClientState>,
    pub sessions: HashMap<Sessionid4, SessionState>,
    pub open_files: HashMap<[u8; 12], OpenFileState>,
    pub lock_files: HashMap<[u8; 12], LockFileState>,
    /// Reverse index: file_id → list of open stateid `other` values.
    pub file_opens: HashMap<FileId, Vec<[u8; 12]>>,
}

#[derive(Debug)]
pub(super) struct ClientState {
    pub clientid: Clientid4,
    pub owner: ClientOwner4,
    pub confirmed: bool,
    pub sequence_id: Sequenceid4,
}

pub(super) struct SessionState {
    pub clientid: Clientid4,
    pub slots: Vec<SlotState>,
}

#[derive(Clone)]
pub(super) struct SlotState {
    /// Last executed sequence ID (0 = no request executed yet).
    pub sequence_id: Sequenceid4,
    /// Cached encoded Compound4Res for replay on retransmit.
    pub cached_reply: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct OpenFileState {
    pub file_id: FileId,
    pub clientid: Clientid4,
    pub owner: Vec<u8>,
    pub stateid_seq: u32,
    pub share_access: u32,
    pub share_deny: u32,
}

/// Result of stateid validation.
pub struct ValidatedState {
    pub share_access: u32,
}

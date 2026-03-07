use std::collections::HashMap;

use embednfs_proto::*;

use crate::fs::FileId;

#[derive(Debug)]
pub(super) struct LockFileState {
    #[allow(dead_code)]
    pub owner: StateOwner4,
    pub stateid_seq: u32,
}

pub(super) struct StateInner {
    pub clients: HashMap<Clientid4, ClientState>,
    pub sessions: HashMap<Sessionid4, SessionState>,
    pub open_files: HashMap<[u8; 12], OpenFileState>,
    pub lock_files: HashMap<[u8; 12], LockFileState>,
}

#[derive(Debug)]
pub(super) struct ClientState {
    pub clientid: Clientid4,
    #[allow(dead_code)]
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
    pub sequence_id: Sequenceid4,
    #[allow(dead_code)]
    pub cached_reply: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct OpenFileState {
    #[allow(dead_code)]
    pub file_id: FileId,
    #[allow(dead_code)]
    pub clientid: Clientid4,
    #[allow(dead_code)]
    pub stateid_seq: u32,
    #[allow(dead_code)]
    pub share_access: u32,
    #[allow(dead_code)]
    pub share_deny: u32,
}

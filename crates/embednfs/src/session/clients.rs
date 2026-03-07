use std::sync::atomic::Ordering;

use embednfs_proto::*;

use super::manager::StateManager;
use super::state::{ClientState, SessionState, SlotState};

/// Result of SEQUENCE processing.
pub enum SequenceResult {
    /// New request — execute the compound and cache the result.
    NewRequest {
        res: SequenceRes4,
        sessionid: Sessionid4,
        slotid: u32,
    },
    /// Retransmit — return the cached encoded Compound4Res bytes.
    CachedReply(Vec<u8>),
}

impl StateManager {
    /// Handle EXCHANGE_ID.
    pub async fn exchange_id(&self, args: &ExchangeIdArgs4) -> ExchangeIdRes4 {
        let mut inner = self.inner.write().await;

        let clientid = {
            let existing = inner
                .clients
                .values()
                .find(|client| client.owner.ownerid == args.clientowner.ownerid);
            if let Some(client) = existing {
                client.clientid
            } else {
                let clientid = self.next_clientid.fetch_add(1, Ordering::Relaxed);
                inner.clients.insert(
                    clientid,
                    ClientState {
                        clientid,
                        owner: args.clientowner.clone(),
                        confirmed: false,
                        sequence_id: 1,
                    },
                );
                clientid
            }
        };

        let client = inner.clients.get(&clientid).expect("client inserted above");
        let _client_pnfs = args.flags & EXCHGID4_FLAG_MASK_PNFS;
        let pnfs_role = EXCHGID4_FLAG_USE_NON_PNFS;
        let confirmed_flag = if client.confirmed {
            EXCHGID4_FLAG_CONFIRMED_R
        } else {
            0
        };

        ExchangeIdRes4 {
            clientid,
            sequenceid: client.sequence_id,
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
        let client = inner
            .clients
            .get_mut(&args.clientid)
            .ok_or(NfsStat4::StaleClientid)?;

        if args.sequence != client.sequence_id {
            return Err(NfsStat4::SeqMisordered);
        }
        client.sequence_id += 1;
        client.confirmed = true;

        let mut sessionid = [0u8; 16];
        sessionid[..8].copy_from_slice(&args.clientid.to_be_bytes());
        sessionid[8..16].copy_from_slice(&(client.sequence_id as u64).to_be_bytes());

        let max_slots = args.fore_chan_attrs.maxrequests.min(64) as usize;
        let slots = vec![
            SlotState {
                sequence_id: 0,
                cached_reply: None,
            };
            max_slots.max(1)
        ];

        let fore_chan = ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: args.fore_chan_attrs.maxrequestsize.min(1_049_620),
            maxresponsesize: args.fore_chan_attrs.maxresponsesize.min(1_049_620),
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

    /// Handle SEQUENCE (RFC 8881 §18.46).
    ///
    /// Slot stores the last executed sequence ID. A new request has
    /// `sequenceid == stored + 1`; a retransmit has `sequenceid == stored`.
    pub async fn sequence(&self, args: &SequenceArgs4) -> Result<SequenceResult, NfsStat4> {
        let mut inner = self.inner.write().await;
        let session = inner
            .sessions
            .get_mut(&args.sessionid)
            .ok_or(NfsStat4::BadSession)?;

        let slot_idx = args.slotid as usize;
        if slot_idx >= session.slots.len() {
            return Err(NfsStat4::BadSlot);
        }

        let highest_slot = (session.slots.len() - 1) as u32;
        let slot = &mut session.slots[slot_idx];

        if args.sequenceid == slot.sequence_id + 1 {
            // New request — advance slot.
            slot.sequence_id = args.sequenceid;
            slot.cached_reply = None;
            Ok(SequenceResult::NewRequest {
                res: SequenceRes4 {
                    sessionid: args.sessionid,
                    sequenceid: args.sequenceid,
                    slotid: args.slotid,
                    highest_slotid: highest_slot,
                    target_highest_slotid: highest_slot,
                    status_flags: 0,
                },
                sessionid: args.sessionid,
                slotid: args.slotid,
            })
        } else if args.sequenceid == slot.sequence_id {
            // Retransmit — return cached reply if available.
            match &slot.cached_reply {
                Some(cached) => Ok(SequenceResult::CachedReply(cached.clone())),
                None => Err(NfsStat4::RetryUncachedRep),
            }
        } else {
            Err(NfsStat4::SeqMisordered)
        }
    }

    /// Cache the encoded Compound4Res for a slot's replay cache.
    pub async fn cache_slot_reply(
        &self,
        sessionid: &Sessionid4,
        slotid: u32,
        encoded: Vec<u8>,
    ) {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get_mut(sessionid)
            && let Some(slot) = session.slots.get_mut(slotid as usize)
        {
            slot.cached_reply = Some(encoded);
        }
    }

    /// Handle DESTROY_SESSION.
    pub async fn destroy_session(&self, sessionid: &Sessionid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.sessions.remove(sessionid).ok_or(NfsStat4::BadSession)?;
        Ok(())
    }

    /// Handle DESTROY_CLIENTID.
    pub async fn destroy_clientid(&self, clientid: Clientid4) -> Result<(), NfsStat4> {
        let mut inner = self.inner.write().await;
        inner.sessions.retain(|_, session| session.clientid != clientid);
        inner
            .clients
            .remove(&clientid)
            .ok_or(NfsStat4::StaleClientid)?;
        Ok(())
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

    /// Look up the client ID associated with a session.
    pub async fn session_clientid(&self, sessionid: &Sessionid4) -> Option<Clientid4> {
        let inner = self.inner.read().await;
        inner.sessions.get(sessionid).map(|session| session.clientid)
    }
}

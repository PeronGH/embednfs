use embednfs_proto::{NfsStat4, SequenceArgs4, SequenceRes4};

use super::StateManager;
use super::model::{CachedReplay, SequenceCacheToken, SequenceReplay, SessionState};

impl StateManager {
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
    #[expect(
        clippy::indexing_slicing,
        reason = "BadSlot is returned locally before indexing the session slot table"
    )]
    pub(crate) async fn prepare_sequence(
        &self,
        args: &SequenceArgs4,
        fingerprint: &[u8],
        connection_id: u64,
    ) -> SequenceReplay {
        let mut inner = self.inner.write().await;

        let session = match inner.sessions.get_mut(&args.sessionid) {
            Some(session) => session,
            None => return SequenceReplay::Error(NfsStat4::BadSession),
        };
        let _ = session.connections.insert(connection_id);

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
            let clientid = session.clientid;
            let res = Self::sequence_res(session, args);
            return SequenceReplay::Execute(
                res,
                SequenceCacheToken {
                    sessionid: args.sessionid,
                    slotid: args.slotid,
                    fingerprint: fingerprint.to_vec(),
                },
                clientid,
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
}

use tracing::{debug, trace};

use embednfs_proto::*;

use crate::fs::FileSystem;
use crate::session::SequenceResult;

use super::handles::path_to_fh;
use super::util::{
    allows_compound_without_sequence, argop_name, error_res_for_op, res_status, resop_name,
};
use super::NfsServer;

/// Result of compound processing, distinguishing new results from cached replays.
pub(super) enum CompoundResult {
    /// Freshly computed result, with optional session/slot for caching.
    Fresh {
        result: Compound4Res,
        cache_slot: Option<(Sessionid4, u32)>,
    },
    /// Cached encoded Compound4Res bytes from the replay cache.
    CachedReply(Vec<u8>),
}

impl<F: FileSystem> NfsServer<F> {
    pub(super) async fn handle_compound(&self, args: Compound4Args) -> CompoundResult {
        let op_names: Vec<&'static str> = args.argarray.iter().map(argop_name).collect();
        debug!(
            "COMPOUND: tag={:?}, minorversion={}, ops={}, sequence={:?}",
            args.tag,
            args.minorversion,
            args.argarray.len(),
            op_names
        );

        if args.minorversion != 1 {
            return CompoundResult::Fresh {
                result: Compound4Res {
                    status: NfsStat4::MinorVersMismatch,
                    tag: args.tag,
                    resarray: vec![],
                },
                cache_slot: None,
            };
        }

        let total_ops = args.argarray.len();
        let first_op = args.argarray.first();
        let starts_with_sequence = matches!(first_op, Some(NfsArgop4::Sequence(_)));
        let leading_sequence_sessionid = match first_op {
            Some(NfsArgop4::Sequence(sequence)) => Some(sequence.sessionid),
            _ => None,
        };
        let leading_sequence_clientid = match leading_sequence_sessionid {
            Some(sessionid) => self.state.session_clientid(&sessionid).await,
            None => None,
        };

        if let Some(first_op) = first_op
            && !starts_with_sequence
        {
            if allows_compound_without_sequence(first_op) {
                if total_ops != 1 {
                    let res = error_res_for_op(first_op, NfsStat4::NotOnlyOp);
                    return CompoundResult::Fresh {
                        result: Compound4Res {
                            status: NfsStat4::NotOnlyOp,
                            tag: args.tag,
                            resarray: vec![res],
                        },
                        cache_slot: None,
                    };
                }
            } else {
                let status = if matches!(first_op, NfsArgop4::Illegal) {
                    NfsStat4::OpIllegal
                } else {
                    NfsStat4::OpNotInSession
                };
                let res = error_res_for_op(first_op, status);
                return CompoundResult::Fresh {
                    result: Compound4Res {
                        status,
                        tag: args.tag,
                        resarray: vec![res],
                    },
                    cache_slot: None,
                };
            }
        }

        let mut current_fh: Option<NfsFh4> = None;
        let mut saved_fh: Option<NfsFh4> = None;
        let mut resarray = Vec::with_capacity(total_ops);
        let mut overall_status = NfsStat4::Ok;
        let mut cache_slot: Option<(Sessionid4, u32)> = None;

        for (idx, op) in args.argarray.into_iter().enumerate() {
            if idx > 0 {
                if matches!(&op, NfsArgop4::Sequence(_)) {
                    let res = NfsResop4::Sequence(NfsStat4::SequencePos, None);
                    resarray.push(res);
                    overall_status = NfsStat4::SequencePos;
                    break;
                }

                if let NfsArgop4::BindConnToSession(_) = &op {
                    let res = NfsResop4::BindConnToSession(NfsStat4::NotOnlyOp, None);
                    resarray.push(res);
                    overall_status = NfsStat4::NotOnlyOp;
                    break;
                }

                if let NfsArgop4::DestroySession(args) = &op
                    && leading_sequence_sessionid == Some(args.sessionid) && idx + 1 != total_ops
                {
                    let res = NfsResop4::DestroySession(NfsStat4::NotOnlyOp);
                    resarray.push(res);
                    overall_status = NfsStat4::NotOnlyOp;
                    break;
                }

                if let (Some(clientid), NfsArgop4::DestroyClientid(args)) =
                    (leading_sequence_clientid, &op)
                    && args.clientid == clientid
                {
                    let res = NfsResop4::DestroyClientid(NfsStat4::ClientidBusy);
                    resarray.push(res);
                    overall_status = NfsStat4::ClientidBusy;
                    break;
                }

                if let NfsArgop4::MustNotImplement(opcode) = &op {
                    let res = NfsResop4::MustNotImplement(*opcode, NfsStat4::Notsupp);
                    resarray.push(res);
                    overall_status = NfsStat4::Notsupp;
                    break;
                }
            }

            // Handle SEQUENCE at position 0 specially for replay cache.
            let res = if idx == 0
                && let NfsArgop4::Sequence(ref seq_args) = op
            {
                match self.state.sequence(seq_args).await {
                    Ok(SequenceResult::NewRequest {
                        res,
                        sessionid,
                        slotid,
                    }) => {
                        cache_slot = Some((sessionid, slotid));
                        NfsResop4::Sequence(NfsStat4::Ok, Some(res))
                    }
                    Ok(SequenceResult::CachedReply(cached)) => {
                        return CompoundResult::CachedReply(cached);
                    }
                    Err(status) => NfsResop4::Sequence(status, None),
                }
            } else {
                self.handle_op(op, &mut current_fh, &mut saved_fh).await
            };
            let status = res_status(&res);
            trace!("  result: op={}, status={:?}", resop_name(&res), status);
            if status != NfsStat4::Ok {
                debug!("  op failed: status={:?}", status);
            }
            resarray.push(res);

            if status != NfsStat4::Ok {
                overall_status = status;
                break;
            }
        }

        CompoundResult::Fresh {
            result: Compound4Res {
                status: overall_status,
                tag: args.tag,
                resarray,
            },
            cache_slot,
        }
    }

    async fn handle_op(
        &self,
        op: NfsArgop4,
        current_fh: &mut Option<NfsFh4>,
        saved_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        match op {
            NfsArgop4::Access(args) => self.op_access(&args, current_fh).await,
            NfsArgop4::Close(args) => self.op_close(&args, current_fh).await,
            NfsArgop4::Commit(args) => self.op_commit(&args, current_fh).await,
            NfsArgop4::Create(args) => self.op_create(&args, current_fh).await,
            NfsArgop4::Getattr(args) => self.op_getattr(&args, current_fh).await,
            NfsArgop4::Getfh => self.op_getfh(current_fh).await,
            NfsArgop4::Link(args) => self.op_link(&args, current_fh, saved_fh).await,
            NfsArgop4::Lookup(args) => self.op_lookup(&args, current_fh).await,
            NfsArgop4::Lookupp => self.op_lookupp(current_fh).await,
            NfsArgop4::Open(args) => self.op_open(&args, current_fh).await,
            NfsArgop4::Putfh(args) => {
                *current_fh = Some(args.object);
                NfsResop4::Putfh(NfsStat4::Ok)
            }
            NfsArgop4::Putpubfh => {
                *current_fh = Some(path_to_fh("/"));
                NfsResop4::Putpubfh(NfsStat4::Ok)
            }
            NfsArgop4::Putrootfh => {
                *current_fh = Some(path_to_fh("/"));
                NfsResop4::Putrootfh(NfsStat4::Ok)
            }
            NfsArgop4::Read(args) => self.op_read(&args, current_fh).await,
            NfsArgop4::Readdir(args) => self.op_readdir(&args, current_fh).await,
            NfsArgop4::Readlink => self.op_readlink(current_fh).await,
            NfsArgop4::Remove(args) => self.op_remove(&args, current_fh).await,
            NfsArgop4::Rename(args) => self.op_rename(&args, current_fh, saved_fh).await,
            NfsArgop4::Restorefh => {
                if let Some(fh) = saved_fh.clone() {
                    *current_fh = Some(fh);
                    NfsResop4::Restorefh(NfsStat4::Ok)
                } else {
                    NfsResop4::Restorefh(NfsStat4::Restorefh)
                }
            }
            NfsArgop4::Savefh => {
                if let Some(fh) = current_fh.clone() {
                    *saved_fh = Some(fh);
                    NfsResop4::Savefh(NfsStat4::Ok)
                } else {
                    NfsResop4::Savefh(NfsStat4::Nofilehandle)
                }
            }
            NfsArgop4::Secinfo(_) => NfsResop4::Secinfo(
                NfsStat4::Ok,
                vec![SecinfoEntry4 { flavor: 1 }, SecinfoEntry4 { flavor: 0 }],
            ),
            NfsArgop4::Setattr(args) => self.op_setattr(&args, current_fh).await,
            NfsArgop4::Write(args) => self.op_write(&args, current_fh).await,
            NfsArgop4::ExchangeId(args) => {
                let res = self.state.exchange_id(&args).await;
                NfsResop4::ExchangeId(NfsStat4::Ok, Some(res))
            }
            NfsArgop4::CreateSession(args) => match self.state.create_session(&args).await {
                Ok(res) => NfsResop4::CreateSession(NfsStat4::Ok, Some(res)),
                Err(status) => NfsResop4::CreateSession(status, None),
            },
            NfsArgop4::DestroySession(args) => match self.state.destroy_session(&args.sessionid).await
            {
                Ok(()) => NfsResop4::DestroySession(NfsStat4::Ok),
                Err(status) => NfsResop4::DestroySession(status),
            },
            NfsArgop4::Sequence(_) => {
                unreachable!("SEQUENCE is handled directly in handle_compound")
            }
            NfsArgop4::ReclaimComplete(_) => NfsResop4::ReclaimComplete(NfsStat4::Ok),
            NfsArgop4::DestroyClientid(args) => {
                match self.state.destroy_clientid(args.clientid).await {
                    Ok(()) => NfsResop4::DestroyClientid(NfsStat4::Ok),
                    Err(status) => NfsResop4::DestroyClientid(status),
                }
            }
            NfsArgop4::BindConnToSession(args) => {
                match self.state.bind_conn_to_session(&args).await {
                    Ok(res) => NfsResop4::BindConnToSession(NfsStat4::Ok, Some(res)),
                    Err(status) => NfsResop4::BindConnToSession(status, None),
                }
            }
            NfsArgop4::SecInfoNoName(_) => NfsResop4::SecInfoNoName(
                NfsStat4::Ok,
                vec![SecinfoEntry4 { flavor: 1 }, SecinfoEntry4 { flavor: 0 }],
            ),
            NfsArgop4::FreeStateid(args) => match self.state.free_stateid(&args.stateid).await {
                Ok(()) => NfsResop4::FreeStateid(NfsStat4::Ok),
                Err(status) => NfsResop4::FreeStateid(status),
            },
            NfsArgop4::TestStateid(args) => {
                let results = vec![NfsStat4::Ok; args.stateids.len()];
                NfsResop4::TestStateid(NfsStat4::Ok, results)
            }
            NfsArgop4::DelegReturn(_) => NfsResop4::DelegReturn(NfsStat4::Ok),
            NfsArgop4::MustNotImplement(op) => NfsResop4::MustNotImplement(op, NfsStat4::Notsupp),
            NfsArgop4::Lock(args) => self.op_lock(&args, current_fh).await,
            NfsArgop4::Lockt(args) => self.op_lockt(&args, current_fh).await,
            NfsArgop4::Locku(args) => self.op_locku(&args).await,
            NfsArgop4::OpenAttr(_) => NfsResop4::OpenAttr(NfsStat4::Notsupp),
            NfsArgop4::DelegPurge => NfsResop4::DelegPurge(NfsStat4::Ok),
            NfsArgop4::Verify(vattr) => self.op_verify(&vattr, current_fh, false).await,
            NfsArgop4::Nverify(vattr) => self.op_verify(&vattr, current_fh, true).await,
            NfsArgop4::OpenDowngrade(args) => {
                let mut stateid = args.open_stateid;
                stateid.seqid = stateid.seqid.wrapping_add(1);
                NfsResop4::OpenDowngrade(NfsStat4::Ok, Some(stateid))
            }
            NfsArgop4::LayoutGet => NfsResop4::LayoutGet(NfsStat4::Notsupp),
            NfsArgop4::LayoutReturn => NfsResop4::LayoutReturn(NfsStat4::Notsupp),
            NfsArgop4::LayoutCommit => NfsResop4::LayoutCommit(NfsStat4::Notsupp),
            NfsArgop4::GetDirDelegation => NfsResop4::GetDirDelegation(NfsStat4::Notsupp),
            NfsArgop4::WantDelegation => NfsResop4::WantDelegation(NfsStat4::Notsupp),
            NfsArgop4::BackchannelCtl => NfsResop4::BackchannelCtl(NfsStat4::Notsupp),
            NfsArgop4::GetDeviceInfo => NfsResop4::GetDeviceInfo(NfsStat4::Notsupp),
            NfsArgop4::GetDeviceList => NfsResop4::GetDeviceList(NfsStat4::Notsupp),
            NfsArgop4::SetSsv => NfsResop4::SetSsv(NfsStat4::Notsupp),
            NfsArgop4::Illegal => NfsResop4::Illegal(NfsStat4::OpIllegal),
        }
    }
}

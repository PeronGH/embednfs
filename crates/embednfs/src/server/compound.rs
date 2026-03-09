use tracing::{debug, trace};

use embednfs_proto::*;

use crate::fs::{FileSystem, RequestContext};

use super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(super) async fn handle_compound(
        &self,
        args: Compound4Args,
        mut prepared_sequence: Option<NfsResop4>,
        request_ctx: &RequestContext,
        connection_id: u64,
    ) -> Compound4Res {
        let op_names: Vec<&'static str> = args.argarray.iter().map(argop_name).collect();
        debug!(
            "COMPOUND: tag={:?}, minorversion={}, ops={}, sequence={:?}",
            args.tag,
            args.minorversion,
            args.argarray.len(),
            op_names
        );

        if args.minorversion != 1 {
            return Compound4Res {
                status: NfsStat4::MinorVersMismatch,
                tag: args.tag,
                resarray: vec![],
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
                    return Compound4Res {
                        status: NfsStat4::NotOnlyOp,
                        tag: args.tag,
                        resarray: vec![res],
                    };
                }
            } else {
                let status = if matches!(first_op, NfsArgop4::Illegal) {
                    NfsStat4::OpIllegal
                } else {
                    NfsStat4::OpNotInSession
                };
                let res = error_res_for_op(first_op, status);
                return Compound4Res {
                    status,
                    tag: args.tag,
                    resarray: vec![res],
                };
            }
        }

        let mut current_fh: Option<NfsFh4> = None;
        let mut saved_fh: Option<NfsFh4> = None;
        let mut resarray = Vec::with_capacity(total_ops);
        let mut overall_status = NfsStat4::Ok;

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
                    && leading_sequence_sessionid == Some(args.sessionid)
                    && idx + 1 != total_ops
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

            let res = if idx == 0 {
                match (&op, prepared_sequence.take()) {
                    (NfsArgop4::Sequence(_), Some(res)) => res,
                    _ => {
                        self.handle_op(
                            op,
                            &mut current_fh,
                            &mut saved_fh,
                            request_ctx,
                            connection_id,
                            leading_sequence_clientid,
                        )
                        .await
                    }
                }
            } else {
                self.handle_op(
                    op,
                    &mut current_fh,
                    &mut saved_fh,
                    request_ctx,
                    connection_id,
                    leading_sequence_clientid,
                )
                .await
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

        Compound4Res {
            status: overall_status,
            tag: args.tag,
            resarray,
        }
    }

    pub(super) async fn handle_op(
        &self,
        op: NfsArgop4,
        current_fh: &mut Option<NfsFh4>,
        saved_fh: &mut Option<NfsFh4>,
        request_ctx: &RequestContext,
        connection_id: u64,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        match op {
            NfsArgop4::Access(args) => self.op_access(request_ctx, &args, current_fh).await,
            NfsArgop4::Close(args) => self.op_close(&args).await,
            NfsArgop4::Commit(args) => self.op_commit(request_ctx, &args, current_fh).await,
            NfsArgop4::Create(args) => self.op_create(request_ctx, &args, current_fh).await,
            NfsArgop4::Getattr(args) => self.op_getattr(request_ctx, &args, current_fh).await,
            NfsArgop4::Getfh => self.op_getfh(current_fh).await,
            NfsArgop4::Link(args) => self.op_link(request_ctx, &args, current_fh, saved_fh).await,
            NfsArgop4::Lookup(args) => self.op_lookup(request_ctx, &args, current_fh).await,
            NfsArgop4::Lookupp => self.op_lookupp(request_ctx, current_fh).await,
            NfsArgop4::Open(args) => {
                if let Some(clientid) = sequence_clientid
                    && let Err(status) = self
                        .state
                        .validate_open_reclaim(clientid, &args.claim)
                        .await
                {
                    return NfsResop4::Open(status, None);
                }
                self.op_open(request_ctx, &args, current_fh).await
            }
            NfsArgop4::Putfh(args) => {
                if !Self::fh_has_valid_format(&args.object) {
                    return NfsResop4::Putfh(NfsStat4::Badhandle);
                }
                *current_fh = Some(args.object);
                NfsResop4::Putfh(NfsStat4::Ok)
            }
            NfsArgop4::Putpubfh => {
                let root_fh = self.state.object_to_fh(&self.root_object().await).await;
                *current_fh = Some(root_fh);
                NfsResop4::Putpubfh(NfsStat4::Ok)
            }
            NfsArgop4::Putrootfh => {
                let root_fh = self.state.object_to_fh(&self.root_object().await).await;
                *current_fh = Some(root_fh);
                NfsResop4::Putrootfh(NfsStat4::Ok)
            }
            NfsArgop4::Read(args) => self.op_read(request_ctx, &args, current_fh).await,
            NfsArgop4::Readdir(args) => self.op_readdir(request_ctx, &args, current_fh).await,
            NfsArgop4::Readlink => self.op_readlink(request_ctx, current_fh).await,
            NfsArgop4::Remove(args) => self.op_remove(request_ctx, &args, current_fh).await,
            NfsArgop4::Rename(args) => {
                self.op_rename(request_ctx, &args, current_fh, saved_fh)
                    .await
            }
            NfsArgop4::Restorefh => {
                if let Some(fh) = saved_fh.clone() {
                    *current_fh = Some(fh);
                    NfsResop4::Restorefh(NfsStat4::Ok)
                } else {
                    NfsResop4::Restorefh(NfsStat4::Nofilehandle)
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
            NfsArgop4::Setattr(args) => self.op_setattr(request_ctx, &args, current_fh).await,
            NfsArgop4::Write(args) => self.op_write(request_ctx, &args, current_fh).await,
            NfsArgop4::ExchangeId(args) => {
                let res = self.state.exchange_id(&args).await;
                NfsResop4::ExchangeId(NfsStat4::Ok, Some(res))
            }
            NfsArgop4::CreateSession(args) => {
                match self.state.create_session(&args, connection_id).await {
                    Ok(res) => NfsResop4::CreateSession(NfsStat4::Ok, Some(res)),
                    Err(status) => NfsResop4::CreateSession(status, None),
                }
            }
            NfsArgop4::DestroySession(args) => {
                match self
                    .state
                    .destroy_session(&args.sessionid, connection_id)
                    .await
                {
                    Ok(()) => NfsResop4::DestroySession(NfsStat4::Ok),
                    Err(status) => NfsResop4::DestroySession(status),
                }
            }
            NfsArgop4::Sequence(_) => NfsResop4::Sequence(NfsStat4::Serverfault, None),
            NfsArgop4::ReclaimComplete(args) => {
                self.op_reclaim_complete(&args, current_fh, sequence_clientid)
                    .await
            }
            NfsArgop4::DestroyClientid(args) => {
                match self.state.destroy_clientid(args.clientid).await {
                    Ok(()) => NfsResop4::DestroyClientid(NfsStat4::Ok),
                    Err(status) => NfsResop4::DestroyClientid(status),
                }
            }
            NfsArgop4::BindConnToSession(args) => {
                match self.state.bind_conn_to_session(&args, connection_id).await {
                    Ok(res) => NfsResop4::BindConnToSession(NfsStat4::Ok, Some(res)),
                    Err(status) => NfsResop4::BindConnToSession(status, None),
                }
            }
            NfsArgop4::SecInfoNoName(style) => {
                self.op_secinfo_no_name(request_ctx, style, current_fh)
                    .await
            }
            NfsArgop4::FreeStateid(args) => match self.state.free_stateid(&args.stateid).await {
                Ok(()) => NfsResop4::FreeStateid(NfsStat4::Ok),
                Err(status) => NfsResop4::FreeStateid(status),
            },
            NfsArgop4::TestStateid(args) => {
                let results = self.state.test_stateids(&args.stateids).await;
                NfsResop4::TestStateid(NfsStat4::Ok, results)
            }
            NfsArgop4::DelegReturn(_) => NfsResop4::DelegReturn(NfsStat4::Ok),
            NfsArgop4::MustNotImplement(op) => NfsResop4::MustNotImplement(op, NfsStat4::Notsupp),
            NfsArgop4::Lock(args) => self.op_lock(request_ctx, &args, current_fh).await,
            NfsArgop4::Lockt(args) => self.op_lockt(request_ctx, &args, current_fh).await,
            NfsArgop4::Locku(args) => self.op_locku(&args).await,
            NfsArgop4::OpenAttr(args) => self.op_openattr(request_ctx, &args, current_fh).await,
            NfsArgop4::DelegPurge => NfsResop4::DelegPurge(NfsStat4::Ok),
            NfsArgop4::Verify(vattr) => {
                self.op_verify(request_ctx, &vattr, current_fh, false).await
            }
            NfsArgop4::Nverify(vattr) => {
                self.op_verify(request_ctx, &vattr, current_fh, true).await
            }
            NfsArgop4::OpenDowngrade(args) => match self
                .state
                .open_downgrade(&args.open_stateid, args.share_access, args.share_deny)
                .await
            {
                Ok(stateid) => NfsResop4::OpenDowngrade(NfsStat4::Ok, Some(stateid)),
                Err(status) => NfsResop4::OpenDowngrade(status, None),
            },
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

pub(super) fn sequence_error_compound(tag: &str, status: NfsStat4) -> Compound4Res {
    Compound4Res {
        status,
        tag: tag.to_string(),
        resarray: vec![NfsResop4::Sequence(status, None)],
    }
}

fn allows_compound_without_sequence(op: &NfsArgop4) -> bool {
    matches!(
        op,
        NfsArgop4::ExchangeId(_)
            | NfsArgop4::CreateSession(_)
            | NfsArgop4::DestroySession(_)
            | NfsArgop4::DestroyClientid(_)
            | NfsArgop4::BindConnToSession(_)
    )
}

fn error_res_for_op(op: &NfsArgop4, status: NfsStat4) -> NfsResop4 {
    match op {
        NfsArgop4::Access(_) => NfsResop4::Access(status, 0, 0),
        NfsArgop4::Close(_) => NfsResop4::Close(status, Stateid4::default()),
        NfsArgop4::Commit(_) => NfsResop4::Commit(status, [0u8; 8]),
        NfsArgop4::Create(_) => NfsResop4::Create(status, None, Bitmap4::new()),
        NfsArgop4::Getattr(_) => NfsResop4::Getattr(status, None),
        NfsArgop4::Getfh => NfsResop4::Getfh(status, None),
        NfsArgop4::Link(_) => NfsResop4::Link(status, None),
        NfsArgop4::Lookup(_) => NfsResop4::Lookup(status),
        NfsArgop4::Lookupp => NfsResop4::Lookupp(status),
        NfsArgop4::Open(_) => NfsResop4::Open(status, None),
        NfsArgop4::Putfh(_) => NfsResop4::Putfh(status),
        NfsArgop4::Putpubfh => NfsResop4::Putpubfh(status),
        NfsArgop4::Putrootfh => NfsResop4::Putrootfh(status),
        NfsArgop4::Read(_) => NfsResop4::Read(status, None),
        NfsArgop4::Readdir(_) => NfsResop4::Readdir(status, None),
        NfsArgop4::Readlink => NfsResop4::Readlink(status, None),
        NfsArgop4::Remove(_) => NfsResop4::Remove(status, None),
        NfsArgop4::Rename(_) => NfsResop4::Rename(status, None, None),
        NfsArgop4::Restorefh => NfsResop4::Restorefh(status),
        NfsArgop4::Savefh => NfsResop4::Savefh(status),
        NfsArgop4::Secinfo(_) => NfsResop4::Secinfo(status, vec![]),
        NfsArgop4::Setattr(_) => NfsResop4::Setattr(status, Bitmap4::new()),
        NfsArgop4::Write(_) => NfsResop4::Write(status, None),
        NfsArgop4::ExchangeId(_) => NfsResop4::ExchangeId(status, None),
        NfsArgop4::CreateSession(_) => NfsResop4::CreateSession(status, None),
        NfsArgop4::DestroySession(_) => NfsResop4::DestroySession(status),
        NfsArgop4::Sequence(_) => NfsResop4::Sequence(status, None),
        NfsArgop4::ReclaimComplete(_) => NfsResop4::ReclaimComplete(status),
        NfsArgop4::DestroyClientid(_) => NfsResop4::DestroyClientid(status),
        NfsArgop4::BindConnToSession(_) => NfsResop4::BindConnToSession(status, None),
        NfsArgop4::SecInfoNoName(_) => NfsResop4::SecInfoNoName(status, vec![]),
        NfsArgop4::FreeStateid(_) => NfsResop4::FreeStateid(status),
        NfsArgop4::TestStateid(_) => NfsResop4::TestStateid(status, vec![]),
        NfsArgop4::DelegReturn(_) => NfsResop4::DelegReturn(status),
        NfsArgop4::MustNotImplement(op) => NfsResop4::MustNotImplement(*op, status),
        NfsArgop4::Lock(_) => NfsResop4::Lock(status, None, None),
        NfsArgop4::Lockt(_) => NfsResop4::Lockt(status, None),
        NfsArgop4::Locku(_) => NfsResop4::Locku(status, None),
        NfsArgop4::OpenAttr(_) => NfsResop4::OpenAttr(status),
        NfsArgop4::DelegPurge => NfsResop4::DelegPurge(status),
        NfsArgop4::Verify(_) => NfsResop4::Verify(status),
        NfsArgop4::Nverify(_) => NfsResop4::Nverify(status),
        NfsArgop4::OpenDowngrade(_) => NfsResop4::OpenDowngrade(status, None),
        NfsArgop4::LayoutGet => NfsResop4::LayoutGet(status),
        NfsArgop4::LayoutReturn => NfsResop4::LayoutReturn(status),
        NfsArgop4::LayoutCommit => NfsResop4::LayoutCommit(status),
        NfsArgop4::GetDirDelegation => NfsResop4::GetDirDelegation(status),
        NfsArgop4::WantDelegation => NfsResop4::WantDelegation(status),
        NfsArgop4::BackchannelCtl => NfsResop4::BackchannelCtl(status),
        NfsArgop4::GetDeviceInfo => NfsResop4::GetDeviceInfo(status),
        NfsArgop4::GetDeviceList => NfsResop4::GetDeviceList(status),
        NfsArgop4::SetSsv => NfsResop4::SetSsv(status),
        NfsArgop4::Illegal => NfsResop4::Illegal(status),
    }
}

fn argop_name(op: &NfsArgop4) -> &'static str {
    match op {
        NfsArgop4::Access(_) => "ACCESS",
        NfsArgop4::Close(_) => "CLOSE",
        NfsArgop4::Commit(_) => "COMMIT",
        NfsArgop4::Create(_) => "CREATE",
        NfsArgop4::Getattr(_) => "GETATTR",
        NfsArgop4::Getfh => "GETFH",
        NfsArgop4::Link(_) => "LINK",
        NfsArgop4::Lookup(_) => "LOOKUP",
        NfsArgop4::Lookupp => "LOOKUPP",
        NfsArgop4::Open(_) => "OPEN",
        NfsArgop4::Putfh(_) => "PUTFH",
        NfsArgop4::Putpubfh => "PUTPUBFH",
        NfsArgop4::Putrootfh => "PUTROOTFH",
        NfsArgop4::Read(_) => "READ",
        NfsArgop4::Readdir(_) => "READDIR",
        NfsArgop4::Readlink => "READLINK",
        NfsArgop4::Remove(_) => "REMOVE",
        NfsArgop4::Rename(_) => "RENAME",
        NfsArgop4::Restorefh => "RESTOREFH",
        NfsArgop4::Savefh => "SAVEFH",
        NfsArgop4::Secinfo(_) => "SECINFO",
        NfsArgop4::Setattr(_) => "SETATTR",
        NfsArgop4::Write(_) => "WRITE",
        NfsArgop4::ExchangeId(_) => "EXCHANGE_ID",
        NfsArgop4::CreateSession(_) => "CREATE_SESSION",
        NfsArgop4::DestroySession(_) => "DESTROY_SESSION",
        NfsArgop4::Sequence(_) => "SEQUENCE",
        NfsArgop4::ReclaimComplete(_) => "RECLAIM_COMPLETE",
        NfsArgop4::DestroyClientid(_) => "DESTROY_CLIENTID",
        NfsArgop4::BindConnToSession(_) => "BIND_CONN_TO_SESSION",
        NfsArgop4::SecInfoNoName(_) => "SECINFO_NO_NAME",
        NfsArgop4::FreeStateid(_) => "FREE_STATEID",
        NfsArgop4::TestStateid(_) => "TEST_STATEID",
        NfsArgop4::DelegReturn(_) => "DELEGRETURN",
        NfsArgop4::MustNotImplement(_) => "MUST_NOT_IMPLEMENT",
        NfsArgop4::Lock(_) => "LOCK",
        NfsArgop4::Lockt(_) => "LOCKT",
        NfsArgop4::Locku(_) => "LOCKU",
        NfsArgop4::OpenAttr(_) => "OPENATTR",
        NfsArgop4::DelegPurge => "DELEGPURGE",
        NfsArgop4::Verify(_) => "VERIFY",
        NfsArgop4::Nverify(_) => "NVERIFY",
        NfsArgop4::OpenDowngrade(_) => "OPEN_DOWNGRADE",
        NfsArgop4::LayoutGet => "LAYOUTGET",
        NfsArgop4::LayoutReturn => "LAYOUTRETURN",
        NfsArgop4::LayoutCommit => "LAYOUTCOMMIT",
        NfsArgop4::GetDirDelegation => "GET_DIR_DELEGATION",
        NfsArgop4::WantDelegation => "WANT_DELEGATION",
        NfsArgop4::BackchannelCtl => "BACKCHANNEL_CTL",
        NfsArgop4::GetDeviceInfo => "GETDEVICEINFO",
        NfsArgop4::GetDeviceList => "GETDEVICELIST",
        NfsArgop4::SetSsv => "SET_SSV",
        NfsArgop4::Illegal => "ILLEGAL",
    }
}

fn res_status(res: &NfsResop4) -> NfsStat4 {
    match res {
        NfsResop4::Access(s, _, _) => *s,
        NfsResop4::Close(s, _) => *s,
        NfsResop4::Commit(s, _) => *s,
        NfsResop4::Create(s, _, _) => *s,
        NfsResop4::Getattr(s, _) => *s,
        NfsResop4::Getfh(s, _) => *s,
        NfsResop4::Link(s, _) => *s,
        NfsResop4::Lookup(s) => *s,
        NfsResop4::Lookupp(s) => *s,
        NfsResop4::Open(s, _) => *s,
        NfsResop4::Putfh(s) => *s,
        NfsResop4::Putpubfh(s) => *s,
        NfsResop4::Putrootfh(s) => *s,
        NfsResop4::Read(s, _) => *s,
        NfsResop4::Readdir(s, _) => *s,
        NfsResop4::Readlink(s, _) => *s,
        NfsResop4::Remove(s, _) => *s,
        NfsResop4::Rename(s, _, _) => *s,
        NfsResop4::Restorefh(s) => *s,
        NfsResop4::Savefh(s) => *s,
        NfsResop4::Secinfo(s, _) => *s,
        NfsResop4::Setattr(s, _) => *s,
        NfsResop4::Write(s, _) => *s,
        NfsResop4::ExchangeId(s, _) => *s,
        NfsResop4::CreateSession(s, _) => *s,
        NfsResop4::DestroySession(s) => *s,
        NfsResop4::Sequence(s, _) => *s,
        NfsResop4::ReclaimComplete(s) => *s,
        NfsResop4::DestroyClientid(s) => *s,
        NfsResop4::BindConnToSession(s, _) => *s,
        NfsResop4::SecInfoNoName(s, _) => *s,
        NfsResop4::FreeStateid(s) => *s,
        NfsResop4::TestStateid(s, _) => *s,
        NfsResop4::DelegReturn(s) => *s,
        NfsResop4::MustNotImplement(_, s) => *s,
        NfsResop4::Lock(s, _, _) => *s,
        NfsResop4::Lockt(s, _) => *s,
        NfsResop4::Locku(s, _) => *s,
        NfsResop4::OpenAttr(s) => *s,
        NfsResop4::DelegPurge(s) => *s,
        NfsResop4::Verify(s) => *s,
        NfsResop4::Nverify(s) => *s,
        NfsResop4::OpenDowngrade(s, _) => *s,
        NfsResop4::LayoutGet(s) => *s,
        NfsResop4::LayoutReturn(s) => *s,
        NfsResop4::LayoutCommit(s) => *s,
        NfsResop4::GetDirDelegation(s) => *s,
        NfsResop4::WantDelegation(s) => *s,
        NfsResop4::BackchannelCtl(s) => *s,
        NfsResop4::GetDeviceInfo(s) => *s,
        NfsResop4::GetDeviceList(s) => *s,
        NfsResop4::SetSsv(s) => *s,
        NfsResop4::Illegal(s) => *s,
    }
}

fn resop_name(res: &NfsResop4) -> &'static str {
    match res {
        NfsResop4::Access(_, _, _) => "ACCESS",
        NfsResop4::Close(_, _) => "CLOSE",
        NfsResop4::Commit(_, _) => "COMMIT",
        NfsResop4::Create(_, _, _) => "CREATE",
        NfsResop4::Getattr(_, _) => "GETATTR",
        NfsResop4::Getfh(_, _) => "GETFH",
        NfsResop4::Link(_, _) => "LINK",
        NfsResop4::Lookup(_) => "LOOKUP",
        NfsResop4::Lookupp(_) => "LOOKUPP",
        NfsResop4::Open(_, _) => "OPEN",
        NfsResop4::Putfh(_) => "PUTFH",
        NfsResop4::Putpubfh(_) => "PUTPUBFH",
        NfsResop4::Putrootfh(_) => "PUTROOTFH",
        NfsResop4::Read(_, _) => "READ",
        NfsResop4::Readdir(_, _) => "READDIR",
        NfsResop4::Readlink(_, _) => "READLINK",
        NfsResop4::Remove(_, _) => "REMOVE",
        NfsResop4::Rename(_, _, _) => "RENAME",
        NfsResop4::Restorefh(_) => "RESTOREFH",
        NfsResop4::Savefh(_) => "SAVEFH",
        NfsResop4::Secinfo(_, _) => "SECINFO",
        NfsResop4::Setattr(_, _) => "SETATTR",
        NfsResop4::Write(_, _) => "WRITE",
        NfsResop4::ExchangeId(_, _) => "EXCHANGE_ID",
        NfsResop4::CreateSession(_, _) => "CREATE_SESSION",
        NfsResop4::DestroySession(_) => "DESTROY_SESSION",
        NfsResop4::Sequence(_, _) => "SEQUENCE",
        NfsResop4::ReclaimComplete(_) => "RECLAIM_COMPLETE",
        NfsResop4::DestroyClientid(_) => "DESTROY_CLIENTID",
        NfsResop4::BindConnToSession(_, _) => "BIND_CONN_TO_SESSION",
        NfsResop4::SecInfoNoName(_, _) => "SECINFO_NO_NAME",
        NfsResop4::FreeStateid(_) => "FREE_STATEID",
        NfsResop4::TestStateid(_, _) => "TEST_STATEID",
        NfsResop4::DelegReturn(_) => "DELEGRETURN",
        NfsResop4::MustNotImplement(_, _) => "MUST_NOT_IMPLEMENT",
        NfsResop4::Lock(_, _, _) => "LOCK",
        NfsResop4::Lockt(_, _) => "LOCKT",
        NfsResop4::Locku(_, _) => "LOCKU",
        NfsResop4::OpenAttr(_) => "OPENATTR",
        NfsResop4::DelegPurge(_) => "DELEGPURGE",
        NfsResop4::Verify(_) => "VERIFY",
        NfsResop4::Nverify(_) => "NVERIFY",
        NfsResop4::OpenDowngrade(_, _) => "OPEN_DOWNGRADE",
        NfsResop4::LayoutGet(_) => "LAYOUTGET",
        NfsResop4::LayoutReturn(_) => "LAYOUTRETURN",
        NfsResop4::LayoutCommit(_) => "LAYOUTCOMMIT",
        NfsResop4::GetDirDelegation(_) => "GET_DIR_DELEGATION",
        NfsResop4::WantDelegation(_) => "WANT_DELEGATION",
        NfsResop4::BackchannelCtl(_) => "BACKCHANNEL_CTL",
        NfsResop4::GetDeviceInfo(_) => "GETDEVICEINFO",
        NfsResop4::GetDeviceList(_) => "GETDEVICELIST",
        NfsResop4::SetSsv(_) => "SET_SSV",
        NfsResop4::Illegal(_) => "ILLEGAL",
    }
}

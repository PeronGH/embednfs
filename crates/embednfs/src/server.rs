use bytes::{Bytes, BytesMut};
/// NFSv4.1 server - COMPOUND procedure handling.
///
/// This is the core of the NFS server. It receives COMPOUND requests,
/// dispatches each operation, and builds the COMPOUND response.
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

use crate::attrs;
use crate::fs::*;
use crate::session::StateManager;

/// The NFS server.
pub struct NfsServer<F: NfsFileSystem> {
    fs: Arc<F>,
    state: Arc<StateManager>,
}

impl<F: NfsFileSystem> NfsServer<F> {
    /// Create a new NFS server with the given filesystem.
    pub fn new(fs: F) -> Self {
        NfsServer {
            fs: Arc::new(fs),
            state: Arc::new(StateManager::new()),
        }
    }

    /// Start listening on the given address.
    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Serve on an already-bound TCP listener. Returns the local address.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let local_addr = listener.local_addr()?;
        info!("NFSv4.1 server listening on {local_addr}");

        let server = Arc::new(self);

        loop {
            let (stream, peer) = listener.accept().await?;
            stream.set_nodelay(true)?;
            debug!("New connection from {peer}");
            let server = server.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    debug!("Connection error from {peer}: {e}");
                }
            });
        }
    }

    async fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        let (mut reader, writer) = stream.into_split();
        let mut writer = BufWriter::with_capacity(65536, writer);
        // Reusable read buffer to avoid per-request allocation
        let mut read_buf = vec![0u8; 65536];

        loop {
            // Read RPC-over-TCP record marking: 4-byte header
            // Bit 31 = last fragment, bits 0-30 = length
            let mut header = [0u8; 4];
            match reader.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let header_val = u32::from_be_bytes(header);
            let _last_fragment = (header_val & 0x80000000) != 0;
            let frag_len = (header_val & 0x7FFFFFFF) as usize;

            if frag_len > 2 * 1024 * 1024 {
                warn!("Fragment too large: {frag_len}");
                return Ok(());
            }

            // Grow read buffer if needed (amortized, never shrinks)
            if read_buf.len() < frag_len {
                read_buf.resize(frag_len, 0);
            }
            reader.read_exact(&mut read_buf[..frag_len]).await?;

            let response = self.process_rpc_message(&read_buf[..frag_len]).await;

            // Write response with record marking header + response in one flush
            let resp_len = (response.len() as u32) | 0x80000000;
            writer.write_all(&resp_len.to_be_bytes()).await?;
            writer.write_all(&response).await?;
            writer.flush().await?;
        }
    }

    async fn process_rpc_message(&self, data: &[u8]) -> Bytes {
        trace!("RPC request bytes={} hex={:02x?}", data.len(), data);
        let mut src = Bytes::copy_from_slice(data);

        // Parse RPC call header
        let call = match RpcCallHeader::decode(&mut src) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to decode RPC header: {e}");
                return Bytes::new();
            }
        };

        // Pre-size response: RPC header ~28 bytes + typical response
        let mut response = BytesMut::with_capacity(8192);

        // Check RPC version
        if call.rpcvers != RPC_VERSION {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, RPC_VERSION, RPC_VERSION);
            return response.freeze();
        }

        // Check NFS program
        if call.prog != NFS_PROGRAM {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, NFS_PROGRAM, NFS_PROGRAM);
            return response.freeze();
        }

        // Check NFS version
        if call.vers != NFS_V4 {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, NFS_V4, NFS_V4);
            return response.freeze();
        }

        match call.proc_num {
            0 => {
                // NULL procedure
                encode_rpc_reply_accepted(&mut response, call.xid);
            }
            1 => {
                // COMPOUND procedure
                match Compound4Args::decode(&mut src) {
                    Ok(args) => {
                        let result = self.handle_compound(args).await;
                        encode_rpc_reply_accepted(&mut response, call.xid);
                        result.encode(&mut response);
                    }
                    Err(e) => {
                        warn!("Failed to decode COMPOUND: {e}");
                        encode_rpc_reply_accepted(&mut response, call.xid);
                        let result = Compound4Res {
                            status: NfsStat4::BadXdr,
                            tag: String::new(),
                            resarray: vec![],
                        };
                        result.encode(&mut response);
                    }
                }
            }
            _ => {
                encode_rpc_reply_proc_unavail(&mut response, call.xid);
            }
        }

        let response = response.freeze();
        trace!(
            "RPC response xid={} bytes={} hex={:02x?}",
            call.xid,
            response.len(),
            response
        );
        response
    }

    async fn handle_compound(&self, args: Compound4Args) -> Compound4Res {
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

        if let Some(first_op) = first_op {
            if !starts_with_sequence {
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

                if let NfsArgop4::DestroySession(args) = &op {
                    if leading_sequence_sessionid == Some(args.sessionid) && idx + 1 != total_ops {
                        let res = NfsResop4::DestroySession(NfsStat4::NotOnlyOp);
                        resarray.push(res);
                        overall_status = NfsStat4::NotOnlyOp;
                        break;
                    }
                }

                if let (Some(clientid), NfsArgop4::DestroyClientid(args)) =
                    (leading_sequence_clientid, &op)
                {
                    if args.clientid == clientid {
                        let res = NfsResop4::DestroyClientid(NfsStat4::ClientidBusy);
                        resarray.push(res);
                        overall_status = NfsStat4::ClientidBusy;
                        break;
                    }
                }

                if let NfsArgop4::MustNotImplement(opcode) = &op {
                    let res = NfsResop4::MustNotImplement(*opcode, NfsStat4::Notsupp);
                    resarray.push(res);
                    overall_status = NfsStat4::Notsupp;
                    break;
                }
            }

            let res = self.handle_op(op, &mut current_fh, &mut saved_fh).await;

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
                let root_fh = self.state.file_id_to_fh(1).await;
                *current_fh = Some(root_fh);
                NfsResop4::Putpubfh(NfsStat4::Ok)
            }
            NfsArgop4::Putrootfh => {
                let root_fh = self.state.file_id_to_fh(1).await;
                *current_fh = Some(root_fh);
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
            NfsArgop4::Secinfo(_) => {
                NfsResop4::Secinfo(
                    NfsStat4::Ok,
                    vec![
                        SecinfoEntry4 { flavor: 1 }, // AUTH_SYS
                        SecinfoEntry4 { flavor: 0 }, // AUTH_NONE
                    ],
                )
            }
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
            NfsArgop4::DestroySession(args) => {
                match self.state.destroy_session(&args.sessionid).await {
                    Ok(()) => NfsResop4::DestroySession(NfsStat4::Ok),
                    Err(status) => NfsResop4::DestroySession(status),
                }
            }
            NfsArgop4::Sequence(args) => match self.state.sequence(&args).await {
                Ok(res) => NfsResop4::Sequence(NfsStat4::Ok, Some(res)),
                Err(status) => NfsResop4::Sequence(status, None),
            },
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
            NfsArgop4::SecInfoNoName(_) => {
                NfsResop4::SecInfoNoName(
                    NfsStat4::Ok,
                    vec![
                        SecinfoEntry4 { flavor: 1 }, // AUTH_SYS
                        SecinfoEntry4 { flavor: 0 }, // AUTH_NONE
                    ],
                )
            }
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
            NfsArgop4::OpenAttr(_) => {
                // Named attributes not supported
                NfsResop4::OpenAttr(NfsStat4::Notsupp)
            }
            NfsArgop4::DelegPurge => NfsResop4::DelegPurge(NfsStat4::Ok),
            NfsArgop4::Verify(vattr) => self.op_verify(&vattr, current_fh, false).await,
            NfsArgop4::Nverify(vattr) => self.op_verify(&vattr, current_fh, true).await,
            NfsArgop4::OpenDowngrade(args) => {
                // Accept the downgrade, return the stateid
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

    // ===== Individual operation handlers =====

    async fn resolve_fh(&self, fh: &Option<NfsFh4>) -> Result<FileId, NfsStat4> {
        let fh = fh.as_ref().ok_or(NfsStat4::Nofilehandle)?;
        self.state.fh_to_file_id(fh).await.ok_or(NfsStat4::Stale)
    }

    async fn op_access(&self, args: &AccessArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Access(status, 0, 0),
        };

        match self.fs.getattr(file_id).await {
            Ok(attr) => {
                let mut server_supported = ACCESS4_READ
                    | ACCESS4_LOOKUP
                    | ACCESS4_MODIFY
                    | ACCESS4_EXTEND
                    | ACCESS4_DELETE
                    | ACCESS4_EXECUTE;
                if attr.file_type == FileType::Directory {
                    server_supported &= !(ACCESS4_EXECUTE);
                }
                // Return only the bits the client asked about
                let supported = args.access & server_supported;
                let access = supported; // Grant all supported access
                NfsResop4::Access(NfsStat4::Ok, supported, access)
            }
            Err(e) => NfsResop4::Access(e.to_nfsstat4(), 0, 0),
        }
    }

    async fn op_close(&self, args: &CloseArgs4, _current_fh: &Option<NfsFh4>) -> NfsResop4 {
        match self.state.close_state(&args.open_stateid).await {
            Ok(stateid) => NfsResop4::Close(NfsStat4::Ok, stateid),
            Err(status) => NfsResop4::Close(status, Stateid4::default()),
        }
    }

    async fn op_commit(&self, _args: &CommitArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Commit(status, [0u8; 8]),
        };

        match self.fs.commit(file_id).await {
            Ok(()) => NfsResop4::Commit(NfsStat4::Ok, self.state.write_verifier),
            Err(e) => NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
        }
    }

    async fn op_create(&self, args: &CreateArgs4, current_fh: &mut Option<NfsFh4>) -> NfsResop4 {
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let dir_attr_before = match self.fs.getattr(dir_id).await {
            Ok(a) => a,
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        };

        let set_attrs = attrs::decode_setattr(&args.createattrs);

        let result = match &args.objtype {
            Createtype4::Dir => self.fs.mkdir(dir_id, &args.objname, &set_attrs).await,
            Createtype4::Link(target) => {
                self.fs
                    .symlink(dir_id, &args.objname, target, &set_attrs)
                    .await
            }
            _ => Err(NfsError::Notsupp),
        };

        match result {
            Ok(new_id) => {
                let dir_attr_after = self
                    .fs
                    .getattr(dir_id)
                    .await
                    .unwrap_or(dir_attr_before.clone());
                let new_fh = self.state.file_id_to_fh(new_id).await;
                *current_fh = Some(new_fh);
                let cinfo = ChangeInfo4 {
                    atomic: true,
                    before: dir_attr_before.change_id,
                    after: dir_attr_after.change_id,
                };
                NfsResop4::Create(NfsStat4::Ok, Some(cinfo), args.createattrs.attrmask.clone())
            }
            Err(e) => NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        }
    }

    async fn op_getattr(&self, args: &GetattrArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Getattr(status, None),
        };

        let fh = current_fh.as_ref().unwrap();

        match self.fs.getattr(file_id).await {
            Ok(attr) => {
                let fattr = attrs::encode_fattr4(&attr, &args.attr_request, fh, &self.fs.fs_info());
                debug!(
                    "GETATTR response: file_id={file_id}, request={:?}, returned={:?}, attr_bytes={}",
                    args.attr_request.0,
                    fattr.attrmask.0,
                    fattr.attr_vals.len()
                );
                NfsResop4::Getattr(NfsStat4::Ok, Some(fattr))
            }
            Err(e) => NfsResop4::Getattr(e.to_nfsstat4(), None),
        }
    }

    async fn op_getfh(&self, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        match current_fh {
            Some(fh) => NfsResop4::Getfh(NfsStat4::Ok, Some(fh.clone())),
            None => NfsResop4::Getfh(NfsStat4::Nofilehandle, None),
        }
    }

    async fn op_link(
        &self,
        args: &LinkArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let source_id = match self.resolve_fh(saved_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Link(status, None),
        };
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Link(status, None),
        };

        let dir_attr_before = match self.fs.getattr(dir_id).await {
            Ok(a) => a,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };

        match self.fs.link(source_id, dir_id, &args.newname).await {
            Ok(()) => {
                let dir_attr_after = self
                    .fs
                    .getattr(dir_id)
                    .await
                    .unwrap_or(dir_attr_before.clone());
                let cinfo = ChangeInfo4 {
                    atomic: true,
                    before: dir_attr_before.change_id,
                    after: dir_attr_after.change_id,
                };
                NfsResop4::Link(NfsStat4::Ok, Some(cinfo))
            }
            Err(e) => NfsResop4::Link(e.to_nfsstat4(), None),
        }
    }

    async fn op_lookup(&self, args: &LookupArgs4, current_fh: &mut Option<NfsFh4>) -> NfsResop4 {
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Lookup(status),
        };

        match self.fs.lookup(dir_id, &args.objname).await {
            Ok(child_id) => {
                let child_fh = self.state.file_id_to_fh(child_id).await;
                *current_fh = Some(child_fh);
                NfsResop4::Lookup(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookup(e.to_nfsstat4()),
        }
    }

    async fn op_lookupp(&self, current_fh: &mut Option<NfsFh4>) -> NfsResop4 {
        let id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Lookupp(status),
        };

        match self.fs.lookup_parent(id).await {
            Ok(parent_id) => {
                let parent_fh = self.state.file_id_to_fh(parent_id).await;
                *current_fh = Some(parent_fh);
                NfsResop4::Lookupp(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookupp(e.to_nfsstat4()),
        }
    }

    async fn op_open(&self, args: &OpenArgs4, current_fh: &mut Option<NfsFh4>) -> NfsResop4 {
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Open(status, None),
        };

        let (file_id, created) = match &args.claim {
            OpenClaim4::Null(name) => {
                // Try to look up existing file
                match self.fs.lookup(dir_id, name).await {
                    Ok(id) => (id, false),
                    Err(NfsError::Noent) => {
                        // Create if requested
                        match &args.openhow {
                            Openflag4::Create(how) => {
                                let set_attrs = match how {
                                    Createhow4::Unchecked(fa) | Createhow4::Guarded(fa) => {
                                        attrs::decode_setattr(fa)
                                    }
                                    Createhow4::Exclusive4_1 { attrs: fa, .. } => {
                                        attrs::decode_setattr(fa)
                                    }
                                    Createhow4::Exclusive(_) => SetFileAttr::default(),
                                };
                                match self.fs.create(dir_id, name, &set_attrs).await {
                                    Ok(id) => (id, true),
                                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                                }
                            }
                            Openflag4::NoCreate => {
                                return NfsResop4::Open(NfsStat4::Noent, None);
                            }
                        }
                    }
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            OpenClaim4::Fh => {
                // Current FH is the file
                (dir_id, false)
            }
            OpenClaim4::Previous(_) => {
                // Reclaim open: just accept the current FH as the file
                (dir_id, false)
            }
            OpenClaim4::DelegCurFh(_) | OpenClaim4::DelegPrevFh => {
                // Delegation claims on current FH
                (dir_id, false)
            }
            _ => {
                return NfsResop4::Open(NfsStat4::Notsupp, None);
            }
        };

        let dir_attr = self.fs.getattr(dir_id).await.unwrap_or_default();
        let new_fh = self.state.file_id_to_fh(file_id).await;

        let stateid = self
            .state
            .create_open_state(
                file_id,
                args.owner.clientid,
                args.share_access,
                args.share_deny,
            )
            .await;

        *current_fh = Some(new_fh);

        let cinfo = ChangeInfo4 {
            atomic: true,
            before: dir_attr.change_id.wrapping_sub(if created { 1 } else { 0 }),
            after: dir_attr.change_id,
        };

        let rflags = OPEN4_RESULT_LOCKTYPE_POSIX;

        NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid,
                cinfo,
                rflags,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::None,
            }),
        )
    }

    async fn op_read(&self, args: &ReadArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Read(status, None),
        };

        match self.fs.read(file_id, args.offset, args.count).await {
            Ok((data, eof)) => NfsResop4::Read(NfsStat4::Ok, Some(ReadRes4 { eof, data })),
            Err(e) => NfsResop4::Read(e.to_nfsstat4(), None),
        }
    }

    async fn op_readdir(&self, args: &ReaddirArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Readdir(status, None),
        };

        let dir_attr = match self.fs.getattr(dir_id).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        let cookieverf = dir_attr.change_id.to_be_bytes();

        debug!(
            "READDIR request: dir_id={dir_id}, cookie={}, cookieverf={:02x?}, dircount={}, maxcount={}, attr_request={:?}",
            args.cookie,
            args.cookieverf,
            args.dircount,
            args.maxcount,
            args.attr_request.0
        );

        if args.cookie != 0 && args.cookieverf != cookieverf {
            debug!(
                "READDIR verifier mismatch: dir_id={dir_id}, cookie={}, request={:02x?}, current={:02x?}",
                args.cookie,
                args.cookieverf,
                cookieverf
            );
            return NfsResop4::Readdir(NfsStat4::NotSame, None);
        }

        match self.fs.readdir(dir_id).await {
            Ok(entries) => {
                // READDIR cookies 0, 1, and 2 are reserved by RFC 8881.
                // Apple clients also reserve 1 and 2 for fabricated "." and "..".
                let cookie_start = match args.cookie {
                    0..=2 => 0,
                    cookie => cookie.saturating_sub(2) as usize,
                };
                let available = &entries[cookie_start.min(entries.len())..];

                let maxcount_limit = args.maxcount as usize;
                let dircount_limit = if args.dircount == 0 {
                    usize::MAX
                } else {
                    args.dircount as usize
                };

                let base_resok_len = readdir_resok_len(&[], false);
                if base_resok_len > maxcount_limit {
                    debug!(
                        "READDIR maxcount too small for reply header: dir_id={dir_id}, maxcount={}, header_bytes={base_resok_len}",
                        args.maxcount
                    );
                    return NfsResop4::Readdir(NfsStat4::Toosmall, None);
                }

                let mut result_entries = Vec::with_capacity(available.len().min(64));
                let mut dir_bytes: usize = 0;
                let mut total_resok_bytes = base_resok_len;

                for (i, entry) in available.iter().enumerate() {
                    let entry_fh = self.state.file_id_to_fh(entry.fileid).await;
                    let entry_fattr = attrs::encode_fattr4(
                        &entry.attr,
                        &args.attr_request,
                        &entry_fh,
                        &self.fs.fs_info(),
                    );
                    let result_entry = Entry4 {
                        cookie: (cookie_start + i + 3) as u64,
                        name: entry.name.clone(),
                        attrs: entry_fattr,
                    };
                    let dir_entry_size = readdir_dir_info_len(&result_entry);
                    let entry_total = readdir_entry_list_item_len(&result_entry);

                    let exceeds_dircount = dir_bytes + dir_entry_size > dircount_limit;
                    let exceeds_maxcount = total_resok_bytes + entry_total > maxcount_limit;
                    if !result_entries.is_empty() && (exceeds_dircount || exceeds_maxcount) {
                        break;
                    }

                    if result_entries.is_empty() && exceeds_maxcount {
                        debug!(
                            "READDIR maxcount too small for a single entry: dir_id={dir_id}, name={}, maxcount={}, entry_bytes={entry_total}, base_bytes={base_resok_len}",
                            result_entry.name,
                            args.maxcount
                        );
                        return NfsResop4::Readdir(NfsStat4::Toosmall, None);
                    }

                    dir_bytes += dir_entry_size;
                    total_resok_bytes += entry_total;
                    result_entries.push(result_entry);
                }

                let eof = result_entries.len() == available.len();

                debug!(
                    "READDIR response: dir_id={dir_id}, cookie={}, entries={}, eof={}, dir_bytes={}, resok_bytes={}, cookieverf={:02x?}",
                    args.cookie,
                    result_entries.len(),
                    eof,
                    dir_bytes,
                    total_resok_bytes,
                    cookieverf
                );
                for entry in &result_entries {
                    debug!(
                        "READDIR entry: dir_id={dir_id}, cookie={}, name={:?}, returned={:?}, attr_bytes={}",
                        entry.cookie,
                        entry.name,
                        entry.attrs.attrmask.0,
                        entry.attrs.attr_vals.len()
                    );
                }

                NfsResop4::Readdir(
                    NfsStat4::Ok,
                    Some(ReaddirRes4 {
                        cookieverf,
                        entries: result_entries,
                        eof,
                    }),
                )
            }
            Err(e) => NfsResop4::Readdir(e.to_nfsstat4(), None),
        }
    }

    async fn op_readlink(&self, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Readlink(status, None),
        };

        match self.fs.readlink(file_id).await {
            Ok(target) => NfsResop4::Readlink(NfsStat4::Ok, Some(target)),
            Err(e) => NfsResop4::Readlink(e.to_nfsstat4(), None),
        }
    }

    async fn op_remove(&self, args: &RemoveArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Remove(status, None),
        };

        let dir_attr_before = match self.fs.getattr(dir_id).await {
            Ok(a) => a,
            Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
        };

        match self.fs.remove(dir_id, &args.target).await {
            Ok(()) => {
                let dir_attr_after = self
                    .fs
                    .getattr(dir_id)
                    .await
                    .unwrap_or(dir_attr_before.clone());
                let cinfo = ChangeInfo4 {
                    atomic: true,
                    before: dir_attr_before.change_id,
                    after: dir_attr_after.change_id,
                };
                NfsResop4::Remove(NfsStat4::Ok, Some(cinfo))
            }
            Err(e) => NfsResop4::Remove(e.to_nfsstat4(), None),
        }
    }

    async fn op_rename(
        &self,
        args: &RenameArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        // Saved FH = source dir, Current FH = target dir
        let src_dir_id = match self.resolve_fh(saved_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };
        let tgt_dir_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };

        let src_attr_before = match self.fs.getattr(src_dir_id).await {
            Ok(a) => a,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };
        let tgt_attr_before = match self.fs.getattr(tgt_dir_id).await {
            Ok(a) => a,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };

        match self
            .fs
            .rename(src_dir_id, &args.oldname, tgt_dir_id, &args.newname)
            .await
        {
            Ok(()) => {
                let src_attr_after = self
                    .fs
                    .getattr(src_dir_id)
                    .await
                    .unwrap_or(src_attr_before.clone());
                let tgt_attr_after = self
                    .fs
                    .getattr(tgt_dir_id)
                    .await
                    .unwrap_or(tgt_attr_before.clone());
                let src_cinfo = ChangeInfo4 {
                    atomic: true,
                    before: src_attr_before.change_id,
                    after: src_attr_after.change_id,
                };
                let tgt_cinfo = ChangeInfo4 {
                    atomic: true,
                    before: tgt_attr_before.change_id,
                    after: tgt_attr_after.change_id,
                };
                NfsResop4::Rename(NfsStat4::Ok, Some(src_cinfo), Some(tgt_cinfo))
            }
            Err(e) => NfsResop4::Rename(e.to_nfsstat4(), None, None),
        }
    }

    async fn op_setattr(&self, args: &SetattrArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        let set_attrs = attrs::decode_setattr(&args.obj_attributes);

        match self.fs.setattr(file_id, set_attrs).await {
            Ok(_) => NfsResop4::Setattr(NfsStat4::Ok, args.obj_attributes.attrmask.clone()),
            Err(e) => NfsResop4::Setattr(e.to_nfsstat4(), Bitmap4::new()),
        }
    }

    async fn op_write(&self, args: &WriteArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Write(status, None),
        };

        match self.fs.write(file_id, args.offset, &args.data).await {
            Ok(count) => NfsResop4::Write(
                NfsStat4::Ok,
                Some(WriteRes4 {
                    count,
                    committed: FILE_SYNC4,
                    writeverf: self.state.write_verifier,
                }),
            ),
            Err(e) => NfsResop4::Write(e.to_nfsstat4(), None),
        }
    }

    async fn op_lock(&self, args: &LockArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        let _file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return NfsResop4::Lock(status, None, None),
        };

        // Create or update lock state
        let stateid = match &args.locker {
            Locker4::NewLockOwner(new_owner) => {
                self.state
                    .create_lock_state(&new_owner.open_stateid, &new_owner.lock_owner)
                    .await
            }
            Locker4::ExistingLockOwner(existing) => {
                self.state.update_lock_state(&existing.lock_stateid).await
            }
        };

        match stateid {
            Ok(sid) => NfsResop4::Lock(NfsStat4::Ok, Some(sid), None),
            Err(status) => NfsResop4::Lock(status, None, None),
        }
    }

    async fn op_lockt(&self, _args: &LocktArgs4, current_fh: &Option<NfsFh4>) -> NfsResop4 {
        // Test if a lock would conflict - we don't track conflicts, always say OK
        match self.resolve_fh(current_fh).await {
            Ok(_) => NfsResop4::Lockt(NfsStat4::Ok, None),
            Err(status) => NfsResop4::Lockt(status, None),
        }
    }

    async fn op_locku(&self, args: &LockuArgs4) -> NfsResop4 {
        match self.state.unlock_state(&args.lock_stateid).await {
            Ok(sid) => NfsResop4::Locku(NfsStat4::Ok, Some(sid)),
            Err(status) => NfsResop4::Locku(status, None),
        }
    }

    /// Handle VERIFY (negate=false) and NVERIFY (negate=true).
    ///
    /// VERIFY returns OK if the supplied attrs match the file's current attrs,
    /// or NFS4ERR_NOT_SAME if they differ.
    /// NVERIFY returns OK if attrs differ, NFS4ERR_SAME if they match.
    async fn op_verify(
        &self,
        client_fattr: &Fattr4,
        current_fh: &Option<NfsFh4>,
        negate: bool,
    ) -> NfsResop4 {
        let make_res = |s: NfsStat4| {
            if negate {
                NfsResop4::Nverify(s)
            } else {
                NfsResop4::Verify(s)
            }
        };

        let file_id = match self.resolve_fh(current_fh).await {
            Ok(id) => id,
            Err(status) => return make_res(status),
        };

        let fh = current_fh.as_ref().unwrap();

        let attr = match self.fs.getattr(file_id).await {
            Ok(a) => a,
            Err(e) => return make_res(e.to_nfsstat4()),
        };

        // Encode the server's current attrs using the same bitmap the client sent
        let server_fattr =
            attrs::encode_fattr4(&attr, &client_fattr.attrmask, fh, &self.fs.fs_info());

        // Compare: same bitmap, same values?
        let attrs_match = server_fattr.attrmask == client_fattr.attrmask
            && server_fattr.attr_vals == client_fattr.attr_vals;

        if negate {
            // NVERIFY: OK if different, SAME if match
            if attrs_match {
                make_res(NfsStat4::Same)
            } else {
                make_res(NfsStat4::Ok)
            }
        } else {
            // VERIFY: OK if match, NOT_SAME if different
            if attrs_match {
                make_res(NfsStat4::Ok)
            } else {
                make_res(NfsStat4::NotSame)
            }
        }
    }
}

fn xdr_opaque_len(len: usize) -> usize {
    4 + len + xdr_pad(len)
}

fn xdr_bitmap4_len(bitmap: &Bitmap4) -> usize {
    4 + (bitmap.0.len() * 4)
}

fn xdr_fattr4_len(fattr: &Fattr4) -> usize {
    xdr_bitmap4_len(&fattr.attrmask) + xdr_opaque_len(fattr.attr_vals.len())
}

fn readdir_dir_info_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len())
}

fn readdir_entry_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len()) + xdr_fattr4_len(&entry.attrs)
}

fn readdir_entry_list_item_len(entry: &Entry4) -> usize {
    4 + readdir_entry_len(entry)
}

fn readdir_resok_len(entries: &[Entry4], _eof: bool) -> usize {
    8 + entries.iter().map(readdir_entry_list_item_len).sum::<usize>() + 4 + 4
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

/// Extract the status from a result operation.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(name: &str, fileid: u64) -> Entry4 {
        let mut bitmap = Bitmap4::new();
        bitmap.set(FATTR4_FILEID);
        bitmap.set(FATTR4_TYPE);

        let mut attr_vals = BytesMut::new();
        NfsFtype4::Reg.encode(&mut attr_vals);
        fileid.encode(&mut attr_vals);

        Entry4 {
            cookie: fileid,
            name: name.to_string(),
            attrs: Fattr4 {
                attrmask: bitmap,
                attr_vals: attr_vals.to_vec(),
            },
        }
    }

    #[test]
    fn test_readdir_entry_len_matches_encoded_form() {
        let entry = sample_entry("hello.txt", 42);
        let mut encoded = BytesMut::new();
        entry.cookie.encode(&mut encoded);
        entry.name.encode(&mut encoded);
        entry.attrs.encode(&mut encoded);

        assert_eq!(readdir_entry_len(&entry), encoded.len());
        assert_eq!(readdir_entry_list_item_len(&entry), encoded.len() + 4);
        assert_eq!(readdir_dir_info_len(&entry), 8 + xdr_opaque_len(entry.name.len()));
    }

    #[test]
    fn test_readdir_resok_len_matches_readop_encoding() {
        let entries = vec![sample_entry("a.txt", 1), sample_entry("b.txt", 2)];
        let result = ReaddirRes4 {
            cookieverf: [1, 2, 3, 4, 5, 6, 7, 8],
            entries,
            eof: true,
        };

        let mut encoded = BytesMut::new();
        NfsResop4::Readdir(NfsStat4::Ok, Some(result)).encode(&mut encoded);

        let expected_entries = vec![sample_entry("a.txt", 1), sample_entry("b.txt", 2)];
        assert_eq!(readdir_resok_len(&expected_entries, true), encoded.len() - 8);
    }
}

use bytes::{Bytes, BytesMut};
/// NFSv4.1 server - COMPOUND procedure handling.
///
/// This is the core of the NFS server. It receives COMPOUND requests,
/// dispatches each operation, and builds the COMPOUND response.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

use crate::attrs;
use crate::fs::*;
use crate::internal::{ObjectId, ServerFileAttr, ServerFileType, ServerObject};
use crate::session::{SequenceReplay, StateManager, SynthMeta};

const RPC_LAST_FRAGMENT: u32 = 0x8000_0000;
const RPC_FRAG_LEN_MASK: u32 = 0x7fff_ffff;
const MAX_FRAGMENT_SIZE: usize = 2 * 1024 * 1024;
const CONN_BUF_SIZE: usize = 65_536;

type NfsResult<T> = FsResult<T>;

/// Maps numeric ids to NFS owner/group strings.
pub trait IdMapper: Send + Sync + 'static {
    /// Maps a numeric uid to an NFS owner string.
    fn owner(&self, uid: u32) -> String;

    /// Maps a numeric gid to an NFS owner-group string.
    fn group(&self, gid: u32) -> String;
}

/// Default id mapper that renders numeric ids directly.
pub struct NumericIdMapper;

impl IdMapper for NumericIdMapper {
    fn owner(&self, uid: u32) -> String {
        uid.to_string()
    }

    fn group(&self, gid: u32) -> String {
        gid.to_string()
    }
}

/// Builder for [`NfsServer`].
pub struct NfsServerBuilder<F: FileSystem> {
    fs: F,
    id_mapper: Arc<dyn IdMapper>,
}

impl<F: FileSystem> NfsServerBuilder<F> {
    /// Replaces the uid/gid string mapper used for `owner` attributes.
    pub fn id_mapper<M: IdMapper>(mut self, mapper: M) -> Self {
        self.id_mapper = Arc::new(mapper);
        self
    }

    /// Builds the server instance.
    pub fn build(self) -> NfsServer<F> {
        NfsServer {
            fs: Arc::new(self.fs),
            state: Arc::new(StateManager::new()),
            handle_to_object: Arc::new(RwLock::new(HashMap::new())),
            object_to_handle: Arc::new(RwLock::new(HashMap::new())),
            next_object_id: AtomicU64::new(1),
            id_mapper: self.id_mapper,
        }
    }
}

/// The NFS server.
pub struct NfsServer<F: FileSystem> {
    fs: Arc<F>,
    state: Arc<StateManager>,
    handle_to_object: Arc<RwLock<HashMap<F::Handle, ObjectId>>>,
    object_to_handle: Arc<RwLock<HashMap<ObjectId, F::Handle>>>,
    next_object_id: AtomicU64,
    id_mapper: Arc<dyn IdMapper>,
}

impl<F: FileSystem> NfsServer<F> {
    /// Creates a builder for a new server.
    pub fn builder(fs: F) -> NfsServerBuilder<F> {
        NfsServerBuilder {
            fs,
            id_mapper: Arc::new(NumericIdMapper),
        }
    }

    /// Create a new NFS server with the given filesystem.
    pub fn new(fs: F) -> Self {
        Self::builder(fs).build()
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

    async fn register_handle(&self, handle: &F::Handle) -> ObjectId {
        if let Some(id) = self.handle_to_object.read().await.get(handle).copied() {
            return id;
        }

        let mut handle_to_object = self.handle_to_object.write().await;
        if let Some(id) = handle_to_object.get(handle).copied() {
            return id;
        }

        let id = self.next_object_id.fetch_add(1, Ordering::Relaxed);
        handle_to_object.insert(handle.clone(), id);
        self.object_to_handle
            .write()
            .await
            .insert(id, handle.clone());
        id
    }

    async fn object_from_handle(&self, handle: &F::Handle) -> ServerObject {
        ServerObject::Fs(self.register_handle(handle).await)
    }

    async fn root_object(&self) -> ServerObject {
        self.object_from_handle(&self.fs.root()).await
    }

    async fn resolve_backend_handle(&self, object_id: ObjectId) -> NfsResult<F::Handle> {
        self.object_to_handle
            .read()
            .await
            .get(&object_id)
            .cloned()
            .ok_or(FsError::BadHandle)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<F::Handle>> {
        self.fs.symlinks()
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<F::Handle>> {
        self.fs.hard_links()
    }

    fn named_attrs(&self) -> Option<&dyn Xattrs<F::Handle>> {
        self.fs.xattrs()
    }

    fn syncer(&self) -> Option<&dyn CommitSupport<F::Handle>> {
        self.fs.commit_support()
    }

    fn fh_has_valid_format(fh: &NfsFh4) -> bool {
        fh.0.len() == std::mem::size_of::<u64>()
    }

    fn request_context(cred: &OpaqueAuth) -> RequestContext {
        let auth = match cred.flavor {
            x if x == AuthFlavor::None as u32 => AuthContext::None,
            x if x == AuthFlavor::Sys as u32 => {
                let mut body = Bytes::from(cred.body.clone());
                match AuthSysParams::decode(&mut body) {
                    Ok(params) => AuthContext::Sys {
                        uid: params.uid,
                        gid: params.gid,
                        supplemental_gids: params.gids,
                    },
                    Err(_) => AuthContext::Unknown {
                        flavor: cred.flavor,
                    },
                }
            }
            flavor => AuthContext::Unknown { flavor },
        };

        RequestContext { auth }
    }

    fn capabilities(&self) -> FsCapabilities {
        self.fs.capabilities()
    }

    fn limits(&self) -> FsLimits {
        self.fs.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> NfsResult<FsStats> {
        self.fs.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, id: ObjectId) -> NfsResult<Attrs> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.getattr(ctx, &handle).await
    }

    async fn kind_of(&self, ctx: &RequestContext, id: ObjectId) -> NfsResult<ObjectType> {
        self.getattr(ctx, id).await.map(|attrs| attrs.object_type)
    }

    async fn access_for(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        requested: AccessMask,
    ) -> NfsResult<AccessMask> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.access(ctx, &handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
    ) -> NfsResult<ObjectId> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let child = self.fs.lookup(ctx, &handle, name).await?;
        Ok(self.register_handle(&child).await)
    }

    async fn lookup_parent(&self, ctx: &RequestContext, dir_id: ObjectId) -> NfsResult<ObjectId> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let parent = self.fs.parent(ctx, &handle).await?;
        match parent {
            Some(handle) => Ok(self.register_handle(&handle).await),
            None => Err(FsError::NotFound),
        }
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        offset: u64,
        count: u32,
    ) -> NfsResult<(Bytes, bool)> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs
            .read(ctx, &handle, offset, count)
            .await
            .map(|res| (res.data, res.eof))
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        offset: u64,
        data: Bytes,
    ) -> NfsResult<WriteResult> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.write(ctx, &handle, offset, data).await
    }

    async fn create_file(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
        attrs: SetAttrs,
    ) -> NfsResult<CreateResult<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let created = self
            .fs
            .create(
                ctx,
                &handle,
                name,
                CreateRequest {
                    kind: CreateKind::File,
                    attrs,
                },
            )
            .await?;
        Ok(CreateResult {
            handle: self.register_handle(&created.handle).await,
            attrs: created.attrs,
        })
    }

    async fn create_dir(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        name: &str,
        attrs: SetAttrs,
    ) -> NfsResult<CreateResult<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let created = self
            .fs
            .create(
                ctx,
                &handle,
                name,
                CreateRequest {
                    kind: CreateKind::Directory,
                    attrs,
                },
            )
            .await?;
        Ok(CreateResult {
            handle: self.register_handle(&created.handle).await,
            attrs: created.attrs,
        })
    }

    async fn remove(&self, ctx: &RequestContext, dir_id: ObjectId, name: &str) -> NfsResult<()> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        self.fs.remove(ctx, &handle, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: ObjectId,
        from_name: &str,
        to_dir: ObjectId,
        to_name: &str,
    ) -> NfsResult<()> {
        let from_handle = self.resolve_backend_handle(from_dir).await?;
        let to_handle = self.resolve_backend_handle(to_dir).await?;
        self.fs
            .rename(ctx, &from_handle, from_name, &to_handle, to_name)
            .await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir_id: ObjectId,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> NfsResult<DirPage<ObjectId>> {
        let handle = self.resolve_backend_handle(dir_id).await?;
        let page = self
            .fs
            .readdir(ctx, &handle, cookie, max_entries, with_attrs)
            .await?;
        let mut entries = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let object_id = self.register_handle(&entry.handle).await;
            entries.push(DirEntry {
                name: entry.name,
                handle: object_id,
                cookie: entry.cookie,
                attrs: entry.attrs,
            });
        }
        Ok(DirPage {
            entries,
            eof: page.eof,
        })
    }

    async fn setattr_real(
        &self,
        ctx: &RequestContext,
        id: ObjectId,
        attrs: &SetAttrs,
    ) -> NfsResult<Attrs> {
        let handle = self.resolve_backend_handle(id).await?;
        self.fs.setattr(ctx, &handle, attrs).await
    }

    fn nfs_access_mask(bits: u32) -> AccessMask {
        let mut out = AccessMask::NONE;
        if bits & ACCESS4_READ != 0 {
            out |= AccessMask::READ;
        }
        if bits & ACCESS4_LOOKUP != 0 {
            out |= AccessMask::LOOKUP;
        }
        if bits & ACCESS4_MODIFY != 0 {
            out |= AccessMask::MODIFY;
        }
        if bits & ACCESS4_EXTEND != 0 {
            out |= AccessMask::EXTEND;
        }
        if bits & ACCESS4_DELETE != 0 {
            out |= AccessMask::DELETE;
        }
        if bits & ACCESS4_EXECUTE != 0 {
            out |= AccessMask::EXECUTE;
        }
        out
    }

    fn access_bits(mask: AccessMask) -> u32 {
        let mut out = 0;
        if mask.intersects(AccessMask::READ) {
            out |= ACCESS4_READ;
        }
        if mask.intersects(AccessMask::LOOKUP) {
            out |= ACCESS4_LOOKUP;
        }
        if mask.intersects(AccessMask::MODIFY) {
            out |= ACCESS4_MODIFY;
        }
        if mask.intersects(AccessMask::EXTEND) {
            out |= ACCESS4_EXTEND;
        }
        if mask.intersects(AccessMask::DELETE) {
            out |= ACCESS4_DELETE;
        }
        if mask.intersects(AccessMask::EXECUTE) {
            out |= ACCESS4_EXECUTE;
        }
        out
    }

    fn committed_how(stability: WriteStability) -> u32 {
        match stability {
            WriteStability::Unstable => UNSTABLE4,
            WriteStability::DataSync => DATA_SYNC4,
            WriteStability::FileSync => FILE_SYNC4,
        }
    }

    async fn encode_fattr(
        &self,
        request_ctx: &RequestContext,
        attr: &ServerFileAttr,
        request: &Bitmap4,
        fh: &NfsFh4,
    ) -> NfsResult<Fattr4> {
        let stats = self.statfs(request_ctx).await?;
        let limits = self.limits();
        let capabilities = self.capabilities();
        let ctx = attrs::AttrEncodingContext {
            limits: &limits,
            stats: &stats,
            capabilities: &capabilities,
        };
        Ok(attrs::encode_fattr4(attr, request, fh, &ctx))
    }

    async fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> std::io::Result<()> {
        let connection_id = self.state.alloc_connection_id();
        let (mut reader, writer) = stream.into_split();
        let mut writer = BufWriter::with_capacity(CONN_BUF_SIZE, writer);
        let mut read_buf = vec![0u8; CONN_BUF_SIZE];

        loop {
            let mut header = [0u8; 4];
            match reader.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let header_val = u32::from_be_bytes(header);
            let last_fragment = (header_val & RPC_LAST_FRAGMENT) != 0;
            let frag_len = (header_val & RPC_FRAG_LEN_MASK) as usize;

            // TODO: Support RFC 5531 multi-fragment record assembly if non-localhost
            // transport support becomes a target.
            if !last_fragment {
                trace!("received non-terminal RPC fragment; multi-fragment assembly is deferred");
            }

            if frag_len > MAX_FRAGMENT_SIZE {
                warn!("Fragment too large: {frag_len}");
                return Ok(());
            }

            if read_buf.len() < frag_len {
                read_buf.resize(frag_len, 0);
            }
            reader.read_exact(&mut read_buf[..frag_len]).await?;

            let Some(response) = self
                .process_rpc_message(&read_buf[..frag_len], connection_id)
                .await
            else {
                return Ok(());
            };

            // The server fully materializes one RPC reply at a time, so exceeding the
            // fragment limit here indicates an internal sizing bug rather than a
            // recoverable client error.
            let resp_len = u32::try_from(response.len())
                .ok()
                .filter(|len| *len <= RPC_FRAG_LEN_MASK)
                .expect("response exceeds RPC fragment limit");
            let resp_len = resp_len | RPC_LAST_FRAGMENT;
            writer.write_all(&resp_len.to_be_bytes()).await?;
            writer.write_all(&response).await?;
            writer.flush().await?;
        }
    }

    async fn process_rpc_message(&self, data: &[u8], connection_id: u64) -> Option<Bytes> {
        trace!("RPC request bytes={} hex={}", data.len(), hex_bytes(data));
        let mut src = Bytes::copy_from_slice(data);

        let call = match RpcCallHeader::decode(&mut src) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to decode RPC header: {e}");
                return None;
            }
        };

        let mut response = BytesMut::with_capacity(8192);

        if call.rpcvers != RPC_VERSION {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, RPC_VERSION, RPC_VERSION);
            return Some(response.freeze());
        }

        if call.prog != NFS_PROGRAM {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, NFS_PROGRAM, NFS_PROGRAM);
            return Some(response.freeze());
        }

        if call.vers != NFS_V4 {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, NFS_V4, NFS_V4);
            return Some(response.freeze());
        }

        match call.proc_num {
            0 => encode_rpc_reply_accepted(&mut response, call.xid),
            1 => {
                let compound_payload = src.clone();
                match Compound4Args::decode(&mut src) {
                    Ok(args) => {
                        let request_ctx = Self::request_context(&call.cred);
                        let mut replay_token = None;
                        let prepared_sequence = if args.minorversion == 1 {
                            match args.argarray.first() {
                                Some(NfsArgop4::Sequence(seq_args)) => {
                                    let fingerprint =
                                        replay_fingerprint(&call.cred, &compound_payload);
                                    match self
                                        .state
                                        .prepare_sequence(seq_args, &fingerprint, connection_id)
                                        .await
                                    {
                                        SequenceReplay::Execute(res, token) => {
                                            replay_token = Some(token);
                                            Some(NfsResop4::Sequence(NfsStat4::Ok, Some(res)))
                                        }
                                        SequenceReplay::Replay(cached) => {
                                            encode_rpc_reply_accepted(&mut response, call.xid);
                                            response.extend_from_slice(&cached);
                                            return Some(response.freeze());
                                        }
                                        SequenceReplay::Error(status) => {
                                            let result = sequence_error_compound(&args.tag, status);
                                            encode_rpc_reply_accepted(&mut response, call.xid);
                                            result.encode(&mut response);
                                            return Some(response.freeze());
                                        }
                                    }
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };

                        let result = self
                            .handle_compound(args, prepared_sequence, &request_ctx, connection_id)
                            .await;
                        encode_rpc_reply_accepted(&mut response, call.xid);
                        let body_start = response.len();
                        result.encode(&mut response);
                        if let Some(token) = replay_token {
                            let body = response[body_start..].to_vec();
                            if let Err(status) = self.state.finish_sequence(token, body).await {
                                warn!("Failed to finalize replay cache entry: {status:?}");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to decode COMPOUND: {e}");
                        encode_rpc_reply_accepted(&mut response, call.xid);
                        Compound4Res {
                            status: NfsStat4::BadXdr,
                            tag: String::new(),
                            resarray: vec![],
                        }
                        .encode(&mut response);
                    }
                }
            }
            _ => encode_rpc_reply_proc_unavail(&mut response, call.xid),
        }

        let response = response.freeze();
        trace!(
            "RPC response xid={} bytes={} hex={}",
            call.xid,
            response.len(),
            hex_bytes(&response)
        );
        Some(response)
    }

    async fn handle_compound(
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

    async fn handle_op(
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
                    && let Err(status) = self.state.validate_open_reclaim(clientid, &args.claim).await
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
            NfsArgop4::CreateSession(args) => match self.state.create_session(&args, connection_id).await {
                Ok(res) => NfsResop4::CreateSession(NfsStat4::Ok, Some(res)),
                Err(status) => NfsResop4::CreateSession(status, None),
            },
            NfsArgop4::DestroySession(args) => {
                match self.state.destroy_session(&args.sessionid, connection_id).await {
                    Ok(()) => NfsResop4::DestroySession(NfsStat4::Ok),
                    Err(status) => NfsResop4::DestroySession(status),
                }
            }
            NfsArgop4::Sequence(_) => NfsResop4::Sequence(NfsStat4::Serverfault, None),
            NfsArgop4::ReclaimComplete(args) => {
                self.op_reclaim_complete(&args, current_fh, sequence_clientid).await
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
                self.op_secinfo_no_name(request_ctx, style, current_fh).await
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

    fn attr_from_meta(
        meta: SynthMeta,
        file_type: ServerFileType,
        size: u64,
        has_named_attrs: bool,
    ) -> ServerFileAttr {
        ServerFileAttr {
            fileid: meta.fileid,
            file_type,
            size,
            used: size,
            mode: meta.mode,
            nlink: meta.nlink,
            owner: meta.owner,
            owner_group: meta.owner_group,
            atime_sec: meta.atime_sec,
            atime_nsec: meta.atime_nsec,
            mtime_sec: meta.mtime_sec,
            mtime_nsec: meta.mtime_nsec,
            ctime_sec: meta.ctime_sec,
            ctime_nsec: meta.ctime_nsec,
            crtime_sec: meta.crtime_sec,
            crtime_nsec: meta.crtime_nsec,
            change_id: meta.change_id,
            rdev_major: 0,
            rdev_minor: 0,
            archive: meta.archive,
            hidden: meta.hidden,
            system: meta.system,
            has_named_attrs,
        }
    }

    fn attr_from_backend(&self, attrs: Attrs) -> ServerFileAttr {
        ServerFileAttr {
            fileid: attrs.fileid,
            file_type: ServerFileType::from_attrs(&attrs),
            size: attrs.size,
            used: attrs.space_used,
            mode: attrs.mode,
            nlink: attrs.link_count,
            owner: self.id_mapper.owner(attrs.uid),
            owner_group: self.id_mapper.group(attrs.gid),
            atime_sec: attrs.atime.seconds,
            atime_nsec: attrs.atime.nanos,
            mtime_sec: attrs.mtime.seconds,
            mtime_nsec: attrs.mtime.nanos,
            ctime_sec: attrs.ctime.seconds,
            ctime_nsec: attrs.ctime.nanos,
            crtime_sec: attrs.birthtime.seconds,
            crtime_nsec: attrs.birthtime.nanos,
            change_id: attrs.change,
            rdev_major: 0,
            rdev_minor: 0,
            archive: attrs.archive,
            hidden: attrs.hidden,
            system: attrs.system,
            has_named_attrs: attrs.has_named_attrs,
        }
    }

    async fn build_attr(
        &self,
        ctx: &RequestContext,
        object: &ServerObject,
    ) -> NfsResult<ServerFileAttr> {
        match object {
            ServerObject::Fs(id) => {
                let attrs = self.getattr(ctx, *id).await?;
                Ok(self.attr_from_backend(attrs))
            }
            ServerObject::NamedAttrDir(parent) => {
                if self.named_attrs().is_none() {
                    return Err(FsError::Unsupported);
                }
                let count = match self.state.named_attr_count(object).await {
                    Some(count) => count,
                    None => {
                        let count = self.xattr_count(ctx, *parent).await?;
                        self.state
                            .set_named_attr_count(object, ServerFileType::NamedAttrDir, count)
                            .await;
                        count
                    }
                };
                let meta = self
                    .state
                    .ensure_meta(object, ServerFileType::NamedAttrDir)
                    .await;
                Ok(Self::attr_from_meta(
                    meta,
                    ServerFileType::NamedAttrDir,
                    count,
                    false,
                ))
            }
            ServerObject::NamedAttrFile { parent, name } => {
                let parent_handle = self.resolve_backend_handle(*parent).await?;
                let named = self.named_attrs().ok_or(FsError::Unsupported)?;
                let value = named.get_xattr(ctx, &parent_handle, name).await?;
                let meta = self
                    .state
                    .ensure_meta(object, ServerFileType::NamedAttr)
                    .await;
                Ok(Self::attr_from_meta(
                    meta,
                    ServerFileType::NamedAttr,
                    value.len() as u64,
                    false,
                ))
            }
        }
    }

    async fn xattr_count(&self, ctx: &RequestContext, parent: ObjectId) -> NfsResult<u64> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        Ok(named.list_xattrs(ctx, &parent_handle).await?.len() as u64)
    }

    async fn resolve_object(
        &self,
        fh: &Option<NfsFh4>,
    ) -> Result<(NfsFh4, ServerObject), NfsStat4> {
        let fh = fh.clone().ok_or(NfsStat4::Nofilehandle)?;
        let object = self.state.fh_to_object(&fh).await.ok_or(NfsStat4::Stale)?;
        Ok((fh, object))
    }

    async fn parent_change_after_xattr_mutation(&self, ctx: &RequestContext, parent: ObjectId) {
        let _ = self
            .getattr(ctx, parent)
            .await
            .expect("named-attribute parent disappeared before metadata refresh");
    }

    fn create_mode_requires_nonexistence(how: &Createhow4) -> bool {
        matches!(
            how,
            Createhow4::Guarded(_) | Createhow4::Exclusive(_) | Createhow4::Exclusive4_1 { .. }
        )
    }

    fn open_set_mode(how: &Createhow4) -> XattrSetMode {
        match how {
            Createhow4::Unchecked(_) => XattrSetMode::CreateOrReplace,
            Createhow4::Guarded(_) | Createhow4::Exclusive(_) | Createhow4::Exclusive4_1 { .. } => {
                XattrSetMode::CreateOnly
            }
        }
    }

    async fn xattr_read_slice(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        offset: u64,
        count: u32,
    ) -> NfsResult<(Bytes, bool)> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let value = named.get_xattr(ctx, &parent_handle, name).await?;
        let offset = offset as usize;
        if offset >= value.len() {
            return Ok((Bytes::new(), true));
        }
        let end = (offset + count as usize).min(value.len());
        Ok((value.slice(offset..end), end == value.len()))
    }

    async fn xattr_resize(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        size: u64,
    ) -> NfsResult<()> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let mut value = named.get_xattr(ctx, &parent_handle, name).await?.to_vec();
        value.resize(size as usize, 0);
        named
            .set_xattr(
                ctx,
                &parent_handle,
                name,
                Bytes::from(value),
                XattrSetMode::CreateOrReplace,
            )
            .await
    }

    async fn xattr_write(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
        name: &str,
        offset: u64,
        data: &[u8],
    ) -> NfsResult<u32> {
        let parent_handle = self.resolve_backend_handle(parent).await?;
        let named = self.named_attrs().ok_or(FsError::Unsupported)?;
        let mut value = named.get_xattr(ctx, &parent_handle, name).await?.to_vec();
        let offset = offset as usize;
        let end = offset + data.len();
        if end > value.len() {
            value.resize(end, 0);
        }
        value[offset..end].copy_from_slice(data);
        named
            .set_xattr(
                ctx,
                &parent_handle,
                name,
                Bytes::from(value),
                XattrSetMode::CreateOrReplace,
            )
            .await?;
        Ok(data.len() as u32)
    }

    async fn refresh_xattr_summary(
        &self,
        ctx: &RequestContext,
        parent: ObjectId,
    ) -> NfsResult<u64> {
        let count = self.xattr_count(ctx, parent).await?;
        self.state
            .set_named_attr_count(
                &ServerObject::NamedAttrDir(parent),
                ServerFileType::NamedAttrDir,
                count,
            )
            .await;
        Ok(count)
    }

    fn synthetic_change_info(before: u64) -> ChangeInfo4 {
        ChangeInfo4 {
            atomic: false,
            before,
            after: before.wrapping_add(1),
        }
    }

    async fn mutation_change_info(
        &self,
        ctx: &RequestContext,
        object: &ServerObject,
        before: u64,
    ) -> ChangeInfo4 {
        match self.build_attr(ctx, object).await {
            Ok(attr) => ChangeInfo4 {
                atomic: true,
                before,
                after: attr.change_id,
            },
            Err(_) => Self::synthetic_change_info(before),
        }
    }

    // ===== Individual operation handlers =====

    async fn op_access(
        &self,
        request_ctx: &RequestContext,
        args: &AccessArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Access(status, 0, 0),
        };

        match self.build_attr(request_ctx, &object).await {
            Ok(attr) => {
                let mut server_supported = ACCESS4_READ
                    | ACCESS4_LOOKUP
                    | ACCESS4_MODIFY
                    | ACCESS4_EXTEND
                    | ACCESS4_DELETE
                    | ACCESS4_EXECUTE;
                if matches!(
                    attr.file_type,
                    ServerFileType::Directory | ServerFileType::NamedAttrDir
                ) {
                    server_supported &= !ACCESS4_EXECUTE;
                }
                let requested = Self::nfs_access_mask(args.access & server_supported);
                let granted = match object {
                    ServerObject::Fs(id) => match self.access_for(request_ctx, id, requested).await
                    {
                        Ok(mask) => mask,
                        Err(e) => return NfsResop4::Access(e.to_nfsstat4(), 0, 0),
                    },
                    _ => requested,
                };
                let supported = args.access & server_supported;
                NfsResop4::Access(
                    NfsStat4::Ok,
                    supported,
                    Self::access_bits(granted) & supported,
                )
            }
            Err(e) => NfsResop4::Access(e.to_nfsstat4(), 0, 0),
        }
    }

    async fn op_close(&self, args: &CloseArgs4) -> NfsResop4 {
        match self.state.close_state(&args.open_stateid).await {
            Ok(stateid) => NfsResop4::Close(NfsStat4::Ok, stateid),
            Err(status) => NfsResop4::Close(status, Stateid4::default()),
        }
    }

    async fn op_commit(
        &self,
        request_ctx: &RequestContext,
        _args: &CommitArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Commit(status, [0u8; 8]),
        };

        let status = match object {
            ServerObject::Fs(id) => {
                // RFC 8881's COMMIT error table allows NFS4ERR_ISDIR for directories.
                match self.getattr(request_ctx, id).await {
                    Ok(attrs) if attrs.object_type == ObjectType::Directory => {
                        return NfsResop4::Commit(NfsStat4::Isdir, [0u8; 8]);
                    }
                    Err(e) => return NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
                    _ => {}
                }
                if let Some(syncer) = self.syncer() {
                    let handle = match self.resolve_backend_handle(id).await {
                        Ok(handle) => handle,
                        Err(e) => return NfsResop4::Commit(e.to_nfsstat4(), [0u8; 8]),
                    };
                    syncer
                        .commit(request_ctx, &handle, _args.offset, _args.count)
                        .await
                        .map_err(|e| e.to_nfsstat4())
                } else {
                    Ok(())
                }
            }
            ServerObject::NamedAttrFile { .. } => Ok(()),
            ServerObject::NamedAttrDir(_) => Err(NfsStat4::Isdir),
        };

        match status {
            Ok(()) => NfsResop4::Commit(NfsStat4::Ok, self.state.write_verifier),
            Err(status) => NfsResop4::Commit(status, [0u8; 8]),
        }
    }

    async fn op_create(
        &self,
        request_ctx: &RequestContext,
        args: &CreateArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, dir_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let dir_id = match dir_object {
            ServerObject::Fs(id) => id,
            _ => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
        };

        match self.kind_of(request_ctx, dir_id).await {
            Ok(ObjectType::Directory) => {}
            Ok(_) => return NfsResop4::Create(NfsStat4::Notdir, None, Bitmap4::new()),
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        }
        let dir_attr_before = match self.build_attr(request_ctx, &dir_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
        };

        let set_attrs = match attrs::decode_setattr(&args.createattrs) {
            Ok(attrs) => attrs,
            Err(status) => return NfsResop4::Create(status, None, Bitmap4::new()),
        };

        let (new_object, _new_type) = match &args.objtype {
            Createtype4::Dir => match self
                .create_dir(request_ctx, dir_id, &args.objname, set_attrs.clone())
                .await
            {
                Ok(created) => (ServerObject::Fs(created.handle), ServerFileType::Directory),
                Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
            },
            Createtype4::Link(target) => {
                let symlinks = match self.symlinks() {
                    Some(s) => s,
                    None => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
                };
                let parent_handle = match self.resolve_backend_handle(dir_id).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
                };
                match symlinks
                    .create_symlink(
                        request_ctx,
                        &parent_handle,
                        &args.objname,
                        target,
                        &set_attrs,
                    )
                    .await
                {
                    Ok(created) => {
                        let object_id = self.register_handle(&created.handle).await;
                        (ServerObject::Fs(object_id), ServerFileType::Symlink)
                    }
                    Err(e) => return NfsResop4::Create(e.to_nfsstat4(), None, Bitmap4::new()),
                }
            }
            _ => return NfsResop4::Create(NfsStat4::Notsupp, None, Bitmap4::new()),
        };

        let new_fh = self.state.object_to_fh(&new_object).await;
        *current_fh = Some(new_fh);

        let cinfo = self
            .mutation_change_info(request_ctx, &dir_object, dir_attr_before.change_id)
            .await;
        NfsResop4::Create(NfsStat4::Ok, Some(cinfo), Bitmap4::new())
    }

    async fn op_getattr(
        &self,
        request_ctx: &RequestContext,
        args: &GetattrArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (fh, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Getattr(status, None),
        };

        match self.build_attr(request_ctx, &object).await {
            Ok(attr) => {
                match self
                    .encode_fattr(request_ctx, &attr, &args.attr_request, &fh)
                    .await
                {
                    Ok(fattr) => NfsResop4::Getattr(NfsStat4::Ok, Some(fattr)),
                    Err(e) => NfsResop4::Getattr(e.to_nfsstat4(), None),
                }
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
        request_ctx: &RequestContext,
        args: &LinkArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, source) = match self.resolve_object(saved_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Link(status, None),
        };
        let (_, target_dir) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Link(status, None),
        };

        let (source_id, dir_id) = match (source, target_dir.clone()) {
            (ServerObject::Fs(source_id), ServerObject::Fs(dir_id)) => (source_id, dir_id),
            _ => return NfsResop4::Link(NfsStat4::Notsupp, None),
        };

        match self.kind_of(request_ctx, dir_id).await {
            Ok(ObjectType::Directory) => {}
            Ok(_) => return NfsResop4::Link(NfsStat4::Notdir, None),
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        }
        let dir_attr_before = match self.build_attr(request_ctx, &target_dir).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };

        let links = match self.hard_links() {
            Some(links) => links,
            None => return NfsResop4::Link(NfsStat4::Notsupp, None),
        };
        let source_handle = match self.resolve_backend_handle(source_id).await {
            Ok(handle) => handle,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };
        let dir_handle = match self.resolve_backend_handle(dir_id).await {
            Ok(handle) => handle,
            Err(e) => return NfsResop4::Link(e.to_nfsstat4(), None),
        };
        match links
            .link(request_ctx, &source_handle, &dir_handle, &args.newname)
            .await
        {
            Ok(()) => {
                let cinfo = self
                    .mutation_change_info(request_ctx, &target_dir, dir_attr_before.change_id)
                    .await;
                NfsResop4::Link(NfsStat4::Ok, Some(cinfo))
            }
            Err(e) => NfsResop4::Link(e.to_nfsstat4(), None),
        }
    }

    async fn op_lookup(
        &self,
        request_ctx: &RequestContext,
        args: &LookupArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lookup(status),
        };

        let child = match object {
            ServerObject::Fs(dir_id) => match self.kind_of(request_ctx, dir_id).await {
                Ok(ObjectType::Directory) => {
                    match self.lookup(request_ctx, dir_id, &args.objname).await {
                        Ok(id) => Ok(ServerObject::Fs(id)),
                        Err(e) => Err(e),
                    }
                }
                Ok(_) => Err(FsError::NotDirectory),
                Err(e) => Err(e),
            },
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Lookup(NfsStat4::Notsupp),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Lookup(e.to_nfsstat4()),
                };
                match named
                    .get_xattr(request_ctx, &parent_handle, &args.objname)
                    .await
                {
                    Ok(_) => Ok(ServerObject::NamedAttrFile {
                        parent,
                        name: args.objname.clone(),
                    }),
                    Err(e) => Err(e),
                }
            }
            ServerObject::NamedAttrFile { .. } => Err(FsError::NotDirectory),
        };

        match child {
            Ok(child) => {
                *current_fh = Some(self.state.object_to_fh(&child).await);
                NfsResop4::Lookup(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookup(e.to_nfsstat4()),
        }
    }

    async fn op_lookupp(
        &self,
        request_ctx: &RequestContext,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lookupp(status),
        };

        let root_object = self.root_object().await;
        let parent = match object {
            ServerObject::Fs(id) if root_object == ServerObject::Fs(id) => Err(FsError::NotFound),
            ServerObject::Fs(id) => match self.lookup_parent(request_ctx, id).await {
                Ok(parent_id) => Ok(ServerObject::Fs(parent_id)),
                Err(e) => Err(e),
            },
            ServerObject::NamedAttrDir(parent) => Ok(ServerObject::Fs(parent)),
            ServerObject::NamedAttrFile { parent, .. } => Ok(ServerObject::NamedAttrDir(parent)),
        };

        match parent {
            Ok(parent) => {
                *current_fh = Some(self.state.object_to_fh(&parent).await);
                NfsResop4::Lookupp(NfsStat4::Ok)
            }
            Err(e) => NfsResop4::Lookupp(e.to_nfsstat4()),
        }
    }

    async fn op_secinfo_no_name(
        &self,
        request_ctx: &RequestContext,
        style: u32,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::SecInfoNoName(status, vec![]),
        };

        let style_status = match style {
            // SECINFO_STYLE4_CURRENT_FH
            0 => Ok(()),
            // SECINFO_STYLE4_PARENT
            1 => {
                let root_object = self.root_object().await;
                match object {
                    ServerObject::Fs(id) if root_object == ServerObject::Fs(id) => {
                        Err(NfsStat4::Noent)
                    }
                    ServerObject::Fs(id) => self
                        .lookup_parent(request_ctx, id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_nfsstat4()),
                    ServerObject::NamedAttrDir(_) | ServerObject::NamedAttrFile { .. } => Ok(()),
                }
            }
            _ => Err(NfsStat4::Inval),
        };

        match style_status {
            Ok(()) => {
                *current_fh = None;
                NfsResop4::SecInfoNoName(
                    NfsStat4::Ok,
                    vec![SecinfoEntry4 { flavor: 1 }, SecinfoEntry4 { flavor: 0 }],
                )
            }
            Err(status) => NfsResop4::SecInfoNoName(status, vec![]),
        }
    }

    async fn op_reclaim_complete(
        &self,
        args: &ReclaimCompleteArgs4,
        current_fh: &Option<NfsFh4>,
        sequence_clientid: Option<Clientid4>,
    ) -> NfsResop4 {
        let Some(clientid) = sequence_clientid else {
            return NfsResop4::ReclaimComplete(NfsStat4::OpNotInSession);
        };

        if args.one_fs {
            if current_fh.is_none() {
                return NfsResop4::ReclaimComplete(NfsStat4::Nofilehandle);
            }
            if let Err(status) = self.resolve_object(current_fh).await {
                return NfsResop4::ReclaimComplete(status);
            }
        }

        match self.state.reclaim_complete(clientid, args.one_fs).await {
            Ok(()) => NfsResop4::ReclaimComplete(NfsStat4::Ok),
            Err(status) => NfsResop4::ReclaimComplete(status),
        }
    }

    async fn op_open(
        &self,
        request_ctx: &RequestContext,
        args: &OpenArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, container) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Open(status, None),
        };
        let before_attr = self.build_attr(request_ctx, &container).await;

        let mut created = false;
        let mut created_before_change = None;
        let object = match (&container, &args.claim) {
            (ServerObject::Fs(dir_id), OpenClaim4::Null(name)) => {
                match self.kind_of(request_ctx, *dir_id).await {
                    Ok(ObjectType::Directory) => {}
                    Ok(_) => return NfsResop4::Open(NfsStat4::Notdir, None),
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }

                match self.lookup(request_ctx, *dir_id, name).await {
                    Ok(id) => {
                        if let Openflag4::Create(how) = &args.openhow
                            && Self::create_mode_requires_nonexistence(how)
                        {
                            return NfsResop4::Open(NfsStat4::Exist, None);
                        }
                        ServerObject::Fs(id)
                    }
                    Err(FsError::NotFound) => match &args.openhow {
                        Openflag4::Create(how) => {
                            let before_change = match &before_attr {
                                Ok(attr) => attr.change_id,
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            };
                            let set_attrs = match how {
                                Createhow4::Unchecked(fa) | Createhow4::Guarded(fa) => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive4_1 { attrs: fa, .. } => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive(_) => Default::default(),
                            };
                            match self
                                .create_file(request_ctx, *dir_id, name, set_attrs)
                                .await
                            {
                                Ok(created_file) => {
                                    created = true;
                                    created_before_change = Some(before_change);
                                    ServerObject::Fs(created_file.handle)
                                }
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            }
                        }
                        Openflag4::NoCreate => return NfsResop4::Open(NfsStat4::Noent, None),
                    },
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            (ServerObject::NamedAttrDir(parent), OpenClaim4::Null(name)) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Open(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(*parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                };
                match named.get_xattr(request_ctx, &parent_handle, name).await {
                    Ok(_) => {
                        if let Openflag4::Create(how) = &args.openhow
                            && Self::create_mode_requires_nonexistence(how)
                        {
                            return NfsResop4::Open(NfsStat4::Exist, None);
                        }
                        ServerObject::NamedAttrFile {
                            parent: *parent,
                            name: name.clone(),
                        }
                    }
                    Err(FsError::NotFound) => match &args.openhow {
                        Openflag4::Create(how) => {
                            let before_change = match &before_attr {
                                Ok(attr) => attr.change_id,
                                Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                            };
                            created = true;
                            created_before_change = Some(before_change);
                            let object = ServerObject::NamedAttrFile {
                                parent: *parent,
                                name: name.clone(),
                            };
                            let set_attrs = match how {
                                Createhow4::Unchecked(fa) | Createhow4::Guarded(fa) => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive4_1 { attrs: fa, .. } => {
                                    match attrs::decode_setattr(fa) {
                                        Ok(attrs) => attrs,
                                        Err(status) => return NfsResop4::Open(status, None),
                                    }
                                }
                                Createhow4::Exclusive(_) => Default::default(),
                            };
                            let mut initial = vec![];
                            if let Some(size) = set_attrs.size {
                                initial.resize(size as usize, 0);
                            }
                            if let Err(e) = named
                                .set_xattr(
                                    request_ctx,
                                    &parent_handle,
                                    name,
                                    Bytes::from(initial),
                                    Self::open_set_mode(how),
                                )
                                .await
                            {
                                return NfsResop4::Open(e.to_nfsstat4(), None);
                            }
                            if let Err(e) = self.refresh_xattr_summary(request_ctx, *parent).await {
                                warn!("xattr summary refresh failed: {e:?}");
                            }
                            self.state
                                .apply_setattr(&object, ServerFileType::NamedAttr, &set_attrs)
                                .await;
                            self.state
                                .touch_metadata(&container, ServerFileType::NamedAttrDir)
                                .await;
                            self.parent_change_after_xattr_mutation(request_ctx, *parent)
                                .await;
                            object
                        }
                        Openflag4::NoCreate => return NfsResop4::Open(NfsStat4::Noent, None),
                    },
                    Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
                }
            }
            (_, OpenClaim4::Fh)
            | (_, OpenClaim4::Previous(_))
            | (_, OpenClaim4::DelegCurFh(_))
            | (_, OpenClaim4::DelegPrevFh) => container.clone(),
            _ => return NfsResop4::Open(NfsStat4::Notsupp, None),
        };

        let opened_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Open(e.to_nfsstat4(), None),
        };
        if matches!(
            opened_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Open(NfsStat4::Isdir, None);
        }

        if !created && let Err(e) = &before_attr {
            return NfsResop4::Open(e.to_nfsstat4(), None);
        }

        let stateid = match self
            .state
            .create_open_state(
                object.clone(),
                args.owner.clientid,
                args.share_access,
                args.share_deny,
            )
            .await
        {
            Ok(stateid) => stateid,
            Err(status) => return NfsResop4::Open(status, None),
        };

        *current_fh = Some(self.state.object_to_fh(&object).await);

        let cinfo = if created {
            // The create path records the pre-mutation directory change id before
            // issuing the mutation, so it must be present here.
            let before_change =
                created_before_change.expect("created OPEN missing pre-mutation change info");
            self.mutation_change_info(request_ctx, &container, before_change)
                .await
        } else {
            // Non-creating OPENs require pre-operation directory attrs so the unchanged
            // change_info4 can be reported without sentinel values.
            let change = before_attr
                .as_ref()
                .expect("non-creating OPEN missing directory attrs")
                .change_id;
            ChangeInfo4 {
                atomic: true,
                before: change,
                after: change,
            }
        };

        NfsResop4::Open(
            NfsStat4::Ok,
            Some(OpenRes4 {
                stateid,
                cinfo,
                rflags: OPEN4_RESULT_LOCKTYPE_POSIX,
                attrset: Bitmap4::new(),
                delegation: OpenDelegation4::None,
            }),
        )
    }

    async fn op_read(
        &self,
        request_ctx: &RequestContext,
        args: &ReadArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Read(status, None),
        };

        let result = match object {
            ServerObject::Fs(id) => {
                // RFC 8881 §18.22.3: READ on a directory must return NFS4ERR_ISDIR.
                match self.getattr(request_ctx, id).await {
                    Ok(attrs) if attrs.object_type == ObjectType::Directory => {
                        return NfsResop4::Read(NfsStat4::Isdir, None);
                    }
                    Err(e) => return NfsResop4::Read(e.to_nfsstat4(), None),
                    _ => {}
                }
                self.read(request_ctx, id, args.offset, args.count).await
            }
            ServerObject::NamedAttrFile { parent, name } => {
                self.xattr_read_slice(request_ctx, parent, &name, args.offset, args.count)
                    .await
            }
            ServerObject::NamedAttrDir(_) => Err(FsError::IsDirectory),
        };

        match result {
            Ok((data, eof)) => NfsResop4::Read(
                NfsStat4::Ok,
                Some(ReadRes4 {
                    eof,
                    data: data.to_vec(),
                }),
            ),
            Err(e) => NfsResop4::Read(e.to_nfsstat4(), None),
        }
    }

    async fn op_readdir(
        &self,
        request_ctx: &RequestContext,
        args: &ReaddirArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Readdir(status, None),
        };

        let dir_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        if !matches!(
            dir_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Readdir(NfsStat4::Notdir, None);
        }
        let cookieverf = dir_attr.change_id.to_be_bytes();

        if args.cookie != 0 && args.cookieverf != cookieverf {
            return NfsResop4::Readdir(NfsStat4::NotSame, None);
        }

        let with_attrs = args.attr_request.0.iter().any(|word| *word != 0);
        let backend_max_entries = (args.maxcount / 128).max(1);
        let entries = match object.clone() {
            ServerObject::Fs(dir_id) => match self
                .readdir(
                    request_ctx,
                    dir_id,
                    args.cookie,
                    backend_max_entries,
                    with_attrs,
                )
                .await
            {
                Ok(page) => page
                    .entries
                    .into_iter()
                    .map(|entry| {
                        (
                            entry.name,
                            ServerObject::Fs(entry.handle),
                            entry.cookie,
                            entry.attrs,
                        )
                    })
                    .collect::<Vec<_>>(),
                Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
            },
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Readdir(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
                };
                let names = match named.list_xattrs(request_ctx, &parent_handle).await {
                    Ok(names) => names,
                    Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
                };
                let start = if args.cookie == 0 {
                    0
                } else {
                    args.cookie.saturating_sub(2) as usize
                };
                names
                    .into_iter()
                    .skip(start)
                    .map(|name| {
                        let object = ServerObject::NamedAttrFile {
                            parent,
                            name: name.clone(),
                        };
                        let cookie = start as u64 + 3;
                        (name, object, cookie, None)
                    })
                    .enumerate()
                    .map(|(idx, (name, object, base_cookie, attrs))| {
                        (name, object, base_cookie + idx as u64, attrs)
                    })
                    .collect::<Vec<_>>()
            }
            ServerObject::NamedAttrFile { .. } => {
                return NfsResop4::Readdir(NfsStat4::Notdir, None);
            }
        };

        let maxcount_limit = args.maxcount as usize;
        let dircount_limit = if args.dircount == 0 {
            usize::MAX
        } else {
            args.dircount as usize
        };

        let base_resok_len = readdir_resok_len(&[], false);
        if base_resok_len > maxcount_limit {
            return NfsResop4::Readdir(NfsStat4::Toosmall, None);
        }

        let stats = match self.statfs(request_ctx).await {
            Ok(stats) => stats,
            Err(e) => return NfsResop4::Readdir(e.to_nfsstat4(), None),
        };
        let limits = self.limits();
        let caps = self.capabilities();
        let encode_ctx = attrs::AttrEncodingContext {
            limits: &limits,
            stats: &stats,
            capabilities: &caps,
        };

        let mut result_entries = Vec::with_capacity(entries.len().min(64));
        let mut dir_bytes = 0usize;
        let mut total_resok_bytes = base_resok_len;

        for (name, object, cookie, inline_attrs) in &entries {
            let entry_attr = match inline_attrs.clone() {
                Some(attrs) => self.attr_from_backend(attrs),
                None => match self.build_attr(request_ctx, object).await {
                    Ok(attr) => attr,
                    Err(e) => {
                        trace!("readdir: skipping entry {name:?}: {e:?}");
                        continue;
                    }
                },
            };
            let entry_fh = self.state.object_to_fh(object).await;
            let result_entry = Entry4 {
                cookie: *cookie,
                name: name.clone(),
                attrs: attrs::encode_fattr4(
                    &entry_attr,
                    &args.attr_request,
                    &entry_fh,
                    &encode_ctx,
                ),
            };
            let dir_entry_size = readdir_dir_info_len(&result_entry);
            let entry_total = readdir_entry_list_item_len(&result_entry);

            let exceeds_dircount = dir_bytes + dir_entry_size > dircount_limit;
            let exceeds_maxcount = total_resok_bytes + entry_total > maxcount_limit;
            if !result_entries.is_empty() && (exceeds_dircount || exceeds_maxcount) {
                break;
            }

            if result_entries.is_empty() && exceeds_maxcount {
                return NfsResop4::Readdir(NfsStat4::Toosmall, None);
            }

            dir_bytes += dir_entry_size;
            total_resok_bytes += entry_total;
            result_entries.push(result_entry);
        }

        let eof = result_entries.len() == entries.len();
        NfsResop4::Readdir(
            NfsStat4::Ok,
            Some(ReaddirRes4 {
                cookieverf,
                entries: result_entries,
                eof,
            }),
        )
    }

    async fn op_readlink(
        &self,
        request_ctx: &RequestContext,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Readlink(status, None),
        };

        let result = match object {
            ServerObject::Fs(id) => match self.symlinks() {
                Some(symlinks) => {
                    let handle = match self.resolve_backend_handle(id).await {
                        Ok(handle) => handle,
                        Err(e) => return NfsResop4::Readlink(e.to_nfsstat4(), None),
                    };
                    symlinks.readlink(request_ctx, &handle).await
                }
                None => Err(FsError::Unsupported),
            },
            _ => Err(FsError::InvalidInput),
        };

        match result {
            Ok(target) => NfsResop4::Readlink(NfsStat4::Ok, Some(target)),
            Err(e) => NfsResop4::Readlink(e.to_nfsstat4(), None),
        }
    }

    async fn op_remove(
        &self,
        request_ctx: &RequestContext,
        args: &RemoveArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, dir_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Remove(status, None),
        };

        let dir_attr_before = match self.build_attr(request_ctx, &dir_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
        };

        let status = match dir_object.clone() {
            ServerObject::Fs(dir_id) => {
                match self.remove(request_ctx, dir_id, &args.target).await {
                    Ok(()) => NfsStat4::Ok,
                    Err(e) => e.to_nfsstat4(),
                }
            }
            ServerObject::NamedAttrDir(parent) => {
                let named = match self.named_attrs() {
                    Some(named) => named,
                    None => return NfsResop4::Remove(NfsStat4::Notsupp, None),
                };
                let parent_handle = match self.resolve_backend_handle(parent).await {
                    Ok(handle) => handle,
                    Err(e) => return NfsResop4::Remove(e.to_nfsstat4(), None),
                };
                match named
                    .remove_xattr(request_ctx, &parent_handle, &args.target)
                    .await
                {
                    Ok(()) => {
                        if let Err(e) = self.refresh_xattr_summary(request_ctx, parent).await {
                            warn!("xattr summary refresh failed: {e:?}");
                        }
                        self.state
                            .touch_metadata(&dir_object, ServerFileType::NamedAttrDir)
                            .await;
                        self.parent_change_after_xattr_mutation(request_ctx, parent)
                            .await;
                        NfsStat4::Ok
                    }
                    Err(e) => e.to_nfsstat4(),
                }
            }
            ServerObject::NamedAttrFile { .. } => NfsStat4::Notdir,
        };

        if status == NfsStat4::Ok {
            let cinfo = self
                .mutation_change_info(request_ctx, &dir_object, dir_attr_before.change_id)
                .await;
            NfsResop4::Remove(NfsStat4::Ok, Some(cinfo))
        } else {
            NfsResop4::Remove(status, None)
        }
    }

    async fn op_rename(
        &self,
        request_ctx: &RequestContext,
        args: &RenameArgs4,
        current_fh: &Option<NfsFh4>,
        saved_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, src_object) = match self.resolve_object(saved_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };
        let (_, tgt_object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Rename(status, None, None),
        };

        let (src_dir_id, tgt_dir_id) = match (src_object.clone(), tgt_object.clone()) {
            (ServerObject::Fs(src_dir_id), ServerObject::Fs(tgt_dir_id)) => {
                (src_dir_id, tgt_dir_id)
            }
            _ => return NfsResop4::Rename(NfsStat4::Notsupp, None, None),
        };

        let src_before = match self.build_attr(request_ctx, &src_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };
        let tgt_before = match self.build_attr(request_ctx, &tgt_object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Rename(e.to_nfsstat4(), None, None),
        };

        match self
            .rename(
                request_ctx,
                src_dir_id,
                &args.oldname,
                tgt_dir_id,
                &args.newname,
            )
            .await
        {
            Ok(()) => {
                let src_cinfo = self
                    .mutation_change_info(request_ctx, &src_object, src_before.change_id)
                    .await;
                let tgt_cinfo = self
                    .mutation_change_info(request_ctx, &tgt_object, tgt_before.change_id)
                    .await;
                NfsResop4::Rename(NfsStat4::Ok, Some(src_cinfo), Some(tgt_cinfo))
            }
            Err(e) => NfsResop4::Rename(e.to_nfsstat4(), None, None),
        }
    }

    async fn op_setattr(
        &self,
        request_ctx: &RequestContext,
        args: &SetattrArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        let set_attrs = match attrs::decode_setattr(&args.obj_attributes) {
            Ok(attrs) => attrs,
            Err(status) => return NfsResop4::Setattr(status, Bitmap4::new()),
        };

        let status = match object.clone() {
            ServerObject::Fs(id) => match self.setattr_real(request_ctx, id, &set_attrs).await {
                Ok(_) => NfsStat4::Ok,
                Err(e) => e.to_nfsstat4(),
            },
            ServerObject::NamedAttrFile { parent, name } => {
                if let Some(size) = set_attrs.size
                    && let Err(e) = self.xattr_resize(request_ctx, parent, &name, size).await
                {
                    return NfsResop4::Setattr(e.to_nfsstat4(), Bitmap4::new());
                }
                self.state
                    .apply_setattr(&object, ServerFileType::NamedAttr, &set_attrs)
                    .await;
                if set_attrs.size.is_some() {
                    self.state
                        .touch_data(&object, ServerFileType::NamedAttr)
                        .await;
                }
                NfsStat4::Ok
            }
            ServerObject::NamedAttrDir(_) => {
                if set_attrs.size.is_some() {
                    NfsStat4::Isdir
                } else {
                    self.state
                        .apply_setattr(&object, ServerFileType::NamedAttrDir, &set_attrs)
                        .await;
                    NfsStat4::Ok
                }
            }
        };

        if status == NfsStat4::Ok {
            NfsResop4::Setattr(NfsStat4::Ok, args.obj_attributes.attrmask.clone())
        } else {
            NfsResop4::Setattr(status, Bitmap4::new())
        }
    }

    async fn op_write(
        &self,
        request_ctx: &RequestContext,
        args: &WriteArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Write(status, None),
        };

        let file_type = match &object {
            ServerObject::Fs(id) => match self.getattr(request_ctx, *id).await {
                Ok(attrs) => {
                    let file_type = ServerFileType::from_attrs(&attrs);
                    if file_type == ServerFileType::Directory {
                        return NfsResop4::Write(NfsStat4::Isdir, None);
                    }
                    file_type
                }
                Err(e) => return NfsResop4::Write(e.to_nfsstat4(), None),
            },
            ServerObject::NamedAttrFile { .. } => ServerFileType::NamedAttr,
            ServerObject::NamedAttrDir(_) => return NfsResop4::Write(NfsStat4::Isdir, None),
        };

        let result = match object.clone() {
            ServerObject::Fs(id) => {
                self.write(
                    request_ctx,
                    id,
                    args.offset,
                    Bytes::copy_from_slice(&args.data),
                )
                .await
            }
            ServerObject::NamedAttrFile { parent, name } => self
                .xattr_write(request_ctx, parent, &name, args.offset, &args.data)
                .await
                .map(|written| WriteResult {
                    written,
                    stability: WriteStability::FileSync,
                }),
            ServerObject::NamedAttrDir(_) => Err(FsError::IsDirectory),
        };

        match result {
            Ok(result) => {
                if !matches!(object, ServerObject::Fs(_)) {
                    self.state.touch_data(&object, file_type).await;
                }
                NfsResop4::Write(
                    NfsStat4::Ok,
                    Some(WriteRes4 {
                        count: result.written,
                        committed: Self::committed_how(result.stability),
                        writeverf: self.state.write_verifier,
                    }),
                )
            }
            Err(e) => NfsResop4::Write(e.to_nfsstat4(), None),
        }
    }

    async fn op_lock(
        &self,
        request_ctx: &RequestContext,
        args: &LockArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lock(status, None, None),
        };

        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lock(e.to_nfsstat4(), None, None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lock(NfsStat4::Isdir, None, None);
        }

        match &args.locker {
            Locker4::NewLockOwner(new_owner) => {
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &new_owner.lock_owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        None,
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .create_lock_state(
                        &new_owner.open_stateid,
                        &new_owner.lock_owner,
                        object,
                        args.locktype,
                        args.offset,
                        args.length,
                    )
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
            Locker4::ExistingLockOwner(existing) => {
                let (lock_object, owner) =
                    match self.state.lock_state_info(&existing.lock_stateid).await {
                        Some(info) => info,
                        None => return NfsResop4::Lock(NfsStat4::BadStateid, None, None),
                    };
                if lock_object != object {
                    return NfsResop4::Lock(NfsStat4::BadStateid, None, None);
                }
                if let Some(denied) = self
                    .state
                    .find_lock_conflict(
                        &object,
                        &owner,
                        args.locktype,
                        args.offset,
                        args.length,
                        Some(&existing.lock_stateid),
                    )
                    .await
                {
                    return NfsResop4::Lock(NfsStat4::Denied, None, Some(denied));
                }
                match self
                    .state
                    .update_lock_state(
                        &existing.lock_stateid,
                        args.locktype,
                        args.offset,
                        args.length,
                    )
                    .await
                {
                    Ok(stateid) => NfsResop4::Lock(NfsStat4::Ok, Some(stateid), None),
                    Err(status) => NfsResop4::Lock(status, None, None),
                }
            }
        }
    }

    async fn op_lockt(
        &self,
        request_ctx: &RequestContext,
        args: &LocktArgs4,
        current_fh: &Option<NfsFh4>,
    ) -> NfsResop4 {
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::Lockt(status, None),
        };
        let object_attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return NfsResop4::Lockt(e.to_nfsstat4(), None),
        };
        if matches!(
            object_attr.file_type,
            ServerFileType::Directory | ServerFileType::NamedAttrDir
        ) {
            return NfsResop4::Lockt(NfsStat4::Isdir, None);
        }
        match self
            .state
            .find_lock_conflict(
                &object,
                &args.owner,
                args.locktype,
                args.offset,
                args.length,
                None,
            )
            .await
        {
            Some(denied) => NfsResop4::Lockt(NfsStat4::Denied, Some(denied)),
            None => NfsResop4::Lockt(NfsStat4::Ok, None),
        }
    }

    async fn op_locku(&self, args: &LockuArgs4) -> NfsResop4 {
        match self
            .state
            .unlock_state(&args.lock_stateid, args.offset, args.length)
            .await
        {
            Ok(stateid) => NfsResop4::Locku(NfsStat4::Ok, Some(stateid)),
            Err(status) => NfsResop4::Locku(status, None),
        }
    }

    async fn op_openattr(
        &self,
        _request_ctx: &RequestContext,
        _args: &OpenAttrArgs4,
        current_fh: &mut Option<NfsFh4>,
    ) -> NfsResop4 {
        if self.named_attrs().is_none() {
            return NfsResop4::OpenAttr(NfsStat4::Notsupp);
        }
        let (_, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return NfsResop4::OpenAttr(status),
        };
        let attrdir = match object {
            ServerObject::Fs(id) => ServerObject::NamedAttrDir(id),
            _ => return NfsResop4::OpenAttr(NfsStat4::Inval),
        };
        self.state
            .ensure_meta(&attrdir, ServerFileType::NamedAttrDir)
            .await;
        *current_fh = Some(self.state.object_to_fh(&attrdir).await);
        NfsResop4::OpenAttr(NfsStat4::Ok)
    }

    /// Handle VERIFY (negate=false) and NVERIFY (negate=true).
    async fn op_verify(
        &self,
        request_ctx: &RequestContext,
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

        let (fh, object) = match self.resolve_object(current_fh).await {
            Ok(resolved) => resolved,
            Err(status) => return make_res(status),
        };

        let attr = match self.build_attr(request_ctx, &object).await {
            Ok(attr) => attr,
            Err(e) => return make_res(e.to_nfsstat4()),
        };

        let server_fattr = match self
            .encode_fattr(request_ctx, &attr, &client_fattr.attrmask, &fh)
            .await
        {
            Ok(fattr) => fattr,
            Err(e) => return make_res(e.to_nfsstat4()),
        };

        let attrs_match = server_fattr.attrmask == client_fattr.attrmask
            && server_fattr.attr_vals == client_fattr.attr_vals;

        if negate {
            if attrs_match {
                make_res(NfsStat4::Same)
            } else {
                make_res(NfsStat4::Ok)
            }
        } else if attrs_match {
            make_res(NfsStat4::Ok)
        } else {
            make_res(NfsStat4::NotSame)
        }
    }
}

fn xdr_opaque_len(len: usize) -> usize {
    4 + len + xdr_pad(len)
}

fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn replay_fingerprint(cred: &OpaqueAuth, payload: &Bytes) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(8 + cred.body.len() + payload.len());
    cred.flavor.encode(&mut out);
    encode_opaque(&mut out, &cred.body);
    out.extend_from_slice(payload);
    out.to_vec()
}

fn sequence_error_compound(tag: &str, status: NfsStat4) -> Compound4Res {
    Compound4Res {
        status,
        tag: tag.to_string(),
        resarray: vec![NfsResop4::Sequence(status, None)],
    }
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
    8 + entries
        .iter()
        .map(readdir_entry_list_item_len)
        .sum::<usize>()
        + 4
        + 4
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
        assert_eq!(
            readdir_dir_info_len(&entry),
            8 + xdr_opaque_len(entry.name.len())
        );
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
        assert_eq!(
            readdir_resok_len(&expected_entries, true),
            encoded.len() - 8
        );
    }

    #[test]
    fn test_synthetic_change_info_marks_response_non_atomic() {
        let cinfo = NfsServer::<crate::memfs::MemFs>::synthetic_change_info(41);
        assert!(!cinfo.atomic);
        assert_eq!(cinfo.before, 41);
        assert_eq!(cinfo.after, 42);
    }
}

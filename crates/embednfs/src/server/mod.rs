//! NFSv4.1 server implementation.

mod compound;
mod handles;
mod ops;
mod staging;
mod util;

#[cfg(test)]
mod tests;

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

use embednfs_proto::xdr::{XdrDecode, XdrEncode};
use embednfs_proto::*;

use crate::fs::FileSystem;
use crate::session::StateManager;

use self::util::hex_bytes;

/// The NFS server.
pub struct NfsServer<F: FileSystem> {
    fs: Arc<F>,
    state: Arc<StateManager>,
    handles: Arc<StdMutex<handles::HandleRegistry>>,
    staging: Arc<Mutex<HashMap<String, StagedFile>>>,
    next_stage_id: AtomicU64,
    stage_root: PathBuf,
}

#[derive(Debug, Clone)]
struct StagedFile {
    local_path: PathBuf,
    dirty: bool,
}

impl<F: FileSystem> NfsServer<F> {
    /// Create a new NFS server with the given filesystem.
    pub fn new(fs: F) -> Self {
        NfsServer {
            fs: Arc::new(fs),
            state: Arc::new(StateManager::new()),
            handles: Arc::new(StdMutex::new(handles::HandleRegistry::new())),
            staging: Arc::new(Mutex::new(HashMap::new())),
            next_stage_id: AtomicU64::new(1),
            stage_root: std::env::temp_dir().join("embednfs-staging"),
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

        const MAX_FRAGMENT: usize = 2 * 1024 * 1024;
        const MAX_RECORD: usize = 4 * 1024 * 1024;

        loop {
            // Reassemble potentially multi-fragment RPC record (RFC 5531 §11).
            let mut record = BytesMut::new();
            loop {
                let mut header = [0u8; 4];
                match reader.read_exact(&mut header).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) => return Err(e),
                }

                let header_val = u32::from_be_bytes(header);
                let last_fragment = header_val & 0x8000_0000 != 0;
                let frag_len = (header_val & 0x7FFF_FFFF) as usize;

                if frag_len > MAX_FRAGMENT {
                    warn!("Fragment too large: {frag_len}");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("fragment too large: {frag_len}"),
                    ));
                }
                if record.len() + frag_len > MAX_RECORD {
                    warn!("Reassembled record too large");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "reassembled record too large",
                    ));
                }

                let start = record.len();
                record.resize(start + frag_len, 0);
                reader.read_exact(&mut record[start..]).await?;

                if last_fragment {
                    break;
                }
            }

            let Some(response) = self.process_rpc_message(&record).await else {
                return Ok(());
            };
            let resp_len = (response.len() as u32) | 0x8000_0000;
            writer.write_all(&resp_len.to_be_bytes()).await?;
            writer.write_all(&response).await?;
            writer.flush().await?;
        }
    }

    async fn process_rpc_message(&self, data: &[u8]) -> Option<Bytes> {
        trace!("RPC request bytes={} hex={}", data.len(), hex_bytes(data));
        let mut src = Bytes::copy_from_slice(data);

        let call = match RpcCallHeader::decode(&mut src) {
            Ok(call) => call,
            Err(e) => {
                warn!("Failed to decode RPC header: {e}");
                return None;
            }
        };

        let mut response = BytesMut::with_capacity(8192);

        if call.rpcvers != RPC_VERSION {
            encode_rpc_reply_rpc_mismatch(&mut response, call.xid, RPC_VERSION, RPC_VERSION);
            return Some(response.freeze());
        }

        if call.prog != NFS_PROGRAM {
            encode_rpc_reply_prog_unavail(&mut response, call.xid);
            return Some(response.freeze());
        }

        if call.vers != NFS_V4 {
            encode_rpc_reply_prog_mismatch(&mut response, call.xid, NFS_V4, NFS_V4);
            return Some(response.freeze());
        }

        match call.proc_num {
            0 => {
                encode_rpc_reply_accepted(&mut response, call.xid);
            }
            1 => match Compound4Args::decode(&mut src) {
                Ok(args) => {
                    use crate::server::compound::CompoundResult;
                    match self.handle_compound(args).await {
                        CompoundResult::Fresh {
                            result,
                            cache_slot,
                        } => {
                            let mut compound_buf = BytesMut::new();
                            result.encode(&mut compound_buf);
                            if let Some((sessionid, slotid)) = cache_slot {
                                self.state
                                    .cache_slot_reply(
                                        &sessionid,
                                        slotid,
                                        compound_buf.to_vec(),
                                    )
                                    .await;
                            }
                            encode_rpc_reply_accepted(&mut response, call.xid);
                            response.extend_from_slice(&compound_buf);
                        }
                        CompoundResult::CachedReply(cached) => {
                            encode_rpc_reply_accepted(&mut response, call.xid);
                            response.extend_from_slice(&cached);
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
            },
            _ => {
                encode_rpc_reply_proc_unavail(&mut response, call.xid);
            }
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
}

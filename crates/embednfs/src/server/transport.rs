use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tracing::{trace, warn};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

use crate::fs::FileSystem;
use crate::session::SequenceReplay;

use super::compound::sequence_error_compound;
use super::{
    CONN_BUF_SIZE, Compound4Res, MAX_FRAGMENT_SIZE, NfsServer, RPC_FRAG_LEN_MASK,
    RPC_LAST_FRAGMENT, hex_bytes, replay_fingerprint,
};

#[expect(
    clippy::indexing_slicing,
    reason = "body_start is captured from the pre-encode length and response only grows afterward"
)]
fn replay_cache_body(response: &BytesMut, body_start: usize) -> Vec<u8> {
    response[body_start..].to_vec()
}

impl<F: FileSystem> NfsServer<F> {
    #[expect(
        clippy::indexing_slicing,
        reason = "fragment lengths and replay body offsets are validated before slicing"
    )]
    #[expect(
        clippy::expect_used,
        reason = "an oversized single-fragment reply is an internal sizing bug"
    )]
    pub(super) async fn handle_connection(
        self: &std::sync::Arc<Self>,
        stream: TcpStream,
    ) -> std::io::Result<()> {
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
            let request_buf = &mut read_buf[..frag_len];
            let _ = reader.read_exact(request_buf).await?;

            let Some(response) = self
                .process_rpc_message(&read_buf[..frag_len], connection_id)
                .await
            else {
                return Ok(());
            };

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

    pub(super) async fn process_rpc_message(
        &self,
        data: &[u8],
        connection_id: u64,
    ) -> Option<Bytes> {
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

        if let Err(auth) = Self::validate_rpc_auth(&call) {
            encode_rpc_reply_auth_error(&mut response, call.xid, auth);
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
                        let mut sequence_clientid = None;
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
                                        SequenceReplay::Execute(res, token, clientid) => {
                                            replay_token = Some(token);
                                            sequence_clientid = Some(clientid);
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
                            .handle_compound(
                                args,
                                prepared_sequence,
                                sequence_clientid,
                                &request_ctx,
                                connection_id,
                            )
                            .await;
                        encode_rpc_reply_accepted(&mut response, call.xid);
                        let body_start = response.len();
                        result.encode(&mut response);
                        if let Some(token) = replay_token {
                            let body = replay_cache_body(&response, body_start);
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
}

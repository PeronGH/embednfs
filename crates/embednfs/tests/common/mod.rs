//! Shared test helpers for NFS integration tests.
#![allow(dead_code)]

mod encode;
mod parse;

pub use encode::*;
pub use parse::*;

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use embednfs_proto::xdr::*;
use embednfs_proto::*;
use embednfs::{FileSystem, MemFs, NfsServer};

// ── Server setup ─────────────────────────────────────────────────────────────

pub async fn start_server() -> u16 {
    start_server_with_fs(MemFs::new()).await
}

pub async fn start_server_with_fs(fs: MemFs) -> u16 {
    let server = NfsServer::new(fs);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

pub async fn populated_fs(names: &[&str]) -> MemFs {
    let fs = MemFs::new();
    for name in names {
        fs.create_file(&format!("/{name}")).await.unwrap();
    }
    fs
}

// ── RPC transport ────────────────────────────────────────────────────────────

pub async fn send_rpc(stream: &mut TcpStream, xid: u32, proc_num: u32, payload: &[u8]) -> Bytes {
    send_rpc_auth(stream, xid, proc_num, payload, false).await
}

pub async fn send_rpc_auth_sys(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
) -> Bytes {
    send_rpc_auth(stream, xid, proc_num, payload, true).await
}

pub async fn send_rpc_auth(
    stream: &mut TcpStream,
    xid: u32,
    proc_num: u32,
    payload: &[u8],
    auth_sys: bool,
) -> Bytes {
    let mut msg = BytesMut::with_capacity(256);
    xid.encode(&mut msg);
    0u32.encode(&mut msg); // CALL
    2u32.encode(&mut msg); // RPC version
    NFS_PROGRAM.encode(&mut msg);
    NFS_V4.encode(&mut msg);
    proc_num.encode(&mut msg);

    if auth_sys {
        1u32.encode(&mut msg); // flavor = AUTH_SYS
        let mut cred_body = BytesMut::new();
        0u32.encode(&mut cred_body); // stamp
        "localhost".to_string().encode(&mut cred_body); // machinename
        0u32.encode(&mut cred_body); // uid=0
        0u32.encode(&mut cred_body); // gid=0
        0u32.encode(&mut cred_body); // gids count=0
        encode_opaque(&mut msg, &cred_body);
    } else {
        0u32.encode(&mut msg); // cred flavor = AUTH_NONE
        0u32.encode(&mut msg); // cred len
    }
    0u32.encode(&mut msg); // verf flavor = AUTH_NONE
    0u32.encode(&mut msg); // verf len
    msg.put_slice(payload);

    let len = msg.len() as u32 | 0x8000_0000;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&msg).await.unwrap();
    stream.flush().await.unwrap();

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let resp_len = (u32::from_be_bytes(header) & 0x7fff_ffff) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    Bytes::from(resp)
}

// ── Session setup ────────────────────────────────────────────────────────────

pub async fn setup_session(stream: &mut TcpStream) -> [u8; 16] {
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exchange", &[&exchange_id_op]);
    let mut resp = send_rpc(stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_EXCHANGE_ID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (clientid, sequenceid) = skip_exchange_id_res(&mut resp);

    let create_session_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("create-session", &[&create_session_op]);
    let mut resp = send_rpc(stream, 2, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE_SESSION);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let session_data = decode_fixed_opaque(&mut resp, 16).unwrap();
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&session_data);
    sessionid
}

//! Integration tests that start the NFS server and test it using raw RPC.
#![allow(dead_code)]

use bytes::{BufMut, BytesMut, Bytes};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

use nfs4_proto::*;
use nfs4_proto::xdr::*;
use nfs4_server::{NfsServer, MemFs};

async fn start_server() -> u16 {
    let fs = MemFs::new();
    let server = NfsServer::new(fs);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn send_rpc(stream: &mut TcpStream, xid: u32, proc_num: u32, payload: &[u8]) -> Bytes {
    let mut msg = BytesMut::with_capacity(256);
    // RPC call header
    xid.encode(&mut msg);
    0u32.encode(&mut msg); // CALL
    2u32.encode(&mut msg); // RPC version
    NFS_PROGRAM.encode(&mut msg); // program
    NFS_V4.encode(&mut msg); // version
    proc_num.encode(&mut msg); // procedure
    // cred: AUTH_NONE
    0u32.encode(&mut msg); // flavor
    0u32.encode(&mut msg); // body length
    // verf: AUTH_NONE
    0u32.encode(&mut msg); // flavor
    0u32.encode(&mut msg); // body length
    // payload
    msg.put_slice(payload);

    // Send with record marking
    let len = msg.len() as u32 | 0x80000000;
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&msg).await.unwrap();
    stream.flush().await.unwrap();

    // Read response
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let resp_len = (u32::from_be_bytes(header) & 0x7FFFFFFF) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    Bytes::from(resp)
}

fn encode_compound(tag: &str, ops: &[&[u8]]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);
    tag.to_string().encode(&mut buf);
    1u32.encode(&mut buf); // minorversion = 1
    (ops.len() as u32).encode(&mut buf);
    for op in ops {
        buf.put_slice(op);
    }
    buf.to_vec()
}

fn encode_exchange_id() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    // client_owner: verifier + ownerid
    buf.put_slice(&[0u8; 8]); // verifier (fixed 8 bytes)
    let ownerid = b"test-client";
    encode_opaque(&mut buf, ownerid);
    // flags
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    // state_protect: SP4_NONE
    0u32.encode(&mut buf);
    // client_impl_id (empty array)
    0u32.encode(&mut buf);
    buf.to_vec()
}

fn encode_create_session(clientid: u64, seq: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE_SESSION.encode(&mut buf);
    clientid.encode(&mut buf);
    seq.encode(&mut buf);
    0u32.encode(&mut buf); // flags
    // fore_chan_attrs
    0u32.encode(&mut buf); // headerpadsize
    1048576u32.encode(&mut buf); // maxrequestsize
    1048576u32.encode(&mut buf); // maxresponsesize
    8192u32.encode(&mut buf); // maxresponsesize_cached
    16u32.encode(&mut buf); // maxoperations
    8u32.encode(&mut buf); // maxrequests
    0u32.encode(&mut buf); // rdma_ird count
    // back_chan_attrs
    0u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    0u32.encode(&mut buf);
    2u32.encode(&mut buf);
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);
    // cb_program
    0u32.encode(&mut buf);
    // sec_parms
    1u32.encode(&mut buf); // count = 1
    0u32.encode(&mut buf); // AUTH_NONE
    buf.to_vec()
}

fn encode_sequence(sessionid: &[u8; 16], seq: u32, slot: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SEQUENCE.encode(&mut buf);
    buf.put_slice(sessionid);
    seq.encode(&mut buf);
    slot.encode(&mut buf);
    slot.encode(&mut buf); // highest_slotid
    false.encode(&mut buf); // cachethis
    buf.to_vec()
}

fn encode_putrootfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTROOTFH.encode(&mut buf);
    buf.to_vec()
}

fn encode_getfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_GETFH.encode(&mut buf);
    buf.to_vec()
}

fn encode_getattr(bits: &[u32]) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    for b in bits {
        bitmap.set(*b);
    }
    let mut buf = BytesMut::new();
    OP_GETATTR.encode(&mut buf);
    bitmap.encode(&mut buf);
    buf.to_vec()
}

fn encode_lookup(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOOKUP.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

fn encode_readdir() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READDIR.encode(&mut buf);
    0u64.encode(&mut buf); // cookie
    buf.put_slice(&[0u8; 8]); // cookieverf (fixed 8 bytes)
    8192u32.encode(&mut buf); // dircount
    32768u32.encode(&mut buf); // maxcount
    // attr_request: just FILEID and TYPE
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_FILEID);
    bitmap.set(FATTR4_TYPE);
    bitmap.encode(&mut buf);
    buf.to_vec()
}

fn parse_rpc_reply(resp: &mut Bytes) -> (u32, u32) {
    let xid = u32::decode(resp).unwrap();
    let msg_type = u32::decode(resp).unwrap();
    assert_eq!(msg_type, 1); // REPLY
    let reply_stat = u32::decode(resp).unwrap();
    assert_eq!(reply_stat, 0); // ACCEPTED
    // verifier
    let _verf = OpaqueAuth::decode(resp).unwrap();
    let accept_stat = u32::decode(resp).unwrap();
    (xid, accept_stat)
}

#[tokio::test]
async fn test_null_procedure() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    let mut resp = send_rpc(&mut stream, 1, 0, &[]).await;
    let (xid, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(xid, 1);
    assert_eq!(accept_stat, 0); // SUCCESS
}

#[tokio::test]
async fn test_exchange_id_and_create_session() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // EXCHANGE_ID
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("test", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    // Parse COMPOUND response
    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "COMPOUND status should be OK");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    assert_eq!(num_results, 1);

    // Parse EXCHANGE_ID result
    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_EXCHANGE_ID);
    let op_status = u32::decode(&mut resp).unwrap();
    assert_eq!(op_status, 0, "EXCHANGE_ID should succeed");

    let clientid = u64::decode(&mut resp).unwrap();
    let sequenceid = u32::decode(&mut resp).unwrap();
    assert!(clientid > 0);

    // Skip remaining EXCHANGE_ID fields
    let _flags = u32::decode(&mut resp).unwrap();
    let _sp_type = u32::decode(&mut resp).unwrap(); // state_protect
    // server_owner
    let _minor_id = u64::decode(&mut resp).unwrap();
    let _major_id = Vec::<u8>::decode(&mut resp).unwrap();
    let _scope = Vec::<u8>::decode(&mut resp).unwrap();
    let _impl_id_count = u32::decode(&mut resp).unwrap();

    // CREATE_SESSION
    let create_session_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("test", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "COMPOUND status should be OK");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    assert_eq!(num_results, 1);

    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_CREATE_SESSION);
    let op_status = u32::decode(&mut resp).unwrap();
    assert_eq!(op_status, 0, "CREATE_SESSION should succeed");

    // Read session ID (16 bytes fixed)
    let session_data = decode_fixed_opaque(&mut resp, 16).unwrap();
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&session_data);

    // Now do SEQUENCE + PUTROOTFH + GETATTR
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_TYPE, FATTR4_FILEID, FATTR4_MODE]);
    let compound = encode_compound("test", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "COMPOUND (SEQUENCE+PUTROOTFH+GETATTR) should be OK");
}

#[tokio::test]
async fn test_full_session_with_readdir() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // 1. EXCHANGE_ID
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0);
    let _tag = String::decode(&mut resp).unwrap();
    let _ = u32::decode(&mut resp).unwrap(); // num_results
    let _ = u32::decode(&mut resp).unwrap(); // opnum
    let _ = u32::decode(&mut resp).unwrap(); // status
    let clientid = u64::decode(&mut resp).unwrap();
    let sequenceid = u32::decode(&mut resp).unwrap();

    // 2. CREATE_SESSION
    let create_session_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let _ = u32::decode(&mut resp).unwrap();
    let _tag = String::decode(&mut resp).unwrap();
    let _ = u32::decode(&mut resp).unwrap();
    let _ = u32::decode(&mut resp).unwrap();
    let _ = u32::decode(&mut resp).unwrap();
    let session_data = decode_fixed_opaque(&mut resp, 16).unwrap();
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&session_data);

    // 3. SEQUENCE + PUTROOTFH + READDIR
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "COMPOUND (SEQUENCE+PUTROOTFH+READDIR) should be OK");
}

#[tokio::test]
async fn test_reclaim_complete() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Quick session setup
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    u32::decode(&mut resp).unwrap();
    String::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    let clientid = u64::decode(&mut resp).unwrap();
    let sequenceid = u32::decode(&mut resp).unwrap();

    let cs_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("", &[&cs_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    u32::decode(&mut resp).unwrap();
    String::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    u32::decode(&mut resp).unwrap();
    let session_data = decode_fixed_opaque(&mut resp, 16).unwrap();
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&session_data);

    // SEQUENCE + RECLAIM_COMPLETE
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let mut rc_buf = BytesMut::new();
    OP_RECLAIM_COMPLETE.encode(&mut rc_buf);
    false.encode(&mut rc_buf); // one_fs = false
    let rc_op = rc_buf.to_vec();
    let compound = encode_compound("", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "RECLAIM_COMPLETE should succeed");
}

//! Integration tests that start the NFS server and exercise raw RPC flows.
#![allow(dead_code)]

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use nfs4_proto::xdr::*;
use nfs4_proto::*;
use nfs4_server::{MemFs, NfsServer};

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
    xid.encode(&mut msg);
    0u32.encode(&mut msg); // CALL
    2u32.encode(&mut msg); // RPC version
    NFS_PROGRAM.encode(&mut msg);
    NFS_V4.encode(&mut msg);
    proc_num.encode(&mut msg);
    0u32.encode(&mut msg); // cred flavor = AUTH_NONE
    0u32.encode(&mut msg); // cred len
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

fn encode_compound_minor(tag: &str, minorversion: u32, ops: &[&[u8]]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);
    tag.to_string().encode(&mut buf);
    minorversion.encode(&mut buf);
    (ops.len() as u32).encode(&mut buf);
    for op in ops {
        buf.put_slice(op);
    }
    buf.to_vec()
}

fn encode_compound(tag: &str, ops: &[&[u8]]) -> Vec<u8> {
    encode_compound_minor(tag, 1, ops)
}

fn encode_exchange_id() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]); // verifier
    encode_opaque(&mut buf, b"test-client");
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    0u32.encode(&mut buf); // SP4_NONE
    0u32.encode(&mut buf); // client_impl_id = []
    buf.to_vec()
}

fn encode_create_session(clientid: u64, seq: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE_SESSION.encode(&mut buf);
    clientid.encode(&mut buf);
    seq.encode(&mut buf);
    0u32.encode(&mut buf); // flags

    0u32.encode(&mut buf); // fore headerpadsize
    1_048_576u32.encode(&mut buf); // fore maxrequestsize
    1_048_576u32.encode(&mut buf); // fore maxresponsesize
    8192u32.encode(&mut buf); // fore maxresponsesize_cached
    16u32.encode(&mut buf); // fore maxoperations
    8u32.encode(&mut buf); // fore maxrequests
    0u32.encode(&mut buf); // fore rdma_ird count

    0u32.encode(&mut buf); // back headerpadsize
    4096u32.encode(&mut buf); // back maxrequestsize
    4096u32.encode(&mut buf); // back maxresponsesize
    0u32.encode(&mut buf); // back maxresponsesize_cached
    2u32.encode(&mut buf); // back maxoperations
    1u32.encode(&mut buf); // back maxrequests
    0u32.encode(&mut buf); // back rdma_ird count

    0u32.encode(&mut buf); // cb_program
    1u32.encode(&mut buf); // sec_parms count
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

fn encode_getattr(bits: &[u32]) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    for bit in bits {
        bitmap.set(*bit);
    }

    let mut buf = BytesMut::new();
    OP_GETATTR.encode(&mut buf);
    bitmap.encode(&mut buf);
    buf.to_vec()
}

fn encode_readdir() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READDIR.encode(&mut buf);
    0u64.encode(&mut buf); // cookie
    buf.put_slice(&[0u8; 8]); // cookieverf
    8192u32.encode(&mut buf); // dircount
    32768u32.encode(&mut buf); // maxcount

    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_FILEID);
    bitmap.set(FATTR4_TYPE);
    bitmap.encode(&mut buf);
    buf.to_vec()
}

fn encode_open_confirm() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN_CONFIRM.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    buf.to_vec()
}

fn parse_rpc_reply(resp: &mut Bytes) -> (u32, u32) {
    let xid = u32::decode(resp).unwrap();
    let msg_type = u32::decode(resp).unwrap();
    assert_eq!(msg_type, 1, "expected RPC reply");
    let reply_stat = u32::decode(resp).unwrap();
    assert_eq!(reply_stat, 0, "expected accepted reply");
    let _verf = OpaqueAuth::decode(resp).unwrap();
    let accept_stat = u32::decode(resp).unwrap();
    (xid, accept_stat)
}

fn parse_compound_header(resp: &mut Bytes) -> (u32, String, u32) {
    let status = u32::decode(resp).unwrap();
    let tag = String::decode(resp).unwrap();
    let num_results = u32::decode(resp).unwrap();
    (status, tag, num_results)
}

fn parse_op_header(resp: &mut Bytes) -> (u32, u32) {
    let opnum = u32::decode(resp).unwrap();
    let status = u32::decode(resp).unwrap();
    (opnum, status)
}

fn skip_exchange_id_res(resp: &mut Bytes) -> (u64, u32) {
    let clientid = u64::decode(resp).unwrap();
    let sequenceid = u32::decode(resp).unwrap();
    let _flags = u32::decode(resp).unwrap();
    let _state_protect = u32::decode(resp).unwrap();
    let _server_minor_id = u64::decode(resp).unwrap();
    let _server_major_id = Vec::<u8>::decode(resp).unwrap();
    let _server_scope = Vec::<u8>::decode(resp).unwrap();
    let _impl_count = u32::decode(resp).unwrap();
    (clientid, sequenceid)
}

fn skip_sequence_res(resp: &mut Bytes) {
    let _sessionid = decode_fixed_opaque(resp, 16).unwrap();
    let _sequenceid = u32::decode(resp).unwrap();
    let _slotid = u32::decode(resp).unwrap();
    let _highest_slotid = u32::decode(resp).unwrap();
    let _target_highest_slotid = u32::decode(resp).unwrap();
    let _status_flags = u32::decode(resp).unwrap();
}

async fn setup_session(stream: &mut TcpStream) -> [u8; 16] {
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

#[tokio::test]
async fn test_null_procedure() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let mut resp = send_rpc(&mut stream, 1, 0, &[]).await;
    let (xid, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(xid, 1);
    assert_eq!(accept_stat, 0);
}

#[tokio::test]
async fn test_v41_session_flow_and_readdir() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

#[tokio::test]
async fn test_minor_version_mismatch_rejects_non_v41() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let rootfh_op = encode_putrootfh();

    for (xid, minorversion) in [(1, 0u32), (2, 2u32)] {
        let compound = encode_compound_minor("bad-minor", minorversion, &[&rootfh_op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        let (_, accept_stat) = parse_rpc_reply(&mut resp);
        assert_eq!(accept_stat, 0);

        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::MinorVersMismatch as u32);
        assert_eq!(num_results, 0);
    }
}

#[tokio::test]
async fn test_fore_channel_ops_require_sequence() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let _sessionid = setup_session(&mut stream).await;

    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("missing-sequence", &[&rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::OpNotInSession as u32);
    assert_eq!(num_results, 1);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::OpNotInSession as u32);
}

#[tokio::test]
async fn test_sequence_must_be_first_and_unique() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op1 = encode_sequence(&sessionid, 1, 0);
    let seq_op2 = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("sequence-pos", &[&seq_op1, &rootfh_op, &seq_op2]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::SequencePos as u32);
    assert_eq!(num_results, 3);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::SequencePos as u32);
}

#[tokio::test]
async fn test_v40_only_op_is_not_supported_in_v41() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let open_confirm_op = encode_open_confirm();
    let compound = encode_compound("obsolete-op", &[&seq_op, &open_confirm_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Notsupp as u32);
    assert_eq!(num_results, 2);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN_CONFIRM);
    assert_eq!(op_status, NfsStat4::Notsupp as u32);
}

#[tokio::test]
async fn test_exchange_id_without_sequence_must_be_only_op() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let exchange_id_op = encode_exchange_id();
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("not-only-op", &[&exchange_id_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotOnlyOp as u32);
    assert_eq!(num_results, 1);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_EXCHANGE_ID);
    assert_eq!(op_status, NfsStat4::NotOnlyOp as u32);
}

#[tokio::test]
async fn test_reclaim_complete() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let mut rc_buf = BytesMut::new();
    OP_RECLAIM_COMPLETE.encode(&mut rc_buf);
    false.encode(&mut rc_buf);
    let rc_op = rc_buf.to_vec();

    let compound = encode_compound("reclaim", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
}

//! Integration tests that start the NFS server and exercise raw RPC flows.
#![allow(dead_code)]

use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use embednfs_proto::xdr::*;
use embednfs_proto::*;
use embednfs::{MemFs, NfsFileSystem, NfsNamedAttrs, NfsServer, XattrSetMode};

async fn start_server() -> u16 {
    start_server_with_fs(MemFs::new()).await
}

async fn start_server_with_fs(fs: MemFs) -> u16 {
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

fn encode_getfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_GETFH.encode(&mut buf);
    buf.to_vec()
}

fn encode_putfh(fh: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTFH.encode(&mut buf);
    encode_opaque(&mut buf, fh);
    buf.to_vec()
}

fn encode_lookup(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOOKUP.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

fn encode_openattr(createdir: bool) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPENATTR.encode(&mut buf);
    createdir.encode(&mut buf);
    buf.to_vec()
}

fn encode_read(offset: u64, count: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READ.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    offset.encode(&mut buf);
    count.encode(&mut buf);
    buf.to_vec()
}

fn encode_readdir() -> Vec<u8> {
    encode_readdir_custom(0, [0u8; 8], 8192, 32768, &[FATTR4_FILEID, FATTR4_TYPE])
}

fn encode_readdir_custom(
    cookie: u64,
    cookieverf: [u8; 8],
    dircount: u32,
    maxcount: u32,
    bits: &[u32],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READDIR.encode(&mut buf);
    cookie.encode(&mut buf);
    buf.put_slice(&cookieverf);
    dircount.encode(&mut buf);
    maxcount.encode(&mut buf);

    let mut bitmap = Bitmap4::new();
    for bit in bits {
        bitmap.set(*bit);
    }
    bitmap.encode(&mut buf);
    buf.to_vec()
}

fn encode_remove(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_REMOVE.encode(&mut buf);
    name.to_string().encode(&mut buf);
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

fn parse_readdir_body(resp: &mut Bytes) -> (usize, [u8; 8], Vec<(u64, String, Fattr4)>, bool) {
    let body_len_before = resp.len();
    let cookieverf_data = decode_fixed_opaque(resp, 8).unwrap();
    let mut cookieverf = [0u8; 8];
    cookieverf.copy_from_slice(&cookieverf_data);

    let mut entries = Vec::new();
    while bool::decode(resp).unwrap() {
        let cookie = u64::decode(resp).unwrap();
        let name = String::decode(resp).unwrap();
        let attrs = Fattr4::decode(resp).unwrap();
        entries.push((cookie, name, attrs));
    }
    let eof = bool::decode(resp).unwrap();

    (body_len_before - resp.len(), cookieverf, entries, eof)
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

async fn populated_fs(names: &[&str]) -> MemFs {
    let fs = MemFs::new();
    for name in names {
        fs.create_file(1, name).await.unwrap();
    }
    fs
}

async fn fs_with_xattr(file_name: &str, xattr_name: &str, value: &[u8]) -> MemFs {
    let fs = MemFs::new();
    let file_id = fs.create_file(1, file_name).await.unwrap();
    fs.set_xattr(file_id, xattr_name, value, XattrSetMode::CreateOnly)
        .await
        .unwrap();
    fs
}

fn apple_readdirplus_bits() -> Vec<u32> {
    vec![
        FATTR4_SUPPORTED_ATTRS,
        FATTR4_TYPE,
        FATTR4_FH_EXPIRE_TYPE,
        FATTR4_CHANGE,
        FATTR4_SIZE,
        FATTR4_LINK_SUPPORT,
        FATTR4_SYMLINK_SUPPORT,
        FATTR4_NAMED_ATTR,
        FATTR4_FSID,
        FATTR4_UNIQUE_HANDLES,
        FATTR4_LEASE_TIME,
        FATTR4_RDATTR_ERROR,
        FATTR4_FILEHANDLE,
        FATTR4_ACLSUPPORT,
        FATTR4_ARCHIVE,
        FATTR4_CANSETTIME,
        FATTR4_CASE_INSENSITIVE,
        FATTR4_CASE_PRESERVING,
        FATTR4_CHOWN_RESTRICTED,
        FATTR4_FILEID,
        FATTR4_FILES_AVAIL,
        FATTR4_FILES_FREE,
        FATTR4_FILES_TOTAL,
        FATTR4_HIDDEN,
        FATTR4_HOMOGENEOUS,
        FATTR4_MAXFILESIZE,
        FATTR4_MAXLINK,
        FATTR4_MAXNAME,
        FATTR4_MAXREAD,
        FATTR4_MAXWRITE,
        FATTR4_MODE,
        FATTR4_NO_TRUNC,
        FATTR4_NUMLINKS,
        FATTR4_OWNER,
        FATTR4_OWNER_GROUP,
        FATTR4_RAWDEV,
        FATTR4_SPACE_AVAIL,
        FATTR4_SPACE_FREE,
        FATTR4_SPACE_TOTAL,
        FATTR4_SPACE_USED,
        FATTR4_SYSTEM,
        FATTR4_TIME_ACCESS,
        FATTR4_TIME_BACKUP,
        FATTR4_TIME_CREATE,
        FATTR4_TIME_DELTA,
        FATTR4_TIME_METADATA,
        FATTR4_TIME_MODIFY,
        FATTR4_MOUNTED_ON_FILEID,
        FATTR4_SUPPATTR_EXCLCREAT,
    ]
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

#[tokio::test]
async fn test_openattr_on_file_returns_attrdir() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound(
        "openattr",
        &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 5);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPENATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut attr_vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut attr_vals).unwrap();
    assert_eq!(file_type, NfsFtype4::AttrDir as u32);
}

#[tokio::test]
async fn test_openattr_readdir_lists_named_attrs() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 8192, &[FATTR4_FILEID, FATTR4_TYPE]);
    let compound = encode_compound(
        "openattr-readdir",
        &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &readdir_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 5);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_, _, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "user.demo");
}

#[tokio::test]
async fn test_named_attr_lookup_and_read() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let lookup_xattr_op = encode_lookup("user.demo");
    let read_op = encode_read(0, 1024);
    let compound = encode_compound(
        "named-attr-read",
        &[&seq_op, &rootfh_op, &lookup_file_op, &openattr_op, &lookup_xattr_op, &read_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 6);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert_eq!(data, b"value");
}

#[tokio::test]
async fn test_readdir_reply_stays_within_maxcount_and_skips_dot_entries() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt", "delta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 512, 1536, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-bounds", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);

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
    let (body_len, _cookieverf, entries, _eof) = parse_readdir_body(&mut resp);
    assert!(body_len <= 1536, "readdir body exceeded maxcount: {body_len}");
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|(_, name, _)| name != "." && name != ".."));
    assert!(entries.iter().all(|(cookie, _, _)| *cookie >= 3));
}

#[tokio::test]
async fn test_readdir_returns_toosmall_when_entry_cannot_fit() {
    let fs = populated_fs(&["oversized.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 64, 64, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-toosmall", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Toosmall as u32);
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
    assert_eq!(op_status, NfsStat4::Toosmall as u32);
}

#[tokio::test]
async fn test_readdir_cookieverf_stable_for_unchanged_dir() {
    let fs = populated_fs(&["alpha.txt", "beta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-first", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, cookieverf, entries, _) = parse_readdir_body(&mut resp);
    assert!(entries.len() >= 2);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let readdir_op = encode_readdir_custom(entries[0].0, cookieverf, 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 4, 1, &encode_compound("readdir-cont", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, continued_verf, continued_entries, _) = parse_readdir_body(&mut resp);
    assert_eq!(continued_verf, cookieverf);
    assert!(!continued_entries.is_empty());
}

#[tokio::test]
async fn test_readdir_cookieverf_rejects_stale_continuation_after_mutation() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-before-mutate", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, cookieverf, entries, _) = parse_readdir_body(&mut resp);
    assert!(entries.len() >= 2);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let remove_op = encode_remove("gamma.txt");
    let mut resp = send_rpc(&mut stream, 4, 1, &encode_compound("mutate-dir", &[&seq_op, &rootfh_op, &remove_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let readdir_op = encode_readdir_custom(entries[0].0, cookieverf, 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 5, 1, &encode_compound("readdir-stale-verf", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotSame as u32);
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
    assert_eq!(op_status, NfsStat4::NotSame as u32);
}

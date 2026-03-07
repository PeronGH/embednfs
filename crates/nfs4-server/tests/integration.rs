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
    encode_compound_v(tag, 1, ops)
}

fn encode_compound_v(tag: &str, minorversion: u32, ops: &[&[u8]]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);
    tag.to_string().encode(&mut buf);
    minorversion.encode(&mut buf);
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

/// Simulate a Finder-like GETATTR requesting ALL supported attributes.
/// This catches bitmap/data size mismatches that cause "RPC struct is bad".
#[tokio::test]
async fn test_getattr_all_supported_attrs() {
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

    // Request ALL attributes that macOS Finder might request
    let all_attrs = [
        FATTR4_SUPPORTED_ATTRS, FATTR4_TYPE, FATTR4_FH_EXPIRE_TYPE,
        FATTR4_CHANGE, FATTR4_SIZE, FATTR4_LINK_SUPPORT, FATTR4_SYMLINK_SUPPORT,
        FATTR4_NAMED_ATTR, FATTR4_FSID, FATTR4_UNIQUE_HANDLES, FATTR4_LEASE_TIME,
        FATTR4_RDATTR_ERROR, FATTR4_ACLSUPPORT,
        FATTR4_ARCHIVE, FATTR4_CANSETTIME, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING,
        FATTR4_CHOWN_RESTRICTED, FATTR4_FILEHANDLE, FATTR4_FILEID,
        FATTR4_FILES_AVAIL, FATTR4_FILES_FREE, FATTR4_FILES_TOTAL,
        FATTR4_HIDDEN, FATTR4_HOMOGENEOUS,
        FATTR4_MAXFILESIZE, FATTR4_MAXLINK, FATTR4_MAXNAME, FATTR4_MAXREAD, FATTR4_MAXWRITE,
        FATTR4_MODE, FATTR4_NO_TRUNC, FATTR4_NUMLINKS,
        FATTR4_OWNER, FATTR4_OWNER_GROUP,
        FATTR4_RAWDEV, FATTR4_SPACE_AVAIL, FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL,
        FATTR4_SPACE_USED,
        FATTR4_SYSTEM, FATTR4_TIME_ACCESS,
        FATTR4_TIME_BACKUP, FATTR4_TIME_CREATE, FATTR4_TIME_DELTA,
        FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY,
        FATTR4_MOUNTED_ON_FILEID, FATTR4_SUPPATTR_EXCLCREAT,
    ];
    let getattr_op = encode_getattr(&all_attrs);
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 0, "COMPOUND status should be OK");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    assert_eq!(num_results, 3);

    // Parse SEQUENCE result
    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_SEQUENCE);
    let op_status = u32::decode(&mut resp).unwrap();
    assert_eq!(op_status, 0);
    let _ = decode_fixed_opaque(&mut resp, 16).unwrap(); // sessionid
    let _ = u32::decode(&mut resp).unwrap(); // sequenceid
    let _ = u32::decode(&mut resp).unwrap(); // slotid
    let _ = u32::decode(&mut resp).unwrap(); // highest_slotid
    let _ = u32::decode(&mut resp).unwrap(); // target_highest_slotid
    let _ = u32::decode(&mut resp).unwrap(); // status_flags

    // Parse PUTROOTFH result
    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_PUTROOTFH);
    let op_status = u32::decode(&mut resp).unwrap();
    assert_eq!(op_status, 0);

    // Parse GETATTR result - this is the critical part
    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_GETATTR);
    let op_status = u32::decode(&mut resp).unwrap();
    assert_eq!(op_status, 0, "GETATTR should succeed");

    // Parse the Fattr4
    let fattr = Fattr4::decode(&mut resp).unwrap();

    // Verify the bitmap has reasonable bits set
    assert!(fattr.attrmask.is_set(FATTR4_TYPE), "TYPE should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_CHANGE), "CHANGE should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_SIZE), "SIZE should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_FILEID), "FILEID should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_MODE), "MODE should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_ARCHIVE), "ARCHIVE should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_HIDDEN), "HIDDEN should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_SYSTEM), "SYSTEM should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_TIME_BACKUP), "TIME_BACKUP should be in response");
    assert!(fattr.attrmask.is_set(FATTR4_TIME_CREATE), "TIME_CREATE should be in response");

    // Now decode attr_vals byte by byte to verify encoding correctness.
    // The client does exactly this; if our encoding is wrong, it fails.
    let mut vals = Bytes::from(fattr.attr_vals.clone());

    // Decode in bitmap order (same order as encode_fattr4):
    if fattr.attrmask.is_set(FATTR4_SUPPORTED_ATTRS) {
        let _ = Bitmap4::decode(&mut vals).expect("SUPPORTED_ATTRS decode");
    }
    if fattr.attrmask.is_set(FATTR4_TYPE) {
        let _ = u32::decode(&mut vals).expect("TYPE decode"); // nfs_ftype4
    }
    if fattr.attrmask.is_set(FATTR4_FH_EXPIRE_TYPE) {
        let _ = u32::decode(&mut vals).expect("FH_EXPIRE_TYPE decode");
    }
    if fattr.attrmask.is_set(FATTR4_CHANGE) {
        let _ = u64::decode(&mut vals).expect("CHANGE decode");
    }
    if fattr.attrmask.is_set(FATTR4_SIZE) {
        let _ = u64::decode(&mut vals).expect("SIZE decode");
    }
    if fattr.attrmask.is_set(FATTR4_LINK_SUPPORT) {
        let _ = bool::decode(&mut vals).expect("LINK_SUPPORT decode");
    }
    if fattr.attrmask.is_set(FATTR4_SYMLINK_SUPPORT) {
        let _ = bool::decode(&mut vals).expect("SYMLINK_SUPPORT decode");
    }
    if fattr.attrmask.is_set(FATTR4_NAMED_ATTR) {
        let _ = bool::decode(&mut vals).expect("NAMED_ATTR decode");
    }
    if fattr.attrmask.is_set(FATTR4_FSID) {
        let _ = Fsid4::decode(&mut vals).expect("FSID decode");
    }
    if fattr.attrmask.is_set(FATTR4_UNIQUE_HANDLES) {
        let _ = bool::decode(&mut vals).expect("UNIQUE_HANDLES decode");
    }
    if fattr.attrmask.is_set(FATTR4_LEASE_TIME) {
        let _ = u32::decode(&mut vals).expect("LEASE_TIME decode");
    }
    if fattr.attrmask.is_set(FATTR4_RDATTR_ERROR) {
        let _ = u32::decode(&mut vals).expect("RDATTR_ERROR decode");
    }
    if fattr.attrmask.is_set(FATTR4_ACLSUPPORT) {
        let _ = u32::decode(&mut vals).expect("ACLSUPPORT decode");
    }
    if fattr.attrmask.is_set(FATTR4_ARCHIVE) {
        let _ = bool::decode(&mut vals).expect("ARCHIVE decode");
    }
    if fattr.attrmask.is_set(FATTR4_CANSETTIME) {
        let _ = bool::decode(&mut vals).expect("CANSETTIME decode");
    }
    if fattr.attrmask.is_set(FATTR4_CASE_INSENSITIVE) {
        let _ = bool::decode(&mut vals).expect("CASE_INSENSITIVE decode");
    }
    if fattr.attrmask.is_set(FATTR4_CASE_PRESERVING) {
        let _ = bool::decode(&mut vals).expect("CASE_PRESERVING decode");
    }
    if fattr.attrmask.is_set(FATTR4_CHOWN_RESTRICTED) {
        let _ = bool::decode(&mut vals).expect("CHOWN_RESTRICTED decode");
    }
    if fattr.attrmask.is_set(FATTR4_FILEHANDLE) {
        let _ = NfsFh4::decode(&mut vals).expect("FILEHANDLE decode");
    }
    if fattr.attrmask.is_set(FATTR4_FILEID) {
        let _ = u64::decode(&mut vals).expect("FILEID decode");
    }
    if fattr.attrmask.is_set(FATTR4_FILES_AVAIL) {
        let _ = u64::decode(&mut vals).expect("FILES_AVAIL decode");
    }
    if fattr.attrmask.is_set(FATTR4_FILES_FREE) {
        let _ = u64::decode(&mut vals).expect("FILES_FREE decode");
    }
    if fattr.attrmask.is_set(FATTR4_FILES_TOTAL) {
        let _ = u64::decode(&mut vals).expect("FILES_TOTAL decode");
    }
    if fattr.attrmask.is_set(FATTR4_HIDDEN) {
        let _ = bool::decode(&mut vals).expect("HIDDEN decode");
    }
    if fattr.attrmask.is_set(FATTR4_HOMOGENEOUS) {
        let _ = bool::decode(&mut vals).expect("HOMOGENEOUS decode");
    }
    if fattr.attrmask.is_set(FATTR4_MAXFILESIZE) {
        let _ = u64::decode(&mut vals).expect("MAXFILESIZE decode");
    }
    if fattr.attrmask.is_set(FATTR4_MAXLINK) {
        let _ = u32::decode(&mut vals).expect("MAXLINK decode");
    }
    if fattr.attrmask.is_set(FATTR4_MAXNAME) {
        let _ = u32::decode(&mut vals).expect("MAXNAME decode");
    }
    if fattr.attrmask.is_set(FATTR4_MAXREAD) {
        let _ = u64::decode(&mut vals).expect("MAXREAD decode");
    }
    if fattr.attrmask.is_set(FATTR4_MAXWRITE) {
        let _ = u64::decode(&mut vals).expect("MAXWRITE decode");
    }
    if fattr.attrmask.is_set(FATTR4_MODE) {
        let _ = u32::decode(&mut vals).expect("MODE decode");
    }
    if fattr.attrmask.is_set(FATTR4_NO_TRUNC) {
        let _ = bool::decode(&mut vals).expect("NO_TRUNC decode");
    }
    if fattr.attrmask.is_set(FATTR4_NUMLINKS) {
        let _ = u32::decode(&mut vals).expect("NUMLINKS decode");
    }
    if fattr.attrmask.is_set(FATTR4_OWNER) {
        let _ = String::decode(&mut vals).expect("OWNER decode");
    }
    if fattr.attrmask.is_set(FATTR4_OWNER_GROUP) {
        let _ = String::decode(&mut vals).expect("OWNER_GROUP decode");
    }
    if fattr.attrmask.is_set(FATTR4_RAWDEV) {
        let _ = u32::decode(&mut vals).expect("RAWDEV specdata1 decode");
        let _ = u32::decode(&mut vals).expect("RAWDEV specdata2 decode");
    }
    if fattr.attrmask.is_set(FATTR4_SPACE_AVAIL) {
        let _ = u64::decode(&mut vals).expect("SPACE_AVAIL decode");
    }
    if fattr.attrmask.is_set(FATTR4_SPACE_FREE) {
        let _ = u64::decode(&mut vals).expect("SPACE_FREE decode");
    }
    if fattr.attrmask.is_set(FATTR4_SPACE_TOTAL) {
        let _ = u64::decode(&mut vals).expect("SPACE_TOTAL decode");
    }
    if fattr.attrmask.is_set(FATTR4_SPACE_USED) {
        let _ = u64::decode(&mut vals).expect("SPACE_USED decode");
    }
    if fattr.attrmask.is_set(FATTR4_SYSTEM) {
        let _ = bool::decode(&mut vals).expect("SYSTEM decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_ACCESS) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_ACCESS decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_BACKUP) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_BACKUP decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_CREATE) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_CREATE decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_DELTA) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_DELTA decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_METADATA) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_METADATA decode");
    }
    if fattr.attrmask.is_set(FATTR4_TIME_MODIFY) {
        let _ = NfsTime4::decode(&mut vals).expect("TIME_MODIFY decode");
    }
    if fattr.attrmask.is_set(FATTR4_MOUNTED_ON_FILEID) {
        let _ = u64::decode(&mut vals).expect("MOUNTED_ON_FILEID decode");
    }
    if fattr.attrmask.is_set(FATTR4_SUPPATTR_EXCLCREAT) {
        let _ = Bitmap4::decode(&mut vals).expect("SUPPATTR_EXCLCREAT decode");
    }

    // All attr_vals bytes should be consumed
    assert_eq!(vals.len(), 0, "All attr_vals bytes should be consumed; {} bytes left over", vals.len());

    // Also verify no leftover bytes in the RPC response
    assert_eq!(resp.len(), 0, "No leftover bytes in RPC response; {} bytes remain", resp.len());
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

/// RFC 8881 §16.2.3: minorversion != 1 must return NFS4ERR_MINOR_VERS_MISMATCH
/// with zero-length resarray.
#[tokio::test]
async fn test_minorversion_0_rejected() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Send a COMPOUND with minorversion=0 (NFSv4.0)
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound_v("v40", 0, &[&rootfh_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0, "RPC should be accepted");

    // Parse COMPOUND response
    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 10021, "Should return NFS4ERR_MINOR_VERS_MISMATCH (10021)");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    assert_eq!(num_results, 0, "resarray must be empty for minor version mismatch");
}

/// RFC 8881 §16.2.3: minorversion=2 must also be rejected.
#[tokio::test]
async fn test_minorversion_2_rejected() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    let rootfh_op = encode_putrootfh();
    let compound = encode_compound_v("v42", 2, &[&rootfh_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let status = u32::decode(&mut resp).unwrap();
    assert_eq!(status, 10021, "Should return NFS4ERR_MINOR_VERS_MISMATCH (10021)");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    assert_eq!(num_results, 0, "resarray must be empty for minor version mismatch");
}

/// RFC 8881 §8.1: NFSv4.0-only operations must return NFS4ERR_NOTSUPP.
#[tokio::test]
async fn test_v4_0_ops_return_notsupp() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();

    // Establish a v4.1 session
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

    // Test SETCLIENTID (op 35) — v4.0 only, must return NOTSUPP
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let mut setclientid_buf = BytesMut::new();
    OP_SETCLIENTID.encode(&mut setclientid_buf);
    // client verifier (8 bytes)
    setclientid_buf.put_slice(&[0u8; 8]);
    // client id string
    encode_opaque(&mut setclientid_buf, b"dummy");
    // callback (cb_program + cb_location)
    0u32.encode(&mut setclientid_buf); // cb_program
    // netid + uaddr
    "tcp".to_string().encode(&mut setclientid_buf);
    "127.0.0.1.8.1".to_string().encode(&mut setclientid_buf);
    // callback_ident
    0u32.encode(&mut setclientid_buf);
    let setclientid_op = setclientid_buf.to_vec();

    let compound = encode_compound("", &[&seq_op, &setclientid_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let status = u32::decode(&mut resp).unwrap();
    // COMPOUND status should be NOTSUPP (the SETCLIENTID failed)
    assert_eq!(status, 10004, "COMPOUND should fail with NFS4ERR_NOTSUPP (10004)");
    let _tag = String::decode(&mut resp).unwrap();
    let num_results = u32::decode(&mut resp).unwrap();
    // SEQUENCE succeeded, SETCLIENTID failed = 2 results
    assert_eq!(num_results, 2);

    // First result: SEQUENCE should be OK
    let opnum = u32::decode(&mut resp).unwrap();
    assert_eq!(opnum, OP_SEQUENCE);
    let seq_status = u32::decode(&mut resp).unwrap();
    assert_eq!(seq_status, 0, "SEQUENCE should succeed");
}

//! Shared test helpers for NFSv4.1 integration tests.
//!
//! Provides server setup, XDR encoding helpers, and response parsing utilities
//! so that individual test modules stay focused on test logic.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use embednfs::{
    AccessMask, Attrs, CommitSupport, CreateKind, CreateRequest, CreateResult, DirPage, FileSystem,
    FsError, FsResult, FsStats, HardLinks, MemFs, NfsServer, ReadResult, RequestContext, SetAttrs,
    Symlinks, WriteResult, XattrSetMode, Xattrs,
};
use embednfs_proto::xdr::*;
use embednfs_proto::*;

// ===== Server setup =====

pub async fn start_server() -> u16 {
    start_server_with_fs(MemFs::new()).await
}

pub async fn start_server_with_fs<F: FileSystem>(fs: F) -> u16 {
    let server = NfsServer::new(fs);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

pub async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap()
}

// ===== RPC transport =====

pub async fn send_rpc(stream: &mut TcpStream, xid: u32, proc_num: u32, payload: &[u8]) -> Bytes {
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

// ===== COMPOUND encoders =====

pub fn encode_compound_minor(tag: &str, minorversion: u32, ops: &[&[u8]]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(512);
    tag.to_string().encode(&mut buf);
    minorversion.encode(&mut buf);
    (ops.len() as u32).encode(&mut buf);
    for op in ops {
        buf.put_slice(op);
    }
    buf.to_vec()
}

pub fn encode_compound(tag: &str, ops: &[&[u8]]) -> Vec<u8> {
    encode_compound_minor(tag, 1, ops)
}

// ===== Operation encoders =====

pub fn encode_exchange_id() -> Vec<u8> {
    encode_exchange_id_with_name(b"test-client")
}

pub fn encode_exchange_id_with_name(name: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]); // verifier
    encode_opaque(&mut buf, name);
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    0u32.encode(&mut buf); // SP4_NONE
    0u32.encode(&mut buf); // client_impl_id = []
    buf.to_vec()
}

pub fn encode_exchange_id_with_flags(name: &[u8], flags: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]); // verifier
    encode_opaque(&mut buf, name);
    flags.encode(&mut buf);
    0u32.encode(&mut buf); // SP4_NONE
    0u32.encode(&mut buf); // client_impl_id = []
    buf.to_vec()
}

pub fn encode_create_session(clientid: u64, seq: u32) -> Vec<u8> {
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

pub fn encode_destroy_session(sessionid: &[u8; 16]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_DESTROY_SESSION.encode(&mut buf);
    buf.put_slice(sessionid);
    buf.to_vec()
}

pub fn encode_destroy_clientid(clientid: u64) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_DESTROY_CLIENTID.encode(&mut buf);
    clientid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_sequence(sessionid: &[u8; 16], seq: u32, slot: u32) -> Vec<u8> {
    encode_sequence_with_cache(sessionid, seq, slot, false)
}

pub fn encode_sequence_with_cache(
    sessionid: &[u8; 16],
    seq: u32,
    slot: u32,
    cachethis: bool,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SEQUENCE.encode(&mut buf);
    buf.put_slice(sessionid);
    seq.encode(&mut buf);
    slot.encode(&mut buf);
    slot.encode(&mut buf); // highest_slotid
    cachethis.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_putrootfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTROOTFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_putpubfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTPUBFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_getattr(bits: &[u32]) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    for bit in bits {
        bitmap.set(*bit);
    }

    let mut buf = BytesMut::new();
    OP_GETATTR.encode(&mut buf);
    bitmap.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_getfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_GETFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_putfh(fh: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTFH.encode(&mut buf);
    encode_opaque(&mut buf, fh);
    buf.to_vec()
}

pub fn encode_savefh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SAVEFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_restorefh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_RESTOREFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_lookup(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOOKUP.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_lookupp() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOOKUPP.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_openattr(createdir: bool) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPENATTR.encode(&mut buf);
    createdir.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_secinfo_no_name(style: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SECINFO_NO_NAME.encode(&mut buf);
    style.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_create(name: &str) -> Vec<u8> {
    encode_open_create_with_access(name, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE)
}

pub fn encode_open_create_with_access(name: &str, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    share_access.encode(&mut buf);
    share_deny.encode(&mut buf);
    1u64.encode(&mut buf); // clientid
    encode_opaque(&mut buf, b"test-open-owner");
    1u32.encode(&mut buf); // OPEN4_CREATE
    0u32.encode(&mut buf); // UNCHECKED4
    Bitmap4::new().encode(&mut buf); // empty attrs
    encode_opaque(&mut buf, &[]); // empty attr values
    0u32.encode(&mut buf); // CLAIM_NULL
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_nocreate(name: &str) -> Vec<u8> {
    encode_open_nocreate_with_access(name, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE)
}

pub fn encode_open_nocreate_with_access(name: &str, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    share_access.encode(&mut buf);
    share_deny.encode(&mut buf);
    1u64.encode(&mut buf); // clientid
    encode_opaque(&mut buf, b"test-open-owner");
    0u32.encode(&mut buf); // OPEN4_NOCREATE
    0u32.encode(&mut buf); // CLAIM_NULL
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_close(stateid: &Stateid4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CLOSE.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    stateid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_downgrade(stateid: &Stateid4, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN_DOWNGRADE.encode(&mut buf);
    stateid.encode(&mut buf);
    0u32.encode(&mut buf); // seqid is ignored in NFSv4.1
    share_access.encode(&mut buf);
    share_deny.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_read(offset: u64, count: u32) -> Vec<u8> {
    encode_read_stateid(&Stateid4::default(), offset, count)
}

pub fn encode_read_stateid(stateid: &Stateid4, offset: u64, count: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READ.encode(&mut buf);
    stateid.encode(&mut buf);
    offset.encode(&mut buf);
    count.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_write(stateid: &Stateid4, offset: u64, data: &[u8]) -> Vec<u8> {
    encode_write_with_stability(stateid, offset, FILE_SYNC4, data)
}

pub fn encode_write_with_stability(
    stateid: &Stateid4,
    offset: u64,
    stable_how: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_WRITE.encode(&mut buf);
    stateid.encode(&mut buf);
    offset.encode(&mut buf);
    stable_how.encode(&mut buf);
    encode_opaque(&mut buf, data);
    buf.to_vec()
}

pub fn encode_readdir() -> Vec<u8> {
    encode_readdir_custom(0, [0u8; 8], 8192, 32768, &[FATTR4_FILEID, FATTR4_TYPE])
}

pub fn encode_readdir_custom(
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

pub fn encode_remove(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_REMOVE.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_rename(oldname: &str, newname: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_RENAME.encode(&mut buf);
    oldname.to_string().encode(&mut buf);
    newname.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_create_dir(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE.encode(&mut buf);
    // type = NF4DIR (2), with objname
    2u32.encode(&mut buf); // NF4DIR
    name.to_string().encode(&mut buf);
    // createattrs = empty fattr4
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    buf.to_vec()
}

pub fn encode_create_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE.encode(&mut buf);
    5u32.encode(&mut buf); // NF4LNK
    target.to_string().encode(&mut buf); // linkdata
    name.to_string().encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    buf.to_vec()
}

pub fn encode_readlink() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READLINK.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_link(newname: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LINK.encode(&mut buf);
    newname.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_access(access_bits: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_ACCESS.encode(&mut buf);
    access_bits.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_commit(offset: u64, count: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_COMMIT.encode(&mut buf);
    offset.encode(&mut buf);
    count.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_setattr_size(stateid: &Stateid4, size: u64) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_SIZE);

    let mut vals = BytesMut::new();
    size.encode(&mut vals);

    let mut buf = BytesMut::new();
    OP_SETATTR.encode(&mut buf);
    stateid.encode(&mut buf);
    bitmap.encode(&mut buf);
    encode_opaque(&mut buf, &vals);
    buf.to_vec()
}

pub fn encode_setattr_flags(archive: bool, hidden: bool, system: bool) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_ARCHIVE);
    bitmap.set(FATTR4_HIDDEN);
    bitmap.set(FATTR4_SYSTEM);

    let mut vals = BytesMut::new();
    archive.encode(&mut vals);
    hidden.encode(&mut vals);
    system.encode(&mut vals);

    let mut buf = BytesMut::new();
    OP_SETATTR.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    bitmap.encode(&mut buf);
    encode_opaque(&mut buf, &vals);
    buf.to_vec()
}

pub fn encode_setattr_truncated_client_mtime() -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    bitmap.set(FATTR4_TIME_MODIFY_SET);

    let mut vals = BytesMut::new();
    1u32.encode(&mut vals);
    123i64.encode(&mut vals);

    let mut buf = BytesMut::new();
    OP_SETATTR.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    bitmap.encode(&mut buf);
    encode_opaque(&mut buf, &vals);
    buf.to_vec()
}

pub fn encode_verify(bits: &[u32], attr_vals: &[u8]) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    for bit in bits {
        bitmap.set(*bit);
    }
    let mut buf = BytesMut::new();
    OP_VERIFY.encode(&mut buf);
    bitmap.encode(&mut buf);
    encode_opaque(&mut buf, attr_vals);
    buf.to_vec()
}

pub fn encode_nverify(bits: &[u32], attr_vals: &[u8]) -> Vec<u8> {
    let mut bitmap = Bitmap4::new();
    for bit in bits {
        bitmap.set(*bit);
    }
    let mut buf = BytesMut::new();
    OP_NVERIFY.encode(&mut buf);
    bitmap.encode(&mut buf);
    encode_opaque(&mut buf, attr_vals);
    buf.to_vec()
}

pub fn encode_test_stateid(stateids: &[Stateid4]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_TEST_STATEID.encode(&mut buf);
    (stateids.len() as u32).encode(&mut buf);
    for stateid in stateids {
        stateid.encode(&mut buf);
    }
    buf.to_vec()
}

pub fn encode_free_stateid(stateid: &Stateid4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_FREE_STATEID.encode(&mut buf);
    stateid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_confirm() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN_CONFIRM.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    buf.to_vec()
}

pub fn encode_reclaim_complete(one_fs: bool) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_RECLAIM_COMPLETE.encode(&mut buf);
    one_fs.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_illegal() -> Vec<u8> {
    let mut buf = BytesMut::new();
    // Use OP_ILLEGAL (10044)
    OP_ILLEGAL.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_delegreturn(stateid: &Stateid4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_DELEGRETURN.encode(&mut buf);
    stateid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_delegpurge() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_DELEGPURGE.encode(&mut buf);
    0u64.encode(&mut buf); // clientid
    buf.to_vec()
}

pub fn encode_lock_new(
    locktype: u32,
    reclaim: bool,
    offset: u64,
    length: u64,
    open_stateid: &Stateid4,
    lock_owner: &[u8],
    clientid: u64,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOCK.encode(&mut buf);
    locktype.encode(&mut buf);
    reclaim.encode(&mut buf);
    offset.encode(&mut buf);
    length.encode(&mut buf);
    // new_lock_owner = true
    true.encode(&mut buf);
    0u32.encode(&mut buf); // open_seqid
    open_stateid.encode(&mut buf);
    0u32.encode(&mut buf); // lock_seqid
    clientid.encode(&mut buf);
    encode_opaque(&mut buf, lock_owner);
    buf.to_vec()
}

pub fn encode_lock_existing(
    locktype: u32,
    reclaim: bool,
    offset: u64,
    length: u64,
    lock_stateid: &Stateid4,
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOCK.encode(&mut buf);
    locktype.encode(&mut buf);
    reclaim.encode(&mut buf);
    offset.encode(&mut buf);
    length.encode(&mut buf);
    // new_lock_owner = false
    false.encode(&mut buf);
    lock_stateid.encode(&mut buf);
    0u32.encode(&mut buf); // lock_seqid
    buf.to_vec()
}

pub fn encode_lockt(
    locktype: u32,
    offset: u64,
    length: u64,
    clientid: u64,
    owner: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOCKT.encode(&mut buf);
    locktype.encode(&mut buf);
    offset.encode(&mut buf);
    length.encode(&mut buf);
    clientid.encode(&mut buf);
    encode_opaque(&mut buf, owner);
    buf.to_vec()
}

pub fn encode_locku(locktype: u32, lock_stateid: &Stateid4, offset: u64, length: u64) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_LOCKU.encode(&mut buf);
    locktype.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    lock_stateid.encode(&mut buf);
    offset.encode(&mut buf);
    length.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_bind_conn_to_session(sessionid: &[u8; 16], dir: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_BIND_CONN_TO_SESSION.encode(&mut buf);
    buf.put_slice(sessionid);
    dir.encode(&mut buf); // direction (0 = fore, 1 = back, 2 = both)
    false.encode(&mut buf); // rdma
    buf.to_vec()
}

pub fn parse_lock_res(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

pub fn parse_locku_res(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

// ===== Response parsers =====

pub fn parse_rpc_reply(resp: &mut Bytes) -> (u32, u32) {
    let xid = u32::decode(resp).unwrap();
    let msg_type = u32::decode(resp).unwrap();
    assert_eq!(msg_type, 1, "expected RPC reply");
    let reply_stat = u32::decode(resp).unwrap();
    assert_eq!(reply_stat, 0, "expected accepted reply");
    let _verf = OpaqueAuth::decode(resp).unwrap();
    let accept_stat = u32::decode(resp).unwrap();
    (xid, accept_stat)
}

pub fn parse_compound_header(resp: &mut Bytes) -> (u32, String, u32) {
    let status = u32::decode(resp).unwrap();
    let tag = String::decode(resp).unwrap();
    let num_results = u32::decode(resp).unwrap();
    (status, tag, num_results)
}

pub fn parse_op_header(resp: &mut Bytes) -> (u32, u32) {
    let opnum = u32::decode(resp).unwrap();
    let status = u32::decode(resp).unwrap();
    (opnum, status)
}

pub type ReaddirEntry = (u64, String, Fattr4);

pub fn parse_readdir_body(resp: &mut Bytes) -> (usize, [u8; 8], Vec<ReaddirEntry>, bool) {
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

pub fn parse_stateid(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

pub fn skip_change_info(resp: &mut Bytes) {
    let _ = bool::decode(resp).unwrap();
    let _ = u64::decode(resp).unwrap();
    let _ = u64::decode(resp).unwrap();
}

pub fn parse_change_info(resp: &mut Bytes) -> (bool, u64, u64) {
    (
        bool::decode(resp).unwrap(),
        u64::decode(resp).unwrap(),
        u64::decode(resp).unwrap(),
    )
}

pub fn skip_bitmap(resp: &mut Bytes) {
    let _ = Bitmap4::decode(resp).unwrap();
}

pub fn skip_open_res(resp: &mut Bytes) -> Stateid4 {
    let stateid = parse_stateid(resp);
    skip_change_info(resp);
    let _ = u32::decode(resp).unwrap(); // rflags
    skip_bitmap(resp); // attrset
    let _ = u32::decode(resp).unwrap(); // delegation type
    stateid
}

pub fn parse_open_res(resp: &mut Bytes) -> (Stateid4, (bool, u64, u64)) {
    let stateid = parse_stateid(resp);
    let cinfo = parse_change_info(resp);
    let _ = u32::decode(resp).unwrap(); // rflags
    skip_bitmap(resp); // attrset
    let _ = u32::decode(resp).unwrap(); // delegation type
    (stateid, cinfo)
}

pub fn parse_open_downgrade_res(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

pub fn parse_getfh(resp: &mut Bytes) -> Vec<u8> {
    decode_opaque(resp).unwrap()
}

pub fn parse_test_stateid_results(resp: &mut Bytes) -> Vec<u32> {
    let count = u32::decode(resp).unwrap() as usize;
    (0..count).map(|_| u32::decode(resp).unwrap()).collect()
}

pub fn skip_exchange_id_res(resp: &mut Bytes) -> (u64, u32) {
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

pub fn parse_exchange_id_res(resp: &mut Bytes) -> (u64, u32, u32) {
    let clientid = u64::decode(resp).unwrap();
    let sequenceid = u32::decode(resp).unwrap();
    let flags = u32::decode(resp).unwrap();
    let _state_protect = u32::decode(resp).unwrap();
    let _server_minor_id = u64::decode(resp).unwrap();
    let _server_major_id = Vec::<u8>::decode(resp).unwrap();
    let _server_scope = Vec::<u8>::decode(resp).unwrap();
    let _impl_count = u32::decode(resp).unwrap();
    (clientid, sequenceid, flags)
}

pub fn skip_sequence_res(resp: &mut Bytes) {
    let _sessionid = decode_fixed_opaque(resp, 16).unwrap();
    let _sequenceid = u32::decode(resp).unwrap();
    let _slotid = u32::decode(resp).unwrap();
    let _highest_slotid = u32::decode(resp).unwrap();
    let _target_highest_slotid = u32::decode(resp).unwrap();
    let _status_flags = u32::decode(resp).unwrap();
}

pub fn parse_create_session_res(resp: &mut Bytes) -> [u8; 16] {
    let session_data = decode_fixed_opaque(resp, 16).unwrap();
    let mut sessionid = [0u8; 16];
    sessionid.copy_from_slice(&session_data);
    sessionid
}

pub fn parse_write_res(resp: &mut Bytes) -> (u32, u32) {
    let count = u32::decode(resp).unwrap();
    let committed = u32::decode(resp).unwrap();
    let _ = decode_fixed_opaque(resp, 8).unwrap(); // writeverf
    (count, committed)
}

pub fn parse_access_res(resp: &mut Bytes) -> (u32, u32) {
    let supported = u32::decode(resp).unwrap();
    let access = u32::decode(resp).unwrap();
    (supported, access)
}

// ===== Session setup helper =====

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

    parse_create_session_res(&mut resp)
}

/// Full session setup returning (sessionid, clientid) for tests that need clientid.
pub async fn setup_session_full(stream: &mut TcpStream) -> ([u8; 16], u64) {
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

    let sessionid = parse_create_session_res(&mut resp);
    (sessionid, clientid)
}

// ===== Filesystem helpers =====

pub async fn populated_fs(names: &[&str]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    for name in names {
        fs.create(
            &ctx,
            &1,
            name,
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    }
    fs
}

pub async fn fs_with_xattr(file_name: &str, xattr_name: &str, value: &[u8]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let file_id = fs
        .create(
            &ctx,
            &1,
            file_name,
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    fs.set_xattr(
        &ctx,
        &file_id,
        xattr_name,
        Bytes::copy_from_slice(value),
        XattrSetMode::CreateOnly,
    )
    .await
    .unwrap();
    fs
}

pub async fn fs_with_subdir(dir_name: &str) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    fs.create(
        &ctx,
        &1,
        dir_name,
        CreateRequest {
            kind: CreateKind::Directory,
            attrs: SetAttrs::default(),
        },
    )
    .await
    .unwrap();
    fs
}

pub async fn fs_with_data(file_name: &str, data: &[u8]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let fid = fs
        .create(
            &ctx,
            &1,
            file_name,
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    fs.write(&ctx, &fid, 0, Bytes::copy_from_slice(data))
        .await
        .unwrap();
    fs
}

// ===== Custom filesystem wrappers for special test scenarios =====

pub struct BlockingRemoveFs {
    pub inner: MemFs,
    pub entered: Arc<Notify>,
    pub release: Arc<Notify>,
}

pub struct CountingNamedAttrFs {
    pub inner: MemFs,
    pub list_count: Arc<AtomicUsize>,
}

pub struct FailPostMutationRootStatFs {
    pub inner: MemFs,
    pub root_stat_limit: usize,
    pub root_stat_calls: AtomicUsize,
}

pub struct FailFirstRootStatFs {
    pub inner: MemFs,
    pub root_stat_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl FileSystem for BlockingRemoveFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        self.inner.root()
    }

    fn capabilities(&self) -> embednfs::FsCapabilities {
        self.inner.capabilities()
    }

    fn limits(&self) -> embednfs::FsLimits {
        self.inner.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> {
        self.inner.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> {
        self.inner.getattr(ctx, handle).await
    }

    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        self.inner.access(ctx, handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        self.inner.lookup(ctx, parent, name).await
    }

    async fn parent(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        self.inner.parent(ctx, dir).await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        self.inner
            .readdir(ctx, dir, cookie, max_entries, with_attrs)
            .await
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        self.inner.read(ctx, handle, offset, count).await
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
    ) -> FsResult<WriteResult> {
        self.inner.write(ctx, handle, offset, data).await
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        self.inner.create(ctx, parent, name, req).await
    }

    async fn remove(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        self.entered.notify_waiters();
        self.release.notified().await;
        self.inner.remove(ctx, parent, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        self.inner
            .rename(ctx, from_dir, from_name, to_dir, to_name)
            .await
    }

    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        self.inner.setattr(ctx, handle, attrs).await
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        self.inner.symlinks()
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> {
        self.inner.hard_links()
    }

    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> {
        self.inner.xattrs()
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        self.inner.commit_support()
    }
}

#[async_trait::async_trait]
impl FileSystem for CountingNamedAttrFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        self.inner.root()
    }

    fn capabilities(&self) -> embednfs::FsCapabilities {
        self.inner.capabilities()
    }

    fn limits(&self) -> embednfs::FsLimits {
        self.inner.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> {
        self.inner.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> {
        self.inner.getattr(ctx, handle).await
    }

    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        self.inner.access(ctx, handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        self.inner.lookup(ctx, parent, name).await
    }

    async fn parent(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        self.inner.parent(ctx, dir).await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        self.inner
            .readdir(ctx, dir, cookie, max_entries, with_attrs)
            .await
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        self.inner.read(ctx, handle, offset, count).await
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
    ) -> FsResult<WriteResult> {
        self.inner.write(ctx, handle, offset, data).await
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        self.inner.create(ctx, parent, name, req).await
    }

    async fn remove(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        self.inner.remove(ctx, parent, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        self.inner
            .rename(ctx, from_dir, from_name, to_dir, to_name)
            .await
    }

    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        self.inner.setattr(ctx, handle, attrs).await
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        self.inner.symlinks()
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> {
        self.inner.hard_links()
    }

    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> {
        Some(self)
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        self.inner.commit_support()
    }
}

#[async_trait::async_trait]
impl Xattrs<u64> for CountingNamedAttrFs {
    async fn list_xattrs(&self, ctx: &RequestContext, id: &u64) -> FsResult<Vec<String>> {
        self.list_count.fetch_add(1, Ordering::Relaxed);
        self.inner.list_xattrs(ctx, id).await
    }

    async fn get_xattr(&self, ctx: &RequestContext, id: &u64, name: &str) -> FsResult<Bytes> {
        self.inner.get_xattr(ctx, id, name).await
    }

    async fn set_xattr(
        &self,
        ctx: &RequestContext,
        id: &u64,
        name: &str,
        value: Bytes,
        mode: XattrSetMode,
    ) -> FsResult<()> {
        self.inner.set_xattr(ctx, id, name, value, mode).await
    }

    async fn remove_xattr(&self, ctx: &RequestContext, id: &u64, name: &str) -> FsResult<()> {
        self.inner.remove_xattr(ctx, id, name).await
    }
}

#[async_trait::async_trait]
impl FileSystem for FailPostMutationRootStatFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        self.inner.root()
    }

    fn capabilities(&self) -> embednfs::FsCapabilities {
        self.inner.capabilities()
    }

    fn limits(&self) -> embednfs::FsLimits {
        self.inner.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> {
        self.inner.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, id: &u64) -> FsResult<Attrs> {
        if *id == self.inner.root() {
            let call = self.root_stat_calls.fetch_add(1, Ordering::Relaxed);
            if call >= self.root_stat_limit {
                return Err(FsError::Io);
            }
        }
        self.inner.getattr(ctx, id).await
    }

    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        self.inner.access(ctx, handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        self.inner.lookup(ctx, parent, name).await
    }

    async fn parent(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        self.inner.parent(ctx, dir).await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        self.inner
            .readdir(ctx, dir, cookie, max_entries, with_attrs)
            .await
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        self.inner.read(ctx, handle, offset, count).await
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
    ) -> FsResult<WriteResult> {
        self.inner.write(ctx, handle, offset, data).await
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        self.inner.create(ctx, parent, name, req).await
    }

    async fn remove(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        self.inner.remove(ctx, parent, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        self.inner
            .rename(ctx, from_dir, from_name, to_dir, to_name)
            .await
    }

    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        self.inner.setattr(ctx, handle, attrs).await
    }
}

#[async_trait::async_trait]
impl FileSystem for FailFirstRootStatFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        self.inner.root()
    }

    fn capabilities(&self) -> embednfs::FsCapabilities {
        self.inner.capabilities()
    }

    fn limits(&self) -> embednfs::FsLimits {
        self.inner.limits()
    }

    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> {
        self.inner.statfs(ctx).await
    }

    async fn getattr(&self, ctx: &RequestContext, id: &u64) -> FsResult<Attrs> {
        if *id == self.inner.root() && self.root_stat_calls.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(FsError::Io);
        }
        self.inner.getattr(ctx, id).await
    }

    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        self.inner.access(ctx, handle, requested).await
    }

    async fn lookup(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        self.inner.lookup(ctx, parent, name).await
    }

    async fn parent(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        self.inner.parent(ctx, dir).await
    }

    async fn readdir(
        &self,
        ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        self.inner
            .readdir(ctx, dir, cookie, max_entries, with_attrs)
            .await
    }

    async fn read(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        self.inner.read(ctx, handle, offset, count).await
    }

    async fn write(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
    ) -> FsResult<WriteResult> {
        self.inner.write(ctx, handle, offset, data).await
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        self.inner.create(ctx, parent, name, req).await
    }

    async fn remove(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        self.inner.remove(ctx, parent, name).await
    }

    async fn rename(
        &self,
        ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        self.inner
            .rename(ctx, from_dir, from_name, to_dir, to_name)
            .await
    }

    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        self.inner.setattr(ctx, handle, attrs).await
    }
}

// ===== Attribute helpers =====

pub fn apple_readdirplus_bits() -> Vec<u32> {
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

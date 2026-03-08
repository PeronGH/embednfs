//! NFS operation encoders for integration tests.
#![allow(dead_code)]

use bytes::{BufMut, BytesMut};

use embednfs_proto::xdr::*;
use embednfs_proto::*;

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

pub fn encode_exchange_id() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]); // verifier
    encode_opaque(&mut buf, b"test-client");
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
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
    // fore channel attrs
    0u32.encode(&mut buf); // headerpadsize
    1_048_576u32.encode(&mut buf); // maxrequestsize
    1_048_576u32.encode(&mut buf); // maxresponsesize
    8192u32.encode(&mut buf); // maxresponsesize_cached
    16u32.encode(&mut buf); // maxoperations
    8u32.encode(&mut buf); // maxrequests
    0u32.encode(&mut buf); // rdma_ird count
    // back channel attrs
    0u32.encode(&mut buf); // headerpadsize
    4096u32.encode(&mut buf); // maxrequestsize
    4096u32.encode(&mut buf); // maxresponsesize
    0u32.encode(&mut buf); // maxresponsesize_cached
    2u32.encode(&mut buf); // maxoperations
    1u32.encode(&mut buf); // maxrequests
    0u32.encode(&mut buf); // rdma_ird count
    // callback
    0u32.encode(&mut buf); // cb_program
    1u32.encode(&mut buf); // sec_parms count
    0u32.encode(&mut buf); // AUTH_NONE
    buf.to_vec()
}

pub fn encode_sequence(sessionid: &[u8; 16], seq: u32, slot: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SEQUENCE.encode(&mut buf);
    buf.put_slice(sessionid);
    seq.encode(&mut buf);
    slot.encode(&mut buf);
    slot.encode(&mut buf); // highest_slotid
    false.encode(&mut buf); // cachethis
    buf.to_vec()
}

pub fn encode_putrootfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTROOTFH.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_putfh(fh: &NfsFh4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_PUTFH.encode(&mut buf);
    fh.encode(&mut buf);
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

pub fn encode_getfh() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_GETFH.encode(&mut buf);
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
    2u32.encode(&mut buf); // NF4DIR
    name.to_string().encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    buf.to_vec()
}

pub fn encode_open_create(name: &str, share_access: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    share_access.encode(&mut buf);
    OPEN4_SHARE_DENY_NONE.encode(&mut buf);
    0u64.encode(&mut buf);
    encode_opaque(&mut buf, b"test-owner");
    1u32.encode(&mut buf); // opentype=CREATE
    0u32.encode(&mut buf); // createmode=UNCHECKED4
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    0u32.encode(&mut buf); // claim=CLAIM_NULL
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_nocreate(name: &str, share_access: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    share_access.encode(&mut buf);
    OPEN4_SHARE_DENY_NONE.encode(&mut buf);
    0u64.encode(&mut buf);
    encode_opaque(&mut buf, b"test-owner");
    0u32.encode(&mut buf); // opentype=NOCREATE
    0u32.encode(&mut buf); // claim=CLAIM_NULL
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_confirm() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN_CONFIRM.encode(&mut buf);
    Stateid4::default().encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    buf.to_vec()
}

pub fn encode_read(stateid: &Stateid4, offset: u64, count: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_READ.encode(&mut buf);
    stateid.encode(&mut buf);
    offset.encode(&mut buf);
    count.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_write(stateid: &Stateid4, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_WRITE.encode(&mut buf);
    stateid.encode(&mut buf);
    offset.encode(&mut buf);
    FILE_SYNC4.encode(&mut buf);
    encode_opaque(&mut buf, data);
    buf.to_vec()
}

pub fn encode_close(stateid: &Stateid4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CLOSE.encode(&mut buf);
    0u32.encode(&mut buf); // seqid
    stateid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_commit() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_COMMIT.encode(&mut buf);
    0u64.encode(&mut buf); // offset
    0u32.encode(&mut buf); // count
    buf.to_vec()
}

pub fn encode_access(access_bits: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_ACCESS.encode(&mut buf);
    access_bits.encode(&mut buf);
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

pub fn encode_reclaim_complete() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_RECLAIM_COMPLETE.encode(&mut buf);
    false.encode(&mut buf); // one_fs
    buf.to_vec()
}

pub fn encode_secinfo_no_name() -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_SECINFO_NO_NAME.encode(&mut buf);
    0u32.encode(&mut buf); // SECINFO_STYLE4_CURRENT_FH
    buf.to_vec()
}

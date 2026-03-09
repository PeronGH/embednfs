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
    encode_exchange_id_with_name(b"test-client")
}

pub fn encode_exchange_id_with_name(name: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]);
    encode_opaque(&mut buf, name);
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    0u32.encode(&mut buf);
    0u32.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_exchange_id_with_flags(name: &[u8], flags: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]);
    encode_opaque(&mut buf, name);
    flags.encode(&mut buf);
    0u32.encode(&mut buf);
    0u32.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_exchange_id_with_mach_cred(name: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]);
    encode_opaque(&mut buf, name);
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    1u32.encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    0u32.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_exchange_id_with_ssv(
    name: &[u8],
    hash_algs: &[&[u8]],
    encr_algs: &[&[u8]],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_EXCHANGE_ID.encode(&mut buf);
    buf.put_slice(&[0u8; 8]);
    encode_opaque(&mut buf, name);
    EXCHGID4_FLAG_USE_NON_PNFS.encode(&mut buf);
    2u32.encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    (hash_algs.len() as u32).encode(&mut buf);
    for oid in hash_algs {
        encode_opaque(&mut buf, oid);
    }
    (encr_algs.len() as u32).encode(&mut buf);
    for oid in encr_algs {
        encode_opaque(&mut buf, oid);
    }
    4u32.encode(&mut buf);
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_create_session(clientid: u64, seq: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE_SESSION.encode(&mut buf);
    clientid.encode(&mut buf);
    seq.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    1_048_576u32.encode(&mut buf);
    1_048_576u32.encode(&mut buf);
    8192u32.encode(&mut buf);
    16u32.encode(&mut buf);
    8u32.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    0u32.encode(&mut buf);
    2u32.encode(&mut buf);
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_create_session_rpcsec_gss(
    clientid: u64,
    seq: u32,
    service: u32,
    handle_from_server: &[u8],
    handle_from_client: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE_SESSION.encode(&mut buf);
    clientid.encode(&mut buf);
    seq.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    1_048_576u32.encode(&mut buf);
    1_048_576u32.encode(&mut buf);
    8192u32.encode(&mut buf);
    16u32.encode(&mut buf);
    8u32.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    4096u32.encode(&mut buf);
    0u32.encode(&mut buf);
    2u32.encode(&mut buf);
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);

    0u32.encode(&mut buf);
    1u32.encode(&mut buf);
    6u32.encode(&mut buf);
    service.encode(&mut buf);
    encode_opaque(&mut buf, handle_from_server);
    encode_opaque(&mut buf, handle_from_client);
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
    slot.encode(&mut buf);
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

pub fn encode_open_create_guarded(name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf);
    OPEN4_SHARE_ACCESS_BOTH.encode(&mut buf);
    OPEN4_SHARE_DENY_NONE.encode(&mut buf);
    1u64.encode(&mut buf);
    encode_opaque(&mut buf, b"test-open-owner");
    1u32.encode(&mut buf);
    1u32.encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    0u32.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_create_with_access(name: &str, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf);
    share_access.encode(&mut buf);
    share_deny.encode(&mut buf);
    1u64.encode(&mut buf);
    encode_opaque(&mut buf, b"test-open-owner");
    1u32.encode(&mut buf);
    0u32.encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    0u32.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_nocreate_with_owner(name: &str, owner: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf);
    OPEN4_SHARE_ACCESS_BOTH.encode(&mut buf);
    OPEN4_SHARE_DENY_NONE.encode(&mut buf);
    1u64.encode(&mut buf);
    encode_opaque(&mut buf, owner);
    0u32.encode(&mut buf);
    0u32.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_nocreate(name: &str) -> Vec<u8> {
    encode_open_nocreate_with_access(name, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE)
}

pub fn encode_open_nocreate_with_access(name: &str, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf);
    share_access.encode(&mut buf);
    share_deny.encode(&mut buf);
    1u64.encode(&mut buf);
    encode_opaque(&mut buf, b"test-open-owner");
    0u32.encode(&mut buf);
    0u32.encode(&mut buf);
    name.to_string().encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_claim_previous(clientid: u64, deleg_type: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN.encode(&mut buf);
    0u32.encode(&mut buf);
    OPEN4_SHARE_ACCESS_BOTH.encode(&mut buf);
    OPEN4_SHARE_DENY_NONE.encode(&mut buf);
    clientid.encode(&mut buf);
    encode_opaque(&mut buf, b"test-reclaim-owner");
    0u32.encode(&mut buf);
    1u32.encode(&mut buf);
    deleg_type.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_close(stateid: &Stateid4) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CLOSE.encode(&mut buf);
    0u32.encode(&mut buf);
    stateid.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_open_downgrade(stateid: &Stateid4, share_access: u32, share_deny: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_OPEN_DOWNGRADE.encode(&mut buf);
    stateid.encode(&mut buf);
    0u32.encode(&mut buf);
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
    encode_create_type(2, name)
}

pub fn encode_create_type(objtype: u32, name: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE.encode(&mut buf);
    objtype.encode(&mut buf);
    name.to_string().encode(&mut buf);
    Bitmap4::new().encode(&mut buf);
    encode_opaque(&mut buf, &[]);
    buf.to_vec()
}

pub fn encode_create_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_CREATE.encode(&mut buf);
    5u32.encode(&mut buf);
    target.to_string().encode(&mut buf);
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
    0u32.encode(&mut buf);
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
    0u64.encode(&mut buf);
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
    true.encode(&mut buf);
    0u32.encode(&mut buf);
    open_stateid.encode(&mut buf);
    0u32.encode(&mut buf);
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
    false.encode(&mut buf);
    lock_stateid.encode(&mut buf);
    0u32.encode(&mut buf);
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
    0u32.encode(&mut buf);
    lock_stateid.encode(&mut buf);
    offset.encode(&mut buf);
    length.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_bind_conn_to_session(sessionid: &[u8; 16], dir: u32) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_BIND_CONN_TO_SESSION.encode(&mut buf);
    buf.put_slice(sessionid);
    dir.encode(&mut buf);
    false.encode(&mut buf);
    buf.to_vec()
}

pub fn encode_backchannel_ctl_rpcsec_gss(
    cb_program: u32,
    service: u32,
    handle_from_server: &[u8],
    handle_from_client: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();
    OP_BACKCHANNEL_CTL.encode(&mut buf);
    cb_program.encode(&mut buf);
    1u32.encode(&mut buf);
    6u32.encode(&mut buf);
    service.encode(&mut buf);
    encode_opaque(&mut buf, handle_from_server);
    encode_opaque(&mut buf, handle_from_client);
    buf.to_vec()
}

pub fn encode_auth_sys_body(machine_name: &str, gids: &[u32]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    0u32.encode(&mut buf);
    machine_name.to_string().encode(&mut buf);
    501u32.encode(&mut buf);
    20u32.encode(&mut buf);
    (gids.len() as u32).encode(&mut buf);
    for gid in gids {
        gid.encode(&mut buf);
    }
    buf.to_vec()
}

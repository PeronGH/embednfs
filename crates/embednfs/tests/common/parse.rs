//! NFS response parsers for integration tests.
#![allow(dead_code)]

use bytes::Bytes;

use embednfs_proto::xdr::*;
use embednfs_proto::*;

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

pub type ParsedReaddirBody = (usize, [u8; 8], Vec<(u64, String, Fattr4)>, bool);

pub fn parse_readdir_body(resp: &mut Bytes) -> ParsedReaddirBody {
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

pub fn skip_sequence_res(resp: &mut Bytes) {
    let _sessionid = decode_fixed_opaque(resp, 16).unwrap();
    let _sequenceid = u32::decode(resp).unwrap();
    let _slotid = u32::decode(resp).unwrap();
    let _highest_slotid = u32::decode(resp).unwrap();
    let _target_highest_slotid = u32::decode(resp).unwrap();
    let _status_flags = u32::decode(resp).unwrap();
}

pub fn parse_open_res(resp: &mut Bytes) -> Stateid4 {
    let stateid = Stateid4::decode(resp).unwrap();
    let _atomic = bool::decode(resp).unwrap();
    let _before = u64::decode(resp).unwrap();
    let _after = u64::decode(resp).unwrap();
    let _rflags = u32::decode(resp).unwrap();
    let _attrset = Bitmap4::decode(resp).unwrap();
    let deleg_type = u32::decode(resp).unwrap();
    if deleg_type == 3 {
        let _why = u32::decode(resp).unwrap();
    }
    stateid
}

pub fn parse_write_res(resp: &mut Bytes) -> u32 {
    let count = u32::decode(resp).unwrap();
    let _committed = u32::decode(resp).unwrap();
    let _verf = decode_fixed_opaque(resp, 8).unwrap();
    count
}

pub fn parse_read_res(resp: &mut Bytes) -> (bool, Vec<u8>) {
    let eof = bool::decode(resp).unwrap();
    let data = decode_opaque(resp).unwrap();
    (eof, data)
}

pub fn parse_getfh_res(resp: &mut Bytes) -> NfsFh4 {
    NfsFh4::decode(resp).unwrap()
}

pub fn apple_readdirplus_bits() -> Vec<u32> {
    vec![
        FATTR4_SUPPORTED_ATTRS, FATTR4_TYPE, FATTR4_FH_EXPIRE_TYPE,
        FATTR4_CHANGE, FATTR4_SIZE, FATTR4_LINK_SUPPORT, FATTR4_SYMLINK_SUPPORT,
        FATTR4_NAMED_ATTR, FATTR4_FSID, FATTR4_UNIQUE_HANDLES, FATTR4_LEASE_TIME,
        FATTR4_RDATTR_ERROR, FATTR4_FILEHANDLE, FATTR4_ACLSUPPORT, FATTR4_ARCHIVE,
        FATTR4_CANSETTIME, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING,
        FATTR4_CHOWN_RESTRICTED, FATTR4_FILEID, FATTR4_FILES_AVAIL, FATTR4_FILES_FREE,
        FATTR4_FILES_TOTAL, FATTR4_HIDDEN, FATTR4_HOMOGENEOUS, FATTR4_MAXFILESIZE,
        FATTR4_MAXLINK, FATTR4_MAXNAME, FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MODE,
        FATTR4_NO_TRUNC, FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP,
        FATTR4_RAWDEV, FATTR4_SPACE_AVAIL, FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL,
        FATTR4_SPACE_USED, FATTR4_SYSTEM, FATTR4_TIME_ACCESS, FATTR4_TIME_BACKUP,
        FATTR4_TIME_CREATE, FATTR4_TIME_DELTA, FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY,
        FATTR4_MOUNTED_ON_FILEID, FATTR4_SUPPATTR_EXCLCREAT,
    ]
}

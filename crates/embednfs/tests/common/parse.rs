use bytes::Bytes;

use embednfs_proto::xdr::*;
use embednfs_proto::*;

pub fn parse_lock_res(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

pub fn parse_locku_res(resp: &mut Bytes) -> Stateid4 {
    Stateid4::decode(resp).unwrap()
}

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

pub fn parse_rpc_auth_error(resp: &mut Bytes) -> (u32, u32) {
    let xid = u32::decode(resp).unwrap();
    let msg_type = u32::decode(resp).unwrap();
    assert_eq!(msg_type, 1, "expected RPC reply");
    let reply_stat = u32::decode(resp).unwrap();
    assert_eq!(reply_stat, 1, "expected rejected reply");
    let reject_stat = u32::decode(resp).unwrap();
    assert_eq!(reject_stat, 1, "expected AUTH_ERROR");
    let auth_stat = u32::decode(resp).unwrap();
    (xid, auth_stat)
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
    let _ = u32::decode(resp).unwrap();
    skip_bitmap(resp);
    let _ = u32::decode(resp).unwrap();
    stateid
}

pub fn parse_open_res(resp: &mut Bytes) -> (Stateid4, (bool, u64, u64)) {
    let stateid = parse_stateid(resp);
    let cinfo = parse_change_info(resp);
    let _ = u32::decode(resp).unwrap();
    skip_bitmap(resp);
    let _ = u32::decode(resp).unwrap();
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
    let _ = decode_fixed_opaque(resp, 8).unwrap();
    (count, committed)
}

pub fn parse_access_res(resp: &mut Bytes) -> (u32, u32) {
    let supported = u32::decode(resp).unwrap();
    let access = u32::decode(resp).unwrap();
    (supported, access)
}

pub fn skip_secinfo_entries(resp: &mut Bytes) -> u32 {
    let count = u32::decode(resp).unwrap();
    for _ in 0..count {
        let _ = u32::decode(resp).unwrap();
    }
    count
}

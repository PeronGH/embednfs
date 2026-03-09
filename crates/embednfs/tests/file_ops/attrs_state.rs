use super::*;

/// OPEN_DOWNGRADE from read-write access to read-only succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_opendowngrade.py` (CODE `OPDG1`).
/// RFC: RFC 8881 §18.18.3.
#[tokio::test]
async fn test_open_downgrade_updates_open_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create_with_access(
        "downgrade.txt",
        OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_DENY_NONE,
    );
    let compound = encode_compound("create-read-only", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate_with_access(
        "downgrade.txt",
        OPEN4_SHARE_ACCESS_BOTH,
        OPEN4_SHARE_DENY_NONE,
    );
    let compound = encode_compound("open-read-write", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let downgrade_op = encode_open_downgrade(
        &open_stateid,
        OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_DENY_NONE,
    );
    let compound = encode_compound("open-downgrade", &[&seq_op, &downgrade_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN_DOWNGRADE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let downgraded = parse_open_downgrade_res(&mut resp);
    assert_eq!(downgraded.other, open_stateid.other);
    assert_eq!(downgraded.seqid, open_stateid.seqid.wrapping_add(1));
}

/// SETATTR boolean flags round-trip through GETATTR.
/// Origin: implementation-specific attribute coverage.
/// RFC: RFC 8881 §18.30.3.
#[tokio::test]
async fn test_setattr_flags_round_trip() {
    let fs = populated_fs(&["flags.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("flags.txt");
    let setattr_op = encode_setattr_flags(true, true, true);
    let getattr_op = encode_getattr(&[FATTR4_ARCHIVE, FATTR4_HIDDEN, FATTR4_SYSTEM]);
    let compound = encode_compound(
        "setattr-flags",
        &[&seq_op, &rootfh_op, &lookup_op, &setattr_op, &getattr_op],
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
    skip_bitmap(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    assert!(bool::decode(&mut vals).unwrap());
    assert!(bool::decode(&mut vals).unwrap());
    assert!(bool::decode(&mut vals).unwrap());
}

/// SETATTR with truncated client time XDR returns `NFS4ERR_BADXDR`.
/// Origin: RFC- and decoder-driven malformed-XDR check.
/// RFC: RFC 8881 §18.30.3.
#[tokio::test]
async fn test_setattr_badxdr_for_truncated_client_time() {
    let fs = populated_fs(&["badxdr.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("badxdr.txt");
    let setattr_op = encode_setattr_truncated_client_mtime();
    let compound = encode_compound(
        "setattr-badxdr",
        &[&seq_op, &rootfh_op, &lookup_op, &setattr_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::BadXdr as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SETATTR);
    assert_eq!(op_status, NfsStat4::BadXdr as u32);
}

/// GETATTR on the root returns directory attributes.
/// Origin: RFC-driven root-attribute check.
/// RFC: RFC 8881 §18.7.3.
#[tokio::test]
async fn test_getattr_root_is_directory() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_TYPE, FATTR4_FILEID]);
    let compound = encode_compound("getattr-root", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut vals).unwrap();
    assert_eq!(file_type, NfsFtype4::Dir as u32);
    let fileid = u64::decode(&mut vals).unwrap();
    assert_ne!(fileid, 0);
}

/// GETATTR for `supported_attrs` returns a valid bitmap.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_getattr.py` (supported-attrs family).
/// RFC: RFC 8881 §18.7.3.
#[tokio::test]
async fn test_getattr_supported_attrs() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_SUPPORTED_ATTRS]);
    let compound = encode_compound("getattr-supported", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let supported = Bitmap4::decode(&mut vals).unwrap();
    assert!(supported.is_set(FATTR4_TYPE));
    assert!(supported.is_set(FATTR4_SIZE));
    assert!(supported.is_set(FATTR4_FILEID));
    assert!(supported.is_set(FATTR4_CHANGE));
}

/// GETATTR on a file returns the file size.
/// Origin: RFC-driven size-attribute check.
/// RFC: RFC 8881 §18.7.3.
#[tokio::test]
async fn test_getattr_file_size() {
    let fs = fs_with_data("sized.txt", b"1234567890").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("sized.txt");
    let getattr_op = encode_getattr(&[FATTR4_SIZE]);
    let compound = encode_compound(
        "getattr-size",
        &[&seq_op, &rootfh_op, &lookup_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 10);
}

/// ACCESS on the root directory returns meaningful directory access bits.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_access.py` (CODE `ACC1d`, `ACC2d`).
/// RFC: RFC 8881 §18.1.3.
#[tokio::test]
async fn test_access_on_root() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let access_op = encode_access(
        ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE,
    );
    let compound = encode_compound("access-root", &[&seq_op, &rootfh_op, &access_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_ACCESS);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (supported, access) = parse_access_res(&mut resp);
    assert_ne!(supported & ACCESS4_READ, 0);
    assert_ne!(supported & ACCESS4_LOOKUP, 0);
    assert_ne!(access & ACCESS4_READ, 0);
    assert_ne!(access & ACCESS4_LOOKUP, 0);
}

/// ACCESS on a regular file returns meaningful file access bits.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_access.py` (CODE `ACC1r`, `ACC2r`).
/// RFC: RFC 8881 §18.1.3.
#[tokio::test]
async fn test_access_on_file() {
    let fs = populated_fs(&["accessible.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("accessible.txt");
    let access_op = encode_access(ACCESS4_READ | ACCESS4_MODIFY | ACCESS4_EXTEND);
    let compound = encode_compound(
        "access-file",
        &[&seq_op, &rootfh_op, &lookup_op, &access_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_ACCESS);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (supported, access) = parse_access_res(&mut resp);
    assert_ne!(supported & ACCESS4_READ, 0);
    assert_ne!(access & ACCESS4_READ, 0);
}

/// TEST_STATEID distinguishes known and unknown stateids.
/// Origin: RFC-driven state-management check.
/// RFC: RFC 8881 §18.48.3.
#[tokio::test]
async fn test_test_stateid_reports_known_and_unknown_stateids() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("stateid.txt");
    let compound = encode_compound("open-for-teststateid", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);

    let bogus = Stateid4 {
        seqid: 1,
        other: [0x77; 12],
    };
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let test_stateid_op = encode_test_stateid(&[open_stateid, bogus]);
    let compound = encode_compound("teststateid", &[&seq_op, &test_stateid_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_TEST_STATEID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let results = parse_test_stateid_results(&mut resp);
    assert_eq!(
        results,
        vec![NfsStat4::Ok as u32, NfsStat4::BadStateid as u32]
    );
}

/// OPEN create synthesizes non-atomic change info when post-create attribute collection fails.
/// Origin: implementation-specific correctness check.
/// RFC: RFC 8881 §18.16.3.
#[tokio::test]
async fn test_open_create_synthesizes_non_atomic_change_info_when_after_attr_fails() {
    let fs = FailPostMutationRootStatFs {
        inner: MemFs::new(),
        root_stat_limit: 2,
        root_stat_calls: AtomicUsize::new(0),
    };
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("synth-change.txt");
    let compound = encode_compound("open-synth-cinfo", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_stateid, cinfo) = parse_open_res(&mut resp);
    assert!(!cinfo.0);
    assert_eq!(cinfo.2, cinfo.1.wrapping_add(1));
}

/// OPEN of an existing file fails cleanly when directory change info cannot be obtained.
/// Origin: implementation-specific correctness check.
/// RFC: RFC 8881 §18.16.3.
#[tokio::test]
async fn test_open_existing_fails_when_directory_change_info_is_unavailable() {
    let inner = populated_fs(&["existing.txt"]).await;
    let fs = FailFirstRootStatFs {
        inner,
        root_stat_calls: AtomicUsize::new(0),
    };
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("existing.txt");
    let compound = encode_compound(
        "open-existing-missing-cinfo",
        &[&seq_op, &rootfh_op, &open_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Io as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Io as u32);
}

/// SETATTR size truncates a file and GETATTR reflects the new size.
/// Origin: RFC-driven size-truncation check.
/// RFC: RFC 8881 §18.30.3.
#[tokio::test]
async fn test_setattr_truncate_file() {
    let fs = fs_with_data("trunc.txt", b"hello world!").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("trunc.txt");
    let setattr_op = encode_setattr_size(&Stateid4::default(), 5);
    let getattr_op = encode_getattr(&[FATTR4_SIZE]);
    let compound = encode_compound(
        "setattr-trunc",
        &[&seq_op, &rootfh_op, &lookup_op, &setattr_op, &getattr_op],
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
    assert_eq!(opnum, OP_SETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_bitmap(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 5);
}

/// SETATTR size zero truncates a file and subsequent READ returns empty data.
/// Origin: RFC-driven size-truncation check.
/// RFC: RFC 8881 §18.30.3.
#[tokio::test]
async fn test_setattr_truncate_to_zero_then_read() {
    let fs = fs_with_data("zero.txt", b"content").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("zero.txt");
    let setattr_op = encode_setattr_size(&Stateid4::default(), 0);
    let read_op = encode_read(0, 4096);
    let compound = encode_compound(
        "trunc-read",
        &[&seq_op, &rootfh_op, &lookup_op, &setattr_op, &read_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    skip_bitmap(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert!(data.is_empty());
}

/// OPEN with read-only share access allows subsequent READ.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_open.py` (read-only open behavior family).
/// RFC: RFC 8881 §18.16.3.
#[tokio::test]
async fn test_open_read_only_then_read() {
    let fs = fs_with_data("ro.txt", b"readonly data").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate("ro.txt");
    let read_op = encode_read(0, 4096);
    let compound = encode_compound("open-read", &[&seq_op, &rootfh_op, &open_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let _stateid = skip_open_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let _eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert_eq!(data, b"readonly data");
}

/// OPEN, CLOSE, and FREE_STATEID complete a valid stateid lifecycle.
/// Origin: RFC-driven state-management check.
/// RFC: RFC 8881 §18.38.3.
#[tokio::test]
async fn test_open_close_free_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("free-me.txt");
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let close_op = encode_close(&open_stateid);
    let compound = encode_compound("close", &[&seq_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let closed_stateid = parse_stateid(&mut resp);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let free_op = encode_free_stateid(&closed_stateid);
    let compound = encode_compound("free", &[&seq_op, &free_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_FREE_STATEID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// GETATTR with multiple attribute classes returns all requested values.
/// Origin: RFC-driven attribute-encoding check.
/// RFC: RFC 8881 §18.7.3.
#[tokio::test]
async fn test_getattr_multiple_attrs() {
    let fs = fs_with_data("multi.txt", b"hello").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("multi.txt");
    let getattr_op = encode_getattr(&[FATTR4_TYPE, FATTR4_SIZE]);
    let compound = encode_compound(
        "getattr-multi",
        &[&seq_op, &rootfh_op, &lookup_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    assert!(fattr.attrmask.is_set(FATTR4_TYPE));
    assert!(fattr.attrmask.is_set(FATTR4_SIZE));
    let mut vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut vals).unwrap();
    assert_eq!(file_type, NfsFtype4::Reg as u32);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 5);
}

/// GETATTR without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_getattr.py` (CODE `GATT2`).
/// RFC: RFC 8881 §18.7.3.
#[tokio::test]
async fn test_getattr_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound("getattr-nofh", &[&seq_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// GETATTR on the root can return fs-level attributes such as fsid and lease time.
/// Origin: RFC-driven filesystem-attribute check.
/// RFC: RFC 8881 §5.8, §18.7.3.
#[tokio::test]
async fn test_getattr_fs_level_attrs() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[
        FATTR4_FSID,
        FATTR4_MAXREAD,
        FATTR4_MAXWRITE,
        FATTR4_LEASE_TIME,
    ]);
    let compound = encode_compound("getattr-fs", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    assert!(!fattr.attr_vals.is_empty());
}

/// WRITE to a new file is reflected in subsequent GETATTR size results.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_write.py` (CODE `WRT1`, `WRT1b`) plus GETATTR verification.
/// RFC: RFC 8881 §18.32.3, §18.7.3.
#[tokio::test]
async fn test_write_then_getattr_confirms_size() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("sized.txt");
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let stateid = skip_open_res(&mut resp);

    let data = vec![0xABu8; 100];
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_op = encode_lookup("sized.txt");
    let write_op = encode_write(&stateid, 0, &data);
    let getattr_op = encode_getattr(&[FATTR4_SIZE]);
    let compound = encode_compound(
        "write-size",
        &[&seq_op, &rootfh_op, &lookup_op, &write_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_write_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 100);
}

/// ACCESS without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_access.py` (CODE `ACC3`).
/// RFC: RFC 8881 §18.1.3.
#[tokio::test]
async fn test_access_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let access_op = encode_access(ACCESS4_READ);
    let compound = encode_compound("access-nofh", &[&seq_op, &access_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// RENAME within the same directory succeeds.
/// Origin: RFC 8881 §18.26.3 same-directory rename behavior.
/// RFC: RFC 8881 §18.26.3.
#[tokio::test]
async fn test_rename_same_directory() {
    let fs = populated_fs(&["before.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let savefh_op = encode_savefh();
    let rename_op = encode_rename("before.txt", "after.txt");
    let compound = encode_compound(
        "rename-same-dir",
        &[&seq_op, &rootfh_op, &savefh_op, &rename_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_old = encode_lookup("before.txt");
    let compound = encode_compound("lookup-old", &[&seq_op, &rootfh_op, &lookup_old]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let lookup_new = encode_lookup("after.txt");
    let compound = encode_compound("lookup-new", &[&seq_op, &rootfh_op, &lookup_new]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

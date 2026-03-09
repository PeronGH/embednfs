use super::*;

/// SECINFO_NO_NAME on the root returns at least one security entry.
/// Origin: `pynfs/nfs4.1/server41tests/st_secinfo_no_name.py` (CODE `SECNN1`).
/// RFC: RFC 8881 §18.45.3.
#[tokio::test]
async fn test_secinfo_no_name_on_root() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let secinfo_op = encode_secinfo_no_name(0);
    let compound = encode_compound("secinfo-no-name", &[&seq_op, &rootfh_op, &secinfo_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SECINFO_NO_NAME);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let count = skip_secinfo_entries(&mut resp);
    assert!(count >= 1);
}

/// SECINFO_NO_NAME consumes the current filehandle on success.
/// Origin: `pynfs/nfs4.1/server41tests/st_secinfo_no_name.py` (CODE `SECNN2`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.45.3.
#[tokio::test]
async fn test_secinfo_no_name_consumes_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let secinfo_op = encode_secinfo_no_name(0);
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "secinfo-consume-fh",
        &[&seq_op, &rootfh_op, &secinfo_op, &getfh_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SECINFO_NO_NAME);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let count = skip_secinfo_entries(&mut resp);
    assert!(count >= 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// SECINFO_NO_NAME with `SECINFO_STYLE4_PARENT` on the root returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.1/server41tests/st_secinfo_no_name.py` (CODE `SECNN3`).
/// RFC: RFC 8881 §18.45.3.
#[tokio::test]
async fn test_secinfo_no_name_parent_of_root_returns_noent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let secinfo_op = encode_secinfo_no_name(1);
    let compound = encode_compound("secinfo-parent-root", &[&seq_op, &rootfh_op, &secinfo_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SECINFO_NO_NAME);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// SECINFO_NO_NAME with `SECINFO_STYLE4_PARENT` on a subdirectory succeeds.
/// Origin: `pynfs/nfs4.1/server41tests/st_secinfo_no_name.py` (CODE `SECNN4`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.45.3.
#[tokio::test]
async fn test_secinfo_no_name_parent_of_subdir_succeeds() {
    let fs = fs_with_subdir("subdir").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("subdir");
    let secinfo_op = encode_secinfo_no_name(1);
    let compound = encode_compound(
        "secinfo-parent-subdir",
        &[&seq_op, &rootfh_op, &lookup_op, &secinfo_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SECINFO_NO_NAME);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let count = u32::decode(&mut resp).unwrap();
    assert!(count >= 1);
}

/// VERIFY with matching attributes succeeds.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF1*` family).
/// RFC: RFC 8881 §18.31.3.
#[tokio::test]
async fn test_verify_matching_attrs_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound("get-type", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let fattr = Fattr4::decode(&mut resp).unwrap();

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let verify_op = encode_verify(&[FATTR4_TYPE], &fattr.attr_vals);
    let compound = encode_compound("verify-match", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// VERIFY with mismatching attributes returns `NFS4ERR_NOT_SAME`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF3*` family).
/// RFC: RFC 8881 §18.31.3.
#[tokio::test]
async fn test_verify_mismatching_attrs_returns_not_same() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let mut fake_vals = BytesMut::new();
    1u32.encode(&mut fake_vals);
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let verify_op = encode_verify(&[FATTR4_TYPE], &fake_vals);
    let compound = encode_compound("verify-mismatch", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotSame as u32);
}

/// VERIFY without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF4`).
/// RFC: RFC 8881 §18.31.3.
#[tokio::test]
async fn test_verify_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let verify_op = encode_verify(&[FATTR4_SIZE], &17u64.to_be_bytes());
    let compound = encode_compound("verify-nofh", &[&seq_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// VERIFY with a write-only attribute returns `NFS4ERR_INVAL`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF5*` family).
/// RFC: RFC 8881 §18.31.3.
#[tokio::test]
async fn test_verify_write_only_attr_invalid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let mut vals = BytesMut::new();
    0u32.encode(&mut vals);
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let verify_op = encode_verify(&[FATTR4_TIME_MODIFY_SET], &vals);
    let compound = encode_compound("verify-writeonly", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
}

/// VERIFY with an unsupported attribute returns `NFS4ERR_ATTRNOTSUPP`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF7*` family).
/// RFC: RFC 8881 §18.31.3.
#[tokio::test]
async fn test_verify_unsupported_attr_attrnotsupp() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let verify_op = encode_verify(&[255], &[]);
    let compound = encode_compound("verify-unsupported", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::AttrNotsupp as u32);
}

/// NVERIFY with matching attributes returns `NFS4ERR_SAME`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF1*` family).
/// RFC: RFC 8881 §18.15.3.
#[tokio::test]
async fn test_nverify_matching_attrs_returns_same() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound("get-type", &[&seq_op, &rootfh_op, &getattr_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let fattr = Fattr4::decode(&mut resp).unwrap();

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let nverify_op = encode_nverify(&[FATTR4_TYPE], &fattr.attr_vals);
    let compound = encode_compound("nverify-same", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Same as u32);
}

/// NVERIFY with mismatching attributes succeeds.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF2*` family).
/// RFC: RFC 8881 §18.15.3.
#[tokio::test]
async fn test_nverify_mismatching_attrs_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let mut fake_vals = BytesMut::new();
    1u32.encode(&mut fake_vals);
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let nverify_op = encode_nverify(&[FATTR4_TYPE], &fake_vals);
    let compound = encode_compound("nverify-diff", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// NVERIFY without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF4`).
/// RFC: RFC 8881 §18.15.3.
#[tokio::test]
async fn test_nverify_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let nverify_op = encode_nverify(&[FATTR4_SIZE], &17u64.to_be_bytes());
    let compound = encode_compound("nverify-nofh", &[&seq_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// NVERIFY with a write-only attribute returns `NFS4ERR_INVAL`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF5*` family).
/// RFC: RFC 8881 §18.15.3.
#[tokio::test]
async fn test_nverify_write_only_attr_invalid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let mut vals = BytesMut::new();
    0u32.encode(&mut vals);
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let nverify_op = encode_nverify(&[FATTR4_TIME_ACCESS_SET], &vals);
    let compound = encode_compound("nverify-writeonly", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
}

/// NVERIFY with an unsupported attribute returns `NFS4ERR_ATTRNOTSUPP`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF7*` family).
/// RFC: RFC 8881 §18.15.3.
#[tokio::test]
async fn test_nverify_unsupported_attr_attrnotsupp() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let nverify_op = encode_nverify(&[255], &[]);
    let compound = encode_compound("nverify-unsupported", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::AttrNotsupp as u32);
}

/// DELEGRETURN succeeds with a dummy stateid in the current stubbed implementation.
/// Origin: implementation-specific stub behavior.
/// RFC: RFC 8881 §18.6.
#[tokio::test]
async fn test_delegreturn_stub_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let deleg_op = encode_delegreturn(&Stateid4::default());
    let compound = encode_compound("delegreturn", &[&seq_op, &deleg_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DELEGRETURN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// DELEGPURGE succeeds in the current stubbed implementation.
/// Origin: implementation-specific stub behavior.
/// RFC: RFC 8881 §18.5.
#[tokio::test]
async fn test_delegpurge_stub_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let deleg_op = encode_delegpurge();
    let compound = encode_compound("delegpurge", &[&seq_op, &deleg_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DELEGPURGE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

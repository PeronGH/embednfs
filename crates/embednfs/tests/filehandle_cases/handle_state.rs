use super::*;

/// PUTROOTFH sets the current FH to the root.
/// Origin: `pynfs/nfs4.0/servertests/st_putrootfh.py` (CODE `ROOT1`).
/// RFC: RFC 8881 §18.21.
#[tokio::test]
async fn test_putrootfh_sets_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh_op = encode_getfh();
    let compound = encode_compound("putrootfh-getfh", &[&seq_op, &rootfh_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fh = parse_getfh(&mut resp);
    assert!(!fh.is_empty());
}

/// PUTROOTFH always returns the same filehandle for the root.
/// Origin: RFC 8881 §18.21; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.21.
#[tokio::test]
async fn test_putrootfh_consistent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let mut fhs = Vec::new();
    for i in 0u32..2 {
        let seq_op = encode_sequence(&sessionid, i + 1, 0);
        let rootfh_op = encode_putrootfh();
        let getfh_op = encode_getfh();
        let compound = encode_compound("rootfh", &[&seq_op, &rootfh_op, &getfh_op]);
        let mut resp = send_rpc(&mut stream, 3 + i, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, _) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Ok as u32);
        let _ = parse_op_header(&mut resp);
        skip_sequence_res(&mut resp);
        let _ = parse_op_header(&mut resp);
        let _ = parse_op_header(&mut resp);
        fhs.push(parse_getfh(&mut resp));
    }
    assert_eq!(fhs[0], fhs[1]);
}

/// PUTPUBFH sets a valid filehandle.
/// Origin: `pynfs/nfs4.0/servertests/st_putpubfh.py` (CODE `PUB1`).
/// RFC: RFC 8881 §18.20.
#[tokio::test]
async fn test_putpubfh_sets_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let pubfh_op = encode_putpubfh();
    let getfh_op = encode_getfh();
    let compound = encode_compound("putpubfh-getfh", &[&seq_op, &pubfh_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTPUBFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fh = parse_getfh(&mut resp);
    assert!(!fh.is_empty());
}

/// PUTFH with a valid filehandle succeeds.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_putfh.py` (CODE `PUTFH1*` family).
/// RFC: RFC 8881 §18.19.3.
#[tokio::test]
async fn test_putfh_valid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh_op = encode_getfh();
    let compound = encode_compound("get-root-fh", &[&seq_op, &rootfh_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let root_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&root_fh);
    let getfh_op = encode_getfh();
    let compound = encode_compound("putfh-valid", &[&seq_op, &putfh_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let echoed_fh = parse_getfh(&mut resp);
    assert_eq!(echoed_fh, root_fh);
}

/// PUTFH with an invalid filehandle returns `NFS4ERR_BADHANDLE`.
/// Origin: `pynfs/nfs4.1/server41tests/st_putfh.py` (CODE `PUTFH2`).
/// RFC: RFC 8881 §18.19.3.
#[tokio::test]
async fn test_putfh_bad_handle() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let putfh_op = encode_putfh(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let getfh_op = encode_getfh();
    let compound = encode_compound("putfh-bad", &[&seq_op, &putfh_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Badhandle as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTFH);
    assert_eq!(op_status, NfsStat4::Badhandle as u32);
}

/// GETFH without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_getfh.py` (CODE `GF9`).
/// RFC: RFC 8881 §18.8.3.
#[tokio::test]
async fn test_getfh_no_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let getfh_op = encode_getfh();
    let compound = encode_compound("getfh-nofh", &[&seq_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// SAVEFH + RESTOREFH round-trip preserves the filehandle.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_restorefh.py` (CODE `SVFH2*` family).
/// RFC: RFC 8881 §18.27.3, §18.28.3.
#[tokio::test]
async fn test_savefh_restorefh_roundtrip() {
    let fs = populated_fs(&["restore-test.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh_root = encode_getfh();
    let savefh_op = encode_savefh();
    let lookup_op = encode_lookup("restore-test.txt");
    let getfh_file = encode_getfh();
    let restorefh_op = encode_restorefh();
    let getfh_restored = encode_getfh();
    let compound = encode_compound(
        "restore-fh",
        &[
            &seq_op,
            &rootfh_op,
            &getfh_root,
            &savefh_op,
            &lookup_op,
            &getfh_file,
            &restorefh_op,
            &getfh_restored,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let root_fh = parse_getfh(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SAVEFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let file_fh = parse_getfh(&mut resp);
    assert_ne!(root_fh, file_fh);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_RESTOREFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let restored_fh = parse_getfh(&mut resp);
    assert_eq!(restored_fh, root_fh);
}

/// RESTOREFH without a prior SAVEFH returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_restorefh.py` (CODE `RSFH2`) to RFC 8881 §18.27.3 semantics.
/// RFC: RFC 8881 §18.27.3.
#[tokio::test]
async fn test_restorefh_without_save_fails() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let restorefh_op = encode_restorefh();
    let compound = encode_compound("restore-nosave", &[&seq_op, &restorefh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_RESTOREFH);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// SAVEFH without a current FH returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_savefh.py` (CODE `SVFH1`).
/// RFC: RFC 8881 §18.28.3.
#[tokio::test]
async fn test_savefh_no_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let savefh_op = encode_savefh();
    let compound = encode_compound("save-nofh", &[&seq_op, &savefh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SAVEFH);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

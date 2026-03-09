use super::*;

/// COMMIT after an `UNSTABLE4` write succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT1a`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_on_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("commit.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "open-for-commit",
        &[&seq_op, &rootfh_op, &open_op, &getfh_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let write_op = encode_write_with_stability(&stateid, 0, UNSTABLE4, b"unstable-data");
    let compound = encode_compound("write-unstable", &[&seq_op, &putfh_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_WRITE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (count, _) = parse_write_res(&mut resp);
    assert_eq!(count, 13);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit", &[&seq_op, &putfh_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_COMMIT);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let verf = decode_fixed_opaque(&mut resp, 8).unwrap();
    assert_eq!(verf.len(), 8);
}

/// COMMIT without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT3`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit-nofh", &[&seq_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// COMMIT on a directory returns `NFS4ERR_ISDIR`.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT2d`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_on_directory() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit-dir", &[&seq_op, &rootfh_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Isdir as u32);
}

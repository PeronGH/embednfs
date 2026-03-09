use super::*;

// ===== PUTROOTFH (pynfs ROOT) =====

/// LOOKUP of an existing file succeeds and changes current FH.
/// Origin: derived from maintained `pynfs/nfs4.1/server41tests/st_lookup.py` disabled `if 0:` block (CODE `LOOKFILE` family).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_existing_file() {
    let fs = populated_fs(&["hello.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh1 = encode_getfh();
    let lookup_op = encode_lookup("hello.txt");
    let getfh2 = encode_getfh();
    let compound = encode_compound(
        "lookup-file",
        &[&seq_op, &rootfh_op, &getfh1, &lookup_op, &getfh2],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp); // PUTROOTFH
    let _ = parse_op_header(&mut resp); // GETFH1
    let root_fh = parse_getfh(&mut resp);
    let _ = parse_op_header(&mut resp); // LOOKUP
    let _ = parse_op_header(&mut resp); // GETFH2
    let file_fh = parse_getfh(&mut resp);

    // The file FH should differ from root FH
    assert_ne!(root_fh, file_fh);
}

/// LOOKUP of a nonexistent name returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.1/server41tests/st_lookup.py` (CODE `LOOK2`).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_nonexistent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("no-such-file.txt");
    let compound = encode_compound("lookup-noent", &[&seq_op, &rootfh_op, &lookup_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// LOOKUP on a non-directory current filehandle returns `NFS4ERR_NOTDIR`.
/// Origin: maintained `pynfs/nfs4.1/server41tests/st_lookup.py` disabled `if 0:` block (CODE `LOOK5r`).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_on_file_returns_notdir() {
    let fs = populated_fs(&["regular.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup1 = encode_lookup("regular.txt");
    let lookup2 = encode_lookup("child"); // can't lookup inside a file
    let compound = encode_compound("lookup-notdir", &[&seq_op, &rootfh_op, &lookup1, &lookup2]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Notdir as u32);
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Notdir as u32);
}

/// LOOKUP without a current FH returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.1/server41tests/st_lookup.py` (CODE `LOOK1`).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let lookup_op = encode_lookup("anything");
    let compound = encode_compound("lookup-nofh", &[&seq_op, &lookup_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// LOOKUP with a zero-length name returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_lookup.py` (CODE `LOOK3`).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_zero_length_name() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("");
    let compound = encode_compound("lookup-empty", &[&seq_op, &rootfh_op, &lookup_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Inval as u32);
}

/// LOOKUP with a long component returns `NFS4ERR_NAMETOOLONG`.
/// Origin: `pynfs/nfs4.0/servertests/st_lookup.py` (CODE `LOOK4`).
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_name_too_long() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;
    let long_name = "x".repeat(300);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup(&long_name);
    let compound = encode_compound("lookup-long", &[&seq_op, &rootfh_op, &lookup_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nametoolong as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Nametoolong as u32);
}

/// LOOKUP of `.` and `..` returns `NFS4ERR_BADNAME`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_lookup.py` (CODE `LOOK8`) to our stricter RFC-targeted expectation.
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_dot_names_badname() {
    let fs = fs_with_subdir("subdir").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq, name) in [(3, 1, "."), (4, 2, "..")] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let lookup_dir = encode_lookup("subdir");
        let lookup_dot = encode_lookup(name);
        let compound = encode_compound(
            "lookup-dot",
            &[&seq_op, &rootfh_op, &lookup_dir, &lookup_dot],
        );
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Badname as u32);
        assert_eq!(num_results, 4);
        let _ = parse_op_header(&mut resp);
        skip_sequence_res(&mut resp);
        let _ = parse_op_header(&mut resp);
        let _ = parse_op_header(&mut resp);
        let (opnum, op_status) = parse_op_header(&mut resp);
        assert_eq!(opnum, OP_LOOKUP);
        assert_eq!(op_status, NfsStat4::Badname as u32);
    }
}

/// LOOKUP with malformed component XDR returns `NFS4ERR_BADXDR` or an RPC decode error.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_lookup.py` (CODE `LOOK10`) to our raw-RPC integration path.
/// RFC: RFC 8881 §18.13.3.
#[tokio::test]
async fn test_lookup_badxdr_malformed_component() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();

    let mut bad_lookup = BytesMut::new();
    OP_LOOKUP.encode(&mut bad_lookup);
    0xcccc_ccccu32.encode(&mut bad_lookup);
    bad_lookup.extend_from_slice(b"buggy");

    let compound = encode_compound("lookup-badxdr", &[&seq_op, &rootfh_op, &bad_lookup]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _tag, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::BadXdr as u32);
    assert_eq!(num_results, 0);
}

// ===== LOOKUPP (pynfs LOOKP) =====

/// LOOKUPP from root returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.1/server41tests/st_lookupp.py` (CODE `LKPP2`).
/// RFC: RFC 8881 §18.14.3.
#[tokio::test]
async fn test_lookupp_at_root() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh1 = encode_getfh();
    let lookupp_op = encode_lookupp();
    let getfh2 = encode_getfh();
    let compound = encode_compound(
        "lookupp-root",
        &[&seq_op, &rootfh_op, &getfh1, &lookupp_op, &getfh2],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _root_fh = parse_getfh(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUPP);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// LOOKUPP from a subdirectory returns the parent.
/// Origin: `pynfs/nfs4.1/server41tests/st_lookupp.py` (CODE `LKPP1d`).
/// RFC: RFC 8881 §18.14.3.
#[tokio::test]
async fn test_lookupp_from_subdir() {
    let fs = fs_with_subdir("subdir").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getfh1 = encode_getfh();
    let lookup_op = encode_lookup("subdir");
    let lookupp_op = encode_lookupp();
    let getfh2 = encode_getfh();
    let compound = encode_compound(
        "lookupp-subdir",
        &[
            &seq_op,
            &rootfh_op,
            &getfh1,
            &lookup_op,
            &lookupp_op,
            &getfh2,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let root_fh = parse_getfh(&mut resp);
    let _ = parse_op_header(&mut resp); // LOOKUP
    let _ = parse_op_header(&mut resp); // LOOKUPP
    let _ = parse_op_header(&mut resp); // GETFH
    let parent_fh = parse_getfh(&mut resp);

    assert_eq!(root_fh, parent_fh);
}

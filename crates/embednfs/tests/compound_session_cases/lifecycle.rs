use super::*;

/// DESTROY_SESSION on an unknown session returns `NFS4ERR_BADSESSION`.
/// Origin: RFC 8881 §18.37.3; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.37.3.
#[tokio::test]
async fn test_destroy_session_bad_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let fake_session = [0xAAu8; 16];
    let destroy_op = encode_destroy_session(&fake_session);
    let compound = encode_compound("destroy-bad", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadSession as u32);
}

/// After DESTROY_SESSION, subsequent SEQUENCE on that session must fail with `NFS4ERR_BADSESSION`.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_destroy_session.py` (CODE `DSESS1`).
/// RFC: RFC 8881 §18.37.3.
#[tokio::test]
async fn test_destroyed_session_cannot_be_used() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let destroy_op = encode_destroy_session(&sessionid);
    let compound = encode_compound("destroy", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("use-destroyed", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadSession as u32);
}

/// DESTROY_SESSION after SEQUENCE must be the final operation in the COMPOUND.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_session.py` (CODE `DSESS9004`).
/// RFC: RFC 8881 §18.37.3.
#[tokio::test]
async fn test_destroy_session_with_sequence_must_be_final_op() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let destroy_op = encode_destroy_session(&sessionid);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("dsess-not-final", &[&seq_op, &destroy_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotOnlyOp as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(op_status, NfsStat4::NotOnlyOp as u32);
}

/// DESTROY_SESSION without SEQUENCE must be the sole operation.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_session.py` (CODE `DSESS9005`).
/// RFC: RFC 8881 §18.37.3.
#[tokio::test]
async fn test_destroy_session_without_sequence_must_be_sole_op() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let destroy_op = encode_destroy_session(&sessionid);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("dsess-not-sole", &[&destroy_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotOnlyOp as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(op_status, NfsStat4::NotOnlyOp as u32);
}

/// DESTROY_CLIENTID succeeds for an unconfirmed client with no session.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID1`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_unconfirmed_without_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    let (clientid, _) = skip_exchange_id_res(&mut resp);

    let destroy_op = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// DESTROY_CLIENTID succeeds through a different client's session when the target client is unconfirmed.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID2`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_unconfirmed_via_other_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let exchange_id_op = encode_exchange_id_with_name(b"other-client");
    let compound = encode_compound("exid-other", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    let (clientid, _) = skip_exchange_id_res(&mut resp);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let destroy_op = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid-other", &[&seq_op, &destroy_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// DESTROY_CLIENTID with a non-existent client returns `NFS4ERR_STALE_CLIENTID`.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID3`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_stale() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let destroy_op = encode_destroy_clientid(0xDEADCAFE);
    let compound = encode_compound("dcid-stale", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::StaleClientid as u32);
}

/// DESTROY_CLIENTID with a non-existent client inside a session returns `NFS4ERR_STALE_CLIENTID`.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID4`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_stale_in_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let destroy_op = encode_destroy_clientid(0);
    let compound = encode_compound("dcid-stale-sess", &[&seq_op, &destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::StaleClientid as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::StaleClientid as u32);
}

/// DESTROY_CLIENTID using a session belonging to that client returns `NFS4ERR_CLIENTID_BUSY`.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID5`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_same_session_is_busy() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let destroy_op = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid-busy-same", &[&seq_op, &destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::ClientidBusy as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::ClientidBusy as u32);
}

/// DESTROY_CLIENTID without SEQUENCE returns `NFS4ERR_CLIENTID_BUSY` when the target client still has a session.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID6`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_without_sequence_is_busy_when_session_exists() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (_sessionid, clientid) = setup_session_full(&mut stream).await;

    let destroy_op = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid-busy", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::ClientidBusy as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::ClientidBusy as u32);
}

/// DESTROY_CLIENTID without SEQUENCE must be the sole operation.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID7`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_without_sequence_must_be_sole_op() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let destroy_op = encode_destroy_clientid(0);
    let rc_op = encode_reclaim_complete(true);
    let compound = encode_compound("dcid-not-only", &[&destroy_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotOnlyOp as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::NotOnlyOp as u32);
}

/// DESTROY_CLIENTID succeeds once and then returns `NFS4ERR_STALE_CLIENTID`.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_clientid.py` (CODE `DESCID8`).
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_twice() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    let (clientid, _) = skip_exchange_id_res(&mut resp);

    let destroy_op = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid-once", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let compound = encode_compound("dcid-twice", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::StaleClientid as u32);
}

/// RECLAIM_COMPLETE accepts both the file-system-specific and global forms.
/// Origin: `pynfs/nfs4.1/server41tests/st_reclaim_complete.py` (CODE `RECC1`).
/// RFC: RFC 8881 §18.51.3.
#[tokio::test]
async fn test_reclaim_complete() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let rc_one_fs_op = encode_reclaim_complete(true);

    let compound = encode_compound("reclaim-one-fs", &[&seq_op, &rootfh_op, &rc_one_fs_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rc_global_op = encode_reclaim_complete(false);
    let compound = encode_compound("reclaim-global", &[&seq_op, &rc_global_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
}

/// RECLAIM_COMPLETE prevents later reclaim opens for the same scope.
/// Origin: `pynfs/nfs4.1/server41tests/st_reclaim_complete.py` (CODE `RECC2`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.51.3.
#[tokio::test]
async fn test_reclaim_complete_blocks_late_reclaim_open() {
    let fs = populated_fs(&["reclaim.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rc_op = encode_reclaim_complete(false);
    let compound = encode_compound("recc", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("reclaim.txt");
    let open_op = encode_open_claim_previous(clientid, OpenDelegationType4::None as u32);
    let compound = encode_compound(
        "late-reclaim-open",
        &[&seq_op, &rootfh_op, &lookup_op, &open_op],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NoGrace as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::NoGrace as u32);
}

/// A second global RECLAIM_COMPLETE returns `NFS4ERR_COMPLETE_ALREADY`.
/// Origin: `pynfs/nfs4.1/server41tests/st_reclaim_complete.py` (CODE `RECC4`), confirmed against Apple NFS `kext/nfs4_vnops.c`.
/// RFC: RFC 8881 §18.51.4.
#[tokio::test]
async fn test_reclaim_complete_twice_returns_complete_already() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rc_op = encode_reclaim_complete(false);
    let compound = encode_compound("recc-once", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rc_op = encode_reclaim_complete(false);
    let compound = encode_compound("recc-twice", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::CompleteAlready as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_RECLAIM_COMPLETE);
    assert_eq!(op_status, NfsStat4::CompleteAlready as u32);
}

/// DESTROY_CLIENTID succeeds after all sessions for the client are gone.
/// Origin: RFC 8881 §18.50.3; no direct pynfs server41tests case.
/// RFC: RFC 8881 §18.50.3.
#[tokio::test]
async fn test_destroy_clientid_after_destroy_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let destroy_sess = encode_destroy_session(&sessionid);
    let compound = encode_compound("dsess", &[&destroy_sess]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let destroy_client = encode_destroy_clientid(clientid);
    let compound = encode_compound("dcid", &[&destroy_client]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_CLIENTID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

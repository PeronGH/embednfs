//! Tests for COMPOUND, EXCHANGE_ID, CREATE_SESSION, DESTROY_SESSION,
//! DESTROY_CLIENTID, SEQUENCE, and BIND_CONN_TO_SESSION operations.
//!
//! Adapted from pynfs st41 test suite (EXID, CSESS, SEQ, DSESS, DCID tests)
//! and Linux kernel NFS test infrastructure.

mod common;

use bytes::BytesMut;
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::*;

// ===== NULL procedure (pynfs COMP1) =====

/// pynfs COMP1: NULL procedure must return success with empty body.
#[tokio::test]
async fn test_null_procedure() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let mut resp = send_rpc(&mut stream, 1, 0, &[]).await;
    let (xid, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(xid, 1);
    assert_eq!(accept_stat, 0);
}

// ===== COMPOUND basics =====

/// pynfs COMP2: COMPOUND with minorversion != 1 must return NFS4ERR_MINOR_VERS_MISMATCH.
#[tokio::test]
async fn test_minor_version_mismatch_rejects_non_v41() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let rootfh_op = encode_putrootfh();

    for (xid, minorversion) in [(1, 0u32), (2, 2u32)] {
        let compound = encode_compound_minor("bad-minor", minorversion, &[&rootfh_op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        let (_, accept_stat) = parse_rpc_reply(&mut resp);
        assert_eq!(accept_stat, 0);

        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::MinorVersMismatch as u32);
        assert_eq!(num_results, 0);
    }
}

/// pynfs COMP6: Empty COMPOUND (zero ops) with minorversion=1 must succeed.
#[tokio::test]
async fn test_empty_compound_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let compound = encode_compound("empty", &[]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let (status, tag, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(tag, "empty");
    assert_eq!(num_results, 0);
}

/// COMPOUND tag must be echoed back in the response.
#[tokio::test]
async fn test_compound_tag_echo() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let compound = encode_compound("my-unique-tag-123", &[]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (_status, tag, _) = parse_compound_header(&mut resp);
    assert_eq!(tag, "my-unique-tag-123");
}

// ===== EXCHANGE_ID (pynfs EXID) =====

/// pynfs EXID1: Basic EXCHANGE_ID succeeds and returns a valid clientid.
#[tokio::test]
async fn test_exchange_id_basic() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_EXCHANGE_ID);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (clientid, sequenceid, flags) = parse_exchange_id_res(&mut resp);
    assert_ne!(clientid, 0);
    assert!(sequenceid > 0);
    // Server must echo USE_NON_PNFS or a subset
    assert_ne!(flags & EXCHGID4_FLAG_USE_NON_PNFS, 0);
}

/// pynfs EXID2: EXCHANGE_ID must NOT be preceded by SEQUENCE — must be NOT_ONLY_OP
/// if combined with other ops.
#[tokio::test]
async fn test_exchange_id_without_sequence_must_be_only_op() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("not-only-op", &[&exchange_id_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotOnlyOp as u32);
    assert_eq!(num_results, 1);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_EXCHANGE_ID);
    assert_eq!(op_status, NfsStat4::NotOnlyOp as u32);
}

/// pynfs EXID4: Re-sending EXCHANGE_ID with the same ownerid returns
/// EXCHGID4_FLAG_CONFIRMED_R on the second call.
#[tokio::test]
async fn test_exchange_id_confirmed_on_reissue() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    // First: exchange + create session to confirm
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid1", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let (clientid, sequenceid) = skip_exchange_id_res(&mut resp);

    let create_session_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("csess", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Second EXCHANGE_ID with the same owner
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid2", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let (clientid2, _seq2, flags2) = parse_exchange_id_res(&mut resp);
    assert_eq!(clientid2, clientid);
    assert_ne!(flags2 & EXCHGID4_FLAG_CONFIRMED_R, 0);
}

// ===== CREATE_SESSION (pynfs CSESS) =====

/// pynfs CSESS1: Full session establishment flow works.
#[tokio::test]
async fn test_v41_session_flow_and_readdir() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    let (_, accept_stat) = parse_rpc_reply(&mut resp);
    assert_eq!(accept_stat, 0);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs CSESS24: CREATE_SESSION with bad clientid returns NFS4ERR_STALE_CLIENTID.
#[tokio::test]
async fn test_create_session_stale_clientid() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let create_session_op = encode_create_session(0xDEADBEEF, 1);
    let compound = encode_compound("bad-csess", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE_SESSION);
    // Should be STALE_CLIENTID
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::StaleClientid as u32);
}

/// pynfs CSESS9: CREATE_SESSION with wrong sequenceid returns NFS4ERR_SEQ_MISORDERED.
#[tokio::test]
async fn test_create_session_wrong_sequenceid() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    // Get a real clientid first
    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let (clientid, sequenceid) = skip_exchange_id_res(&mut resp);

    // Use wrong sequence (sequenceid + 5 instead of sequenceid)
    let create_session_op = encode_create_session(clientid, sequenceid + 5);
    let compound = encode_compound("bad-seq", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE_SESSION);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::SeqMisordered as u32);
}

// ===== SEQUENCE (pynfs SEQ) =====

/// pynfs SEQ2: Fore-channel ops without SEQUENCE must return NFS4ERR_OP_NOT_IN_SESSION.
#[tokio::test]
async fn test_fore_channel_ops_require_sequence() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let _sessionid = setup_session(&mut stream).await;

    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("missing-sequence", &[&rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::OpNotInSession as u32);
    assert_eq!(num_results, 1);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::OpNotInSession as u32);
}

/// pynfs SEQ9: SEQUENCE must be the first op and must not appear more than once.
#[tokio::test]
async fn test_sequence_must_be_first_and_unique() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op1 = encode_sequence(&sessionid, 1, 0);
    let seq_op2 = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("sequence-pos", &[&seq_op1, &rootfh_op, &seq_op2]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::SequencePos as u32);
    assert_eq!(num_results, 3);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::SequencePos as u32);
}

/// pynfs SEQ3: SEQUENCE with a bad session ID must return NFS4ERR_BADSESSION.
#[tokio::test]
async fn test_sequence_bad_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let _sessionid = setup_session(&mut stream).await;

    let fake_session = [0xFFu8; 16];
    let seq_op = encode_sequence(&fake_session, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("bad-session", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadSession as u32);
}

/// pynfs SEQ4: SEQUENCE with seq_misordered (skipping a seqid).
#[tokio::test]
async fn test_sequence_misordered() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Skip seqid 1, go directly to 5
    let seq_op = encode_sequence(&sessionid, 5, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("misordered", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::SeqMisordered as u32);
}

/// pynfs SEQ6: Slot replay cache — exact replay returns cached response.
#[tokio::test]
async fn test_open_create_retry_replays_cached_reply() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence_with_cache(&sessionid, 1, 0, true);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("once.txt");
    let compound = encode_compound("open-create-retry", &[&seq_op, &rootfh_op, &open_op]);

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
    let first_stateid = skip_open_res(&mut resp);

    let mut retry_resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut retry_resp);
    let (status, _, num_results) = parse_compound_header(&mut retry_resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut retry_resp);
    skip_sequence_res(&mut retry_resp);
    let _ = parse_op_header(&mut retry_resp);
    let (opnum, op_status) = parse_op_header(&mut retry_resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let retry_stateid = skip_open_res(&mut retry_resp);
    assert_eq!(retry_stateid.seqid, first_stateid.seqid);
    assert_eq!(retry_stateid.other, first_stateid.other);
}

/// pynfs SEQ10: False retry — same seqid but different ops returns NFS4ERR_SEQ_FALSE_RETRY.
#[tokio::test]
async fn test_false_retry_returns_seq_false_retry() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound("false-retry-a", &[&seq_op, &rootfh_op, &getattr_op]);

    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let readdir_op = encode_readdir();
    let false_retry = encode_compound("false-retry-b", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut retry_resp = send_rpc(&mut stream, 4, 1, &false_retry).await;
    parse_rpc_reply(&mut retry_resp);
    let (status, _, num_results) = parse_compound_header(&mut retry_resp);
    assert_eq!(status, NfsStat4::SeqFalseRetry as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut retry_resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::SeqFalseRetry as u32);
}

/// Retry while the original request is still in progress returns NFS4ERR_DELAY.
#[tokio::test]
async fn test_retry_while_in_progress_returns_delay() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let inner = populated_fs(&["slow.txt"]).await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let fs = BlockingRemoveFs {
        inner,
        entered: entered.clone(),
        release: release.clone(),
    };
    let port = start_server_with_fs(fs).await;
    let mut stream1 = connect(port).await;
    let sessionid = setup_session(&mut stream1).await;
    let mut stream2 = connect(port).await;

    let seq_op = encode_sequence_with_cache(&sessionid, 1, 0, true);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("slow.txt");
    let compound = encode_compound("remove-delay", &[&seq_op, &rootfh_op, &remove_op]);

    let request = compound.clone();
    let handle = tokio::spawn(async move { send_rpc(&mut stream1, 3, 1, &request).await });
    entered.notified().await;

    let mut retry_resp = send_rpc(&mut stream2, 4, 1, &compound).await;
    parse_rpc_reply(&mut retry_resp);
    let (status, _, num_results) = parse_compound_header(&mut retry_resp);
    assert_eq!(status, NfsStat4::Delay as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut retry_resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Delay as u32);

    release.notify_waiters();
    let mut resp = handle.await.unwrap();
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// pynfs SEQ5: SEQUENCE with slot > highest_slot returns NFS4ERR_BADSLOT.
#[tokio::test]
async fn test_sequence_bad_slot() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Use a very high slot number
    let seq_op = encode_sequence(&sessionid, 1, 9999);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("bad-slot", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadSlot as u32);
}

// ===== DESTROY_SESSION (pynfs DSESS) =====

/// pynfs DSESS1: Destroy a valid session succeeds.
#[tokio::test]
async fn test_destroy_session_basic() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let destroy_op = encode_destroy_session(&sessionid);
    let compound = encode_compound("destroy-session", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs DSESS2: Destroy a non-existent session returns NFS4ERR_BADSESSION.
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

/// After destroying a session, SEQUENCE on it must fail with NFS4ERR_BADSESSION.
#[tokio::test]
async fn test_destroyed_session_cannot_be_used() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Destroy
    let destroy_op = encode_destroy_session(&sessionid);
    let compound = encode_compound("destroy", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Try to use destroyed session
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

// ===== DESTROY_CLIENTID (pynfs DCID) =====

/// pynfs DCID1: DESTROY_CLIENTID with a non-existent client returns NFS4ERR_STALE_CLIENTID.
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

// ===== RECLAIM_COMPLETE (pynfs RECC) =====

/// pynfs RECC1: RECLAIM_COMPLETE with one_fs=false succeeds.
#[tokio::test]
async fn test_reclaim_complete() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rc_op = encode_reclaim_complete(false);

    let compound = encode_compound("reclaim", &[&seq_op, &rc_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
}

// ===== V4.0-only ops must be rejected (pynfs CT) =====

/// pynfs CT3: NFSv4.0-only ops (OPEN_CONFIRM, RENEW, etc.) return NFS4ERR_NOTSUPP.
#[tokio::test]
async fn test_v40_only_op_is_not_supported_in_v41() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let open_confirm_op = encode_open_confirm();
    let compound = encode_compound("obsolete-op", &[&seq_op, &open_confirm_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Notsupp as u32);
    assert_eq!(num_results, 2);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN_CONFIRM);
    assert_eq!(op_status, NfsStat4::Notsupp as u32);
}

// ===== RPC-level malformed input =====

/// Malformed RPC (zero-length body) closes connection.
#[tokio::test]
async fn test_malformed_rpc_header_closes_connection() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    stream
        .write_all(&0x8000_0000u32.to_be_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 1];
    let bytes_read = tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes_read, 0);
}

/// pynfs COMP5: ILLEGAL operation returns NFS4ERR_OP_ILLEGAL.
#[tokio::test]
async fn test_illegal_op() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let illegal_op = encode_illegal();
    let compound = encode_compound("illegal", &[&seq_op, &illegal_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::OpIllegal as u32);
    assert_eq!(num_results, 2);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_ILLEGAL);
    assert_eq!(op_status, NfsStat4::OpIllegal as u32);
}

/// Truly unknown opcode (beyond any valid range) returns NFS4ERR_OP_ILLEGAL.
#[tokio::test]
async fn test_unknown_opcode_returns_illegal() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);

    // Encode a raw opcode that doesn't exist (99999)
    let mut bogus_buf = BytesMut::new();
    99999u32.encode(&mut bogus_buf);
    let bogus_op = bogus_buf.to_vec();

    let compound = encode_compound("unknown-op", &[&seq_op, &bogus_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    // Should fail on the unknown op
    assert!(num_results >= 2);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_ILLEGAL);
    assert_eq!(status, NfsStat4::OpIllegal as u32);
    assert_eq!(op_status, NfsStat4::OpIllegal as u32);
}

/// Multiple concurrent sessions can be created on the same client.
#[tokio::test]
async fn test_multiple_sessions_same_client() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("exid", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let (clientid, sequenceid) = skip_exchange_id_res(&mut resp);

    // First session
    let csess1 = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("csess1", &[&csess1]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let sid1 = parse_create_session_res(&mut resp);

    // Second session
    let csess2 = encode_create_session(clientid, sequenceid + 1);
    let compound = encode_compound("csess2", &[&csess2]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let sid2 = parse_create_session_res(&mut resp);

    // Both sessions should work
    assert_ne!(sid1, sid2);

    let seq_op = encode_sequence(&sid1, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("use-sid1", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sid2, 1, 0);
    let compound = encode_compound("use-sid2", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

// ===== BIND_CONN_TO_SESSION (pynfs BCTOS) =====

/// pynfs BCTOS1: BIND_CONN_TO_SESSION with a valid session succeeds.
#[tokio::test]
async fn test_bind_conn_to_session_basic() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let bind_op = encode_bind_conn_to_session(&sessionid, 0); // fore channel
    let compound = encode_compound("bind-conn", &[&bind_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_BIND_CONN_TO_SESSION);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs BCTOS2: BIND_CONN_TO_SESSION with bad session returns NFS4ERR_BADSESSION.
#[tokio::test]
async fn test_bind_conn_to_session_bad_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let fake_session = [0xBBu8; 16];
    let bind_op = encode_bind_conn_to_session(&fake_session, 0);
    let compound = encode_compound("bind-bad", &[&bind_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_BIND_CONN_TO_SESSION);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadSession as u32);
}

// ===== Multi-slot concurrent usage (pynfs SEQ) =====

/// Multiple slots can be used concurrently on the same session.
#[tokio::test]
async fn test_multiple_slots_concurrent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Use slot 0
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("slot0", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Use slot 1
    let seq_op = encode_sequence(&sessionid, 1, 1);
    let compound = encode_compound("slot1", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Advance slot 0 again
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let compound = encode_compound("slot0-again", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// EXCHANGE_ID with different client names creates distinct clients.
#[tokio::test]
async fn test_exchange_id_different_names_different_clients() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exid1 = encode_exchange_id_with_name(b"client-alpha");
    let compound = encode_compound("exid1", &[&exid1]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    let (clientid1, _) = skip_exchange_id_res(&mut resp);

    let exid2 = encode_exchange_id_with_name(b"client-beta");
    let compound = encode_compound("exid2", &[&exid2]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    let (clientid2, _) = skip_exchange_id_res(&mut resp);

    assert_ne!(clientid1, clientid2);
}

/// COMPOUND with long tag (up to 1024 chars per spec) echoes correctly.
#[tokio::test]
async fn test_compound_long_tag() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let long_tag: String = "x".repeat(256);
    let compound = encode_compound(&long_tag, &[]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (_status, tag, _) = parse_compound_header(&mut resp);
    assert_eq!(tag, long_tag);
}

/// DESTROY_CLIENTID after destroying all sessions succeeds.
#[tokio::test]
async fn test_destroy_clientid_after_destroy_session() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // Destroy the session
    let destroy_sess = encode_destroy_session(&sessionid);
    let compound = encode_compound("dsess", &[&destroy_sess]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Now destroy the client
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

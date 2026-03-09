//! Tests for COMPOUND, EXCHANGE_ID, CREATE_SESSION, DESTROY_SESSION,
//! DESTROY_CLIENTID, SEQUENCE, and BIND_CONN_TO_SESSION operations.
//!
//! This module mixes direct pynfs ports, RFC-derived checks, and
//! implementation-specific session/replay tests.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;

use bytes::BytesMut;
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::*;

// ===== NULL procedure (pynfs COMP1) =====

/// NULL procedure must return success with empty body.
/// Origin: RFC 8881 §17.1; no direct pynfs server41tests case.
/// RFC: RFC 8881 §17.1.
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

/// COMPOUND with minorversion != 1 must return NFS4ERR_MINOR_VERS_MISMATCH.
/// Origin: `pynfs/nfs4.1/server41tests/st_compound.py` (CODE `COMP4a`, `COMP4b`).
/// RFC: RFC 8881 §2.10.6.4.
#[tokio::test]
async fn test_minor_version_mismatch_rejects_non_v41() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let rootfh_op = encode_putrootfh();
    let illegal_op = encode_illegal();

    for (xid, minorversion, op) in [(1, 0u32, &rootfh_op[..]), (2, 2u32, &illegal_op[..])] {
        let compound = encode_compound_minor("bad-minor", minorversion, &[op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        let (_, accept_stat) = parse_rpc_reply(&mut resp);
        assert_eq!(accept_stat, 0);

        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::MinorVersMismatch as u32);
        assert_eq!(num_results, 0);
    }
}

/// Empty COMPOUND with minorversion=1 and zero ops must succeed.
/// Origin: `pynfs/nfs4.1/server41tests/st_compound.py` (CODE `COMP1`).
/// RFC: RFC 8881 §2.10.6.4.
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
/// Origin: `pynfs/nfs4.1/server41tests/st_compound.py` (CODE `COMP2`).
/// RFC: RFC 8881 §2.10.6.2.
#[tokio::test]
async fn test_compound_tag_echo() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let exchange_id_op = encode_exchange_id();
    let compound = encode_compound("my-unique-tag-123", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (_status, tag, _) = parse_compound_header(&mut resp);
    assert_eq!(tag, "my-unique-tag-123");
}

// ===== EXCHANGE_ID (pynfs EXID) =====

/// Basic EXCHANGE_ID succeeds and returns a valid clientid.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_exchange_id.py` (CODE `EID1`, `EID1a`).
/// RFC: RFC 8881 §18.35.3.
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
    assert_ne!(flags & EXCHGID4_FLAG_MASK_PNFS, 0);
}

/// EXCHANGE_ID must be the only op in a non-SEQUENCE COMPOUND.
/// Origin: `pynfs/nfs4.1/server41tests/st_exchange_id.py` (CODE `EID8`).
/// RFC: RFC 8881 §18.35.3.
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

/// Re-sending EXCHANGE_ID for a confirmed client returns the same client and sets `EXCHGID4_FLAG_CONFIRMED_R`.
/// Origin: RFC 8881 §18.35.3 confirmed-record handling; not a direct one-to-one pynfs case.
/// RFC: RFC 8881 §18.35.3.
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

/// Full session establishment flow works and the resulting session can service a simple fore-channel operation.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_create_session.py` (CODE `CSESS1`) plus READDIR coverage.
/// RFC: RFC 8881 §18.36.3.
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

/// CREATE_SESSION with an unknown clientid returns `NFS4ERR_STALE_CLIENTID`.
/// Origin: `pynfs/nfs4.1/server41tests/st_create_session.py` (CODE `CSESS3`).
/// RFC: RFC 8881 §18.36.3.
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

/// CREATE_SESSION with a too-large sequenceid returns `NFS4ERR_SEQ_MISORDERED`.
/// Origin: `pynfs/nfs4.1/server41tests/st_create_session.py` (CODE `CSESS7`).
/// RFC: RFC 8881 §18.36.3.
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

    let create_session_op = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("csess-good", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Use a too-large sequenceid after the successful CREATE_SESSION.
    let create_session_op = encode_create_session(clientid, sequenceid + 2);
    let compound = encode_compound("bad-seq", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE_SESSION);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::SeqMisordered as u32);
}

// ===== SEQUENCE (pynfs SEQ) =====

/// Fore-channel ops without SEQUENCE must return `NFS4ERR_OP_NOT_IN_SESSION`.
/// Origin: `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ11`).
/// RFC: RFC 8881 §18.46.3.
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

/// SEQUENCE must be the first op and must not appear more than once.
/// Origin: `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ2`) plus RFC 8881 duplicate-SEQUENCE enforcement.
/// RFC: RFC 8881 §18.46.3.
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

/// SEQUENCE with a bad session ID must return `NFS4ERR_BADSESSION`.
/// Origin: `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ5`).
/// RFC: RFC 8881 §18.46.3.
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

/// SEQUENCE with a misordered sequenceid must return `NFS4ERR_SEQ_MISORDERED`.
/// Origin: `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ13`).
/// RFC: RFC 8881 §18.46.3.
#[tokio::test]
async fn test_sequence_misordered() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_ok = encode_sequence(&sessionid, 1, 2);
    let compound = encode_compound("sequence-ok", &[&seq_ok]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_too_large = encode_sequence(&sessionid, 3, 2);
    let compound = encode_compound("misordered-high", &[&seq_too_large]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::SeqMisordered as u32);

    let seq_too_small = encode_sequence(&sessionid, 0, 2);
    let compound = encode_compound("misordered-low", &[&seq_too_small]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::SeqMisordered as u32);
}

/// Replaying a cached non-idempotent COMPOUND on the same slot returns the cached reply.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ9b`).
/// RFC: RFC 8881 §2.10.6.1.3.
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

/// Reusing a slot/seqid for a different request returns `NFS4ERR_SEQ_FALSE_RETRY`.
/// Origin: RFC 8881 §2.10.6.1.3.1; not a direct one-to-one pynfs case.
/// RFC: RFC 8881 §2.10.6.1.3.1.
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

/// Retrying while the original request is still in progress returns `NFS4ERR_DELAY`.
/// Origin: RFC 8881 §2.10.6.1.3; implementation-driven concurrency check.
/// RFC: RFC 8881 §2.10.6.1.3.
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

/// SEQUENCE with slot > highest_slot returns `NFS4ERR_BADSLOT`.
/// Origin: `pynfs/nfs4.1/server41tests/st_sequence.py` (CODE `SEQ8`).
/// RFC: RFC 8881 §18.46.3.
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

/// DESTROY_SESSION over an unbound connection fails until SEQUENCE binds the connection.
/// Origin: `pynfs/nfs4.1/server41tests/st_destroy_session.py` (CODE `DSESS9001`).
/// RFC: RFC 8881 §18.37.3.
#[tokio::test]
async fn test_destroy_session_basic() {
    let port = start_server().await;
    let mut stream1 = connect(port).await;
    let sessionid = setup_session(&mut stream1).await;
    let mut stream2 = connect(port).await;

    let destroy_op = encode_destroy_session(&sessionid);
    let compound = encode_compound("destroy-session", &[&destroy_op]);
    let mut resp = send_rpc(&mut stream2, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::ConnNotBoundToSession as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(op_status, NfsStat4::ConnNotBoundToSession as u32);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let seq_compound = encode_compound("bind-by-sequence", &[&seq_op]);
    let mut resp = send_rpc(&mut stream2, 4, 1, &seq_compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let mut resp = send_rpc(&mut stream2, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_DESTROY_SESSION);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

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

// ===== DESTROY_CLIENTID (pynfs DCID) =====

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

// ===== RECLAIM_COMPLETE (pynfs RECC) =====

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

// ===== V4.0-only ops must be rejected (pynfs CT) =====

/// NFSv4.0-only ops such as OPEN_CONFIRM must be rejected in NFSv4.1.
/// Origin: RFC 8881 mandatory-not-to-implement op semantics; not a direct pynfs server41tests case.
/// RFC: RFC 8881 §2.10.6.4.
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

/// Malformed RPC framing with a zero-length body closes the connection.
/// Origin: RFC 5531 §11 record marking; no direct pynfs case.
/// RFC: RFC 5531 §11.
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

/// ILLEGAL operation returns `NFS4ERR_OP_ILLEGAL`.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_compound.py` (CODE `COMP5`).
/// RFC: RFC 8881 §15.1.3.4.
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

/// A truly unknown opcode returns `NFS4ERR_OP_ILLEGAL`.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_compound.py` (CODE `COMP5`).
/// RFC: RFC 8881 §15.1.3.4.
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

/// Multiple sessions can be created on the same confirmed client.
/// Origin: derived from `pynfs/nfs4.1/server41tests/st_create_session.py` (CODE `CSESS2`, `CSESS2b`).
/// RFC: RFC 8881 §18.36.3.
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

    // Second session for the same client, created over the first session.
    let seq_op = encode_sequence(&sid1, 1, 0);
    let csess2 = encode_create_session(clientid, sequenceid + 1);
    let compound = encode_compound("csess2", &[&seq_op, &csess2]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);
    let (_, _) = parse_op_header(&mut resp);
    let sid2 = parse_create_session_res(&mut resp);

    // A different confirmed client can also CREATE_SESSION over sid1 (CSESS2b).
    let exchange_id_op = encode_exchange_id_with_name(b"second-client");
    let compound = encode_compound("exid2", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let (clientid2, sequenceid2) = skip_exchange_id_res(&mut resp);

    let seq_op = encode_sequence(&sid1, 2, 0);
    let csess3 = encode_create_session(clientid2, sequenceid2);
    let compound = encode_compound("csess3", &[&seq_op, &csess3]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);
    let (_, _) = parse_op_header(&mut resp);
    let sid3 = parse_create_session_res(&mut resp);

    assert_ne!(sid1, sid2);
    assert_ne!(sid2, sid3);

    let seq_op = encode_sequence(&sid1, 3, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("use-sid1", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sid2, 1, 0);
    let compound = encode_compound("use-sid2", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 7, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sid3, 1, 0);
    let compound = encode_compound("use-sid3", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 8, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

// ===== BIND_CONN_TO_SESSION (pynfs BCTOS) =====

/// BIND_CONN_TO_SESSION with a valid session succeeds.
/// Origin: RFC 8881 §18.34.3; no direct pynfs server41tests case.
/// RFC: RFC 8881 §18.34.3.
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

/// BIND_CONN_TO_SESSION with an unknown session returns `NFS4ERR_BADSESSION`.
/// Origin: RFC 8881 §18.34.3; no direct pynfs server41tests case.
/// RFC: RFC 8881 §18.34.3.
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
/// Origin: RFC 8881 §2.10.6.1; implementation-driven concurrency check.
/// RFC: RFC 8881 §2.10.6.1.
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

/// EXCHANGE_ID with different client owner strings creates distinct clients.
/// Origin: RFC 8881 §18.35.3 owner semantics; not a direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.35.3.
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

/// COMPOUND with a long tag echoes the tag correctly.
/// Origin: RFC 8881 §2.10.6.2; no direct pynfs case.
/// RFC: RFC 8881 §2.10.6.2.
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

/// DESTROY_CLIENTID succeeds after all sessions for the client are gone.
/// Origin: RFC 8881 §18.50.3; no direct pynfs server41tests case.
/// RFC: RFC 8881 §18.50.3.
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

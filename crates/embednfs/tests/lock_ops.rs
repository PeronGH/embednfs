//! Tests for lock operations: LOCK, LOCKT, LOCKU.
//!
//! Adapted from pynfs st41 (LOCK, LOCKT, LOCKU tests) and RFC 8881
//! section 18.10-18.12 lock semantics.

mod common;

use embednfs_proto::xdr::*;
use embednfs_proto::*;

use common::*;

// Lock type constants matching NfsLockType4 encoding
const READ_LT: u32 = 1;
const WRITE_LT: u32 = 2;
// const READW_LT: u32 = 3; // blocking read (not used in tests yet)
// const WRITEW_LT: u32 = 4; // blocking write (not used in tests yet)

// ===== LOCK (pynfs LOCK) =====

/// pynfs LOCK1: Acquire a write lock on a newly opened file.
#[tokio::test]
async fn test_lock_write_new_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // OPEN + CREATE a file
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("locktest.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "open-for-lock",
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
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    // LOCK the file (new lock owner)
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        u64::MAX, // entire file
        &open_stateid,
        b"test-lock-owner",
        clientid,
    );
    let compound = encode_compound("lock-write", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCK);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let lock_stateid = parse_lock_res(&mut resp);
    assert_ne!(lock_stateid.other, [0u8; 12]);
}

/// pynfs LOCK2: Acquire a read lock on a file.
#[tokio::test]
async fn test_lock_read_new_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("readlock.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open-readlock", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        READ_LT, false, 0, 1024, &open_stateid, b"read-lock-owner", clientid,
    );
    let compound = encode_compound("lock-read", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCK);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs LOCK8: LOCK without a current filehandle returns NFS4ERR_NOFILEHANDLE.
#[tokio::test]
async fn test_lock_no_filehandle() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    // No PUTFH — no current filehandle
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        u64::MAX,
        &Stateid4::default(),
        b"no-fh-owner",
        clientid,
    );
    let compound = encode_compound("lock-nofh", &[&seq_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

// ===== LOCKU (pynfs LOCKU) =====

/// pynfs LOCKU1: Unlock a previously locked region.
#[tokio::test]
async fn test_locku_after_lock() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // OPEN
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("unlock.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    // LOCK
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        u64::MAX,
        &open_stateid,
        b"unlock-owner",
        clientid,
    );
    let compound = encode_compound("lock", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let lock_stateid = parse_lock_res(&mut resp);

    // LOCKU
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let locku_op = encode_locku(WRITE_LT, &lock_stateid, 0, u64::MAX);
    let compound = encode_compound("unlock", &[&seq_op, &putfh_op, &locku_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCKU);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let _unlock_stateid = parse_locku_res(&mut resp);
}

/// pynfs LOCKU6: LOCKU with a bad stateid returns an error.
#[tokio::test]
async fn test_locku_bad_stateid() {
    let fs = populated_fs(&["locku-bad.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("locku-bad.txt");
    let bogus_stateid = Stateid4 {
        seqid: 99,
        other: [0xDD; 12],
    };
    let locku_op = encode_locku(WRITE_LT, &bogus_stateid, 0, u64::MAX);
    let compound = encode_compound(
        "locku-bad-stateid",
        &[&seq_op, &rootfh_op, &lookup_op, &locku_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    // Should fail with a stateid-related error (BadStateid or StaleStateid)
    assert_ne!(status, NfsStat4::Ok as u32);
}

// ===== LOCKT (pynfs LOCKT) =====

/// pynfs LOCKT1: LOCKT on an unlocked file succeeds (no conflict).
#[tokio::test]
async fn test_lockt_no_conflict() {
    let fs = populated_fs(&["lockt-test.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("lockt-test.txt");
    let lockt_op = encode_lockt(WRITE_LT, 0, u64::MAX, clientid, b"lockt-owner");
    let compound = encode_compound(
        "lockt-noconflict",
        &[&seq_op, &rootfh_op, &lookup_op, &lockt_op],
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
    assert_eq!(opnum, OP_LOCKT);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs LOCKT2: LOCKT detects a conflicting lock.
#[tokio::test]
async fn test_lockt_detects_conflict() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // OPEN + LOCK
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("conflict.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        u64::MAX,
        &open_stateid,
        b"holder-owner",
        clientid,
    );
    let compound = encode_compound("lock", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // LOCKT from a different owner — should detect conflict
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lockt_op = encode_lockt(WRITE_LT, 0, u64::MAX, clientid, b"other-owner");
    let compound = encode_compound("lockt-conflict", &[&seq_op, &putfh_op, &lockt_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Denied as u32);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCKT);
    assert_eq!(op_status, NfsStat4::Denied as u32);
}

/// pynfs LOCKT4: LOCKT without a current filehandle returns NFS4ERR_NOFILEHANDLE.
#[tokio::test]
async fn test_lockt_no_filehandle() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let lockt_op = encode_lockt(WRITE_LT, 0, u64::MAX, clientid, b"nofh-owner");
    let compound = encode_compound("lockt-nofh", &[&seq_op, &lockt_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

// ===== Lock + unlock + relock cycle =====

/// Full cycle: LOCK → LOCKU → LOCK again succeeds.
#[tokio::test]
async fn test_lock_unlock_relock_cycle() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // OPEN
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("relock.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    // LOCK
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        u64::MAX,
        &open_stateid,
        b"relock-owner",
        clientid,
    );
    let compound = encode_compound("lock1", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let lock_stateid = parse_lock_res(&mut resp);

    // LOCKU
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let locku_op = encode_locku(WRITE_LT, &lock_stateid, 0, u64::MAX);
    let compound = encode_compound("unlock", &[&seq_op, &putfh_op, &locku_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let unlock_stateid = parse_locku_res(&mut resp);

    // LOCK again using the existing lock owner
    let seq_op = encode_sequence(&sessionid, 4, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_existing(WRITE_LT, false, 0, u64::MAX, &unlock_stateid);
    let compound = encode_compound("relock", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCK);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// Lock a byte range, then test that a non-overlapping range has no conflict.
#[tokio::test]
async fn test_lockt_non_overlapping_range_no_conflict() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let (sessionid, clientid) = setup_session_full(&mut stream).await;

    // OPEN
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("range.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let open_stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    // LOCK bytes 0..1024
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lock_op = encode_lock_new(
        WRITE_LT,
        false,
        0,
        1024,
        &open_stateid,
        b"range-owner",
        clientid,
    );
    let compound = encode_compound("lock-range", &[&seq_op, &putfh_op, &lock_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // LOCKT bytes 2048..4096 from different owner — no conflict
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let lockt_op = encode_lockt(WRITE_LT, 2048, 2048, clientid, b"other-range-owner");
    let compound = encode_compound("lockt-noconflict", &[&seq_op, &putfh_op, &lockt_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOCKT);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

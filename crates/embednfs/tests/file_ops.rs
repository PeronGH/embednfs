//! Tests for file operations: OPEN, CLOSE, READ, WRITE, REMOVE, RENAME,
//! SETATTR, GETATTR, LINK, ACCESS, COMMIT, VERIFY, NVERIFY, TEST_STATEID,
//! FREE_STATEID, OPEN_DOWNGRADE.
//!
//! Adapted from pynfs st41 (OPEN, CLOSE, RD, WRT, RM, RNM, SATT, GATT,
//! LNK, ACC, FREESTATEID, TESTSTATEID tests) and Linux kernel NFS tests.

mod common;

use bytes::{Bytes, BytesMut};
use embednfs::MemFs;
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::sync::atomic::AtomicUsize;

use common::*;

// ===== OPEN + CLOSE (pynfs OPEN, CLOSE) =====

/// pynfs OPEN1: OPEN with CLAIM_NULL + OPEN4_CREATE creates a new file.
#[tokio::test]
async fn test_open_create_new_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("new-file.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "open-create",
        &[&seq_op, &rootfh_op, &open_op, &getfh_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let stateid = skip_open_res(&mut resp);
    assert_ne!(stateid.other, [0u8; 12]); // Valid stateid

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fh = parse_getfh(&mut resp);
    assert!(!fh.is_empty());
}

/// pynfs OPEN3: OPEN with OPEN4_NOCREATE on an existing file succeeds.
#[tokio::test]
async fn test_open_nocreate_existing_file() {
    let fs = populated_fs(&["existing.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate("existing.txt");
    let compound = encode_compound("open-nocreate", &[&seq_op, &rootfh_op, &open_op]);
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
}

/// pynfs OPEN4: OPEN with OPEN4_NOCREATE on a non-existent file returns NFS4ERR_NOENT.
#[tokio::test]
async fn test_open_nocreate_nonexistent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate("ghost.txt");
    let compound = encode_compound("open-noent", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
}

/// pynfs CLOSE1: CLOSE on a valid open stateid succeeds.
#[tokio::test]
async fn test_close_valid_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Open
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("close-test.txt");
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

    // Close
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let close_op = encode_close(&stateid);
    let compound = encode_compound("close", &[&seq_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CLOSE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// pynfs CLOSE2: CLOSE with a bogus stateid returns NFS4ERR_BAD_STATEID.
#[tokio::test]
async fn test_close_bad_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let bogus = Stateid4 {
        seqid: 999,
        other: [0xAA; 12],
    };
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let close_op = encode_close(&bogus);
    let compound = encode_compound("close-bad", &[&seq_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CLOSE);
    assert_eq!(status, op_status);
    assert_eq!(op_status, NfsStat4::BadStateid as u32);
}

// ===== READ (pynfs RD) =====

/// pynfs RD1: READ from a file with data returns the correct bytes.
#[tokio::test]
async fn test_read_file_data() {
    let fs = fs_with_data("data.txt", b"hello world").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("data.txt");
    let read_op = encode_read(0, 1024);
    let compound = encode_compound(
        "read-data",
        &[&seq_op, &rootfh_op, &lookup_op, &read_op],
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
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert_eq!(data, b"hello world");
}

/// pynfs RD4: READ from an empty file returns eof=true with empty data.
#[tokio::test]
async fn test_read_empty_file() {
    let fs = populated_fs(&["empty.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("empty.txt");
    let read_op = encode_read(0, 1024);
    let compound = encode_compound(
        "read-empty",
        &[&seq_op, &rootfh_op, &lookup_op, &read_op],
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
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert!(data.is_empty());
}

/// pynfs RD5: READ with offset beyond EOF returns eof=true with empty data.
#[tokio::test]
async fn test_read_beyond_eof() {
    let fs = fs_with_data("small.txt", b"hi").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("small.txt");
    let read_op = encode_read(1000, 1024);
    let compound = encode_compound(
        "read-beyond",
        &[&seq_op, &rootfh_op, &lookup_op, &read_op],
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
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert!(data.is_empty());
}

/// pynfs RD2: READ on a directory returns an error.
/// The RFC recommends NFS4ERR_ISDIR but our MemFs returns NFS4ERR_INVAL
/// since the FS layer rejects reads on non-file objects generically.
#[tokio::test]
async fn test_read_directory_returns_error() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let read_op = encode_read(0, 1024);
    let compound = encode_compound("read-dir", &[&seq_op, &rootfh_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(status, op_status);
    // MemFs returns INVAL for read on non-file objects
    assert_eq!(op_status, NfsStat4::Inval as u32);
}

// ===== WRITE (pynfs WRT) =====

/// pynfs WRT1: WRITE to a file with an open stateid succeeds.
#[tokio::test]
async fn test_write_and_read_back() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Open + Write
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("write-test.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "open-write",
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

    // Write
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let write_op = encode_write(&stateid, 0, b"test data 12345");
    let compound = encode_compound("write", &[&seq_op, &putfh_op, &write_op]);
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
    let (count, _committed) = parse_write_res(&mut resp);
    assert_eq!(count, 15);

    // Read back
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let read_op = encode_read(0, 1024);
    let compound = encode_compound("readback", &[&seq_op, &putfh_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert_eq!(data, b"test data 12345");
}

/// pynfs WRT4: WRITE at a non-zero offset works correctly.
#[tokio::test]
async fn test_write_at_offset() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Create & open
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("offset.txt");
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
    let stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    // Write "AAAA" at offset 0
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let write_op = encode_write(&stateid, 0, b"AAAA");
    let compound = encode_compound("w1", &[&seq_op, &putfh_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Write "BB" at offset 2
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let write_op = encode_write(&stateid, 2, b"BB");
    let compound = encode_compound("w2", &[&seq_op, &putfh_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // Read back: should be "AABB"
    let seq_op = encode_sequence(&sessionid, 4, 0);
    let read_op = encode_read(0, 1024);
    let compound = encode_compound("read", &[&seq_op, &putfh_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert_eq!(data, b"AABB");
}

// ===== REMOVE (pynfs RM) =====

/// pynfs RM1: REMOVE of an existing file succeeds.
#[tokio::test]
async fn test_remove_existing_file() {
    let fs = populated_fs(&["doomed.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("doomed.txt");
    let compound = encode_compound("remove", &[&seq_op, &rootfh_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_change_info(&mut resp);

    // Verify it's gone
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_op = encode_lookup("doomed.txt");
    let compound = encode_compound("verify-gone", &[&seq_op, &rootfh_op, &lookup_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
}

/// pynfs RM2: REMOVE of a non-existent name returns NFS4ERR_NOENT.
#[tokio::test]
async fn test_remove_nonexistent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("ghost.txt");
    let compound = encode_compound("rm-noent", &[&seq_op, &rootfh_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
}

/// pynfs RM6: Remove retry replays cached reply.
#[tokio::test]
async fn test_remove_retry_replays_cached_reply() {
    let fs = populated_fs(&["remove-me.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence_with_cache(&sessionid, 1, 0, true);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("remove-me.txt");
    let compound = encode_compound("remove-retry", &[&seq_op, &rootfh_op, &remove_op]);

    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let mut retry_resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut retry_resp);
    let (status, _, num_results) = parse_compound_header(&mut retry_resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut retry_resp);
    skip_sequence_res(&mut retry_resp);
    let _ = parse_op_header(&mut retry_resp);
    let (opnum, op_status) = parse_op_header(&mut retry_resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

// ===== RENAME (pynfs RNM) =====

/// pynfs RNM1: RENAME of an existing file to a new name succeeds.
#[tokio::test]
async fn test_rename_file() {
    let fs = populated_fs(&["old-name.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let savefh_op = encode_savefh();
    let rename_op = encode_rename("old-name.txt", "new-name.txt");
    let compound = encode_compound(
        "rename",
        &[&seq_op, &rootfh_op, &savefh_op, &rename_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp); // PUTROOTFH
    let _ = parse_op_header(&mut resp); // SAVEFH
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_RENAME);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    // Verify old name is gone, new name exists
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_old = encode_lookup("old-name.txt");
    let compound = encode_compound("check-old", &[&seq_op, &rootfh_op, &lookup_old]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let lookup_new = encode_lookup("new-name.txt");
    let compound = encode_compound("check-new", &[&seq_op, &rootfh_op, &lookup_new]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// pynfs RNM2: RENAME of a non-existent source returns NFS4ERR_NOENT.
#[tokio::test]
async fn test_rename_nonexistent_source() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let savefh_op = encode_savefh();
    let rename_op = encode_rename("no-such.txt", "target.txt");
    let compound = encode_compound(
        "rename-noent",
        &[&seq_op, &rootfh_op, &savefh_op, &rename_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
}

// ===== OPEN_DOWNGRADE (pynfs OPDG) =====

/// pynfs OPDG1: OPEN_DOWNGRADE from READ+WRITE to READ-only succeeds.
#[tokio::test]
async fn test_open_downgrade_updates_open_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("downgrade.txt");
    let compound = encode_compound("open-for-downgrade", &[&seq_op, &rootfh_op, &open_op]);
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
    let downgrade_op = encode_open_downgrade(
        &open_stateid,
        OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_DENY_NONE,
    );
    let compound = encode_compound("open-downgrade", &[&seq_op, &downgrade_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
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

// ===== SETATTR (pynfs SATT) =====

/// pynfs SATT1: SETATTR boolean flags round-trip.
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

/// pynfs SATT3: SETATTR with truncated/bad XDR returns NFS4ERR_BADXDR.
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

// ===== GETATTR (pynfs GATT) =====

/// pynfs GATT1: GETATTR on root returns valid type=DIR and fileid.
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

/// pynfs GATT3: GETATTR for supported_attrs returns a valid bitmap.
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
    // At minimum: type, size, fileid, change should be supported
    assert!(supported.is_set(FATTR4_TYPE));
    assert!(supported.is_set(FATTR4_SIZE));
    assert!(supported.is_set(FATTR4_FILEID));
    assert!(supported.is_set(FATTR4_CHANGE));
}

/// pynfs GATT5: GETATTR on a file returns size matching what was written.
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

// ===== ACCESS (pynfs ACC) =====

/// pynfs ACC1: ACCESS on root directory returns read/lookup access.
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
    // Should support at least READ and LOOKUP on a directory
    assert_ne!(supported & ACCESS4_READ, 0);
    assert_ne!(supported & ACCESS4_LOOKUP, 0);
    assert_ne!(access & ACCESS4_READ, 0);
    assert_ne!(access & ACCESS4_LOOKUP, 0);
}

/// pynfs ACC2: ACCESS on a regular file returns read/modify.
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

// ===== TEST_STATEID (pynfs TSID) =====

/// pynfs TSID1: TEST_STATEID with known and unknown stateids.
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

// ===== OPEN change info (edge cases from existing tests) =====

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

// ===== SECINFO_NO_NAME =====

/// pynfs SINN1: SECINFO_NO_NAME on root returns at least one security entry.
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
    let count = u32::decode(&mut resp).unwrap();
    assert!(count >= 1);
}

// ===== VERIFY / NVERIFY (pynfs VF, NVF) =====

/// pynfs VF1: VERIFY with matching attrs succeeds (NFS4_OK).
#[tokio::test]
async fn test_verify_matching_attrs_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // First, get the actual type of root
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

    // Now VERIFY with the same values
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let verify_op = encode_verify(&[FATTR4_TYPE], &fattr.attr_vals);
    let compound = encode_compound("verify-match", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// pynfs VF2: VERIFY with non-matching attrs returns NFS4ERR_NOT_SAME.
#[tokio::test]
async fn test_verify_mismatching_attrs_returns_not_same() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Encode type=REG (1) but root is DIR (2)
    let mut fake_vals = BytesMut::new();
    1u32.encode(&mut fake_vals); // NF4REG
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let verify_op = encode_verify(&[FATTR4_TYPE], &fake_vals);
    let compound = encode_compound("verify-mismatch", &[&seq_op, &rootfh_op, &verify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotSame as u32);
}

/// pynfs NVF1: NVERIFY with matching attrs returns NFS4ERR_SAME.
#[tokio::test]
async fn test_nverify_matching_attrs_returns_same() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Get actual type
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

    // NVERIFY with same values => NFS4ERR_SAME
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let nverify_op = encode_nverify(&[FATTR4_TYPE], &fattr.attr_vals);
    let compound = encode_compound("nverify-same", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Same as u32);
}

/// pynfs NVF2: NVERIFY with non-matching attrs succeeds (NFS4_OK).
#[tokio::test]
async fn test_nverify_mismatching_attrs_succeeds() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Encode type=REG (1) but root is DIR (2) — different
    let mut fake_vals = BytesMut::new();
    1u32.encode(&mut fake_vals); // NF4REG
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let nverify_op = encode_nverify(&[FATTR4_TYPE], &fake_vals);
    let compound = encode_compound("nverify-diff", &[&seq_op, &rootfh_op, &nverify_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

// ===== SETATTR truncate (pynfs SATT) =====

/// pynfs SATT4: SETATTR size truncates file and GETATTR reflects new size.
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
    skip_bitmap(&mut resp); // attrsset

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 5);
}

/// SETATTR size=0 empties the file, then READ returns empty.
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

// ===== OPEN share modes (pynfs OPEN) =====

/// pynfs OPEN9: OPEN with SHARE_ACCESS_READ only, then READ succeeds.
#[tokio::test]
async fn test_open_read_only_then_read() {
    let fs = fs_with_data("ro.txt", b"readonly data").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // OPEN with read-only access (NOCREATE)
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

/// OPEN + CLOSE + FREE_STATEID cycle.
#[tokio::test]
async fn test_open_close_free_stateid() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // OPEN
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

    // CLOSE
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

    // FREE_STATEID
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

// ===== GETATTR edge cases =====

/// GETATTR with multiple attribute classes returns all requested.
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
    // Verify the bitmap indicates the attrs we asked for
    assert!(fattr.attrmask.is_set(FATTR4_TYPE));
    assert!(fattr.attrmask.is_set(FATTR4_SIZE));
    // Decode values in bitmap order: type (u32), size (u64)
    let mut vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut vals).unwrap();
    assert_eq!(file_type, NfsFtype4::Reg as u32);
    let size = u64::decode(&mut vals).unwrap();
    assert_eq!(size, 5);
}

/// GETATTR without current filehandle returns NFS4ERR_NOFILEHANDLE.
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

/// GETATTR for fs-level attributes on root (fsid, space, etc).
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
    // Should have returned the requested attributes
    assert!(!fattr.attr_vals.is_empty());
}

// ===== WRITE edge cases =====

/// WRITE to a new file, then GETATTR confirms the size.
#[tokio::test]
async fn test_write_then_getattr_confirms_size() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // OPEN + CREATE
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

    // WRITE 100 bytes
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

/// ACCESS without current filehandle returns NFS4ERR_NOFILEHANDLE.
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

/// RENAME within same directory.
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

    // Verify old name gone, new name exists
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

/// DELEGRETURN with a dummy stateid succeeds (our server stubs it as OK).
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

/// DELEGPURGE stub succeeds.
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

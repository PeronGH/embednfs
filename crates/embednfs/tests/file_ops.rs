//! Tests for file operations: OPEN, CLOSE, READ, WRITE, REMOVE, RENAME,
//! SETATTR, GETATTR, LINK, ACCESS, COMMIT, VERIFY, NVERIFY, TEST_STATEID,
//! FREE_STATEID, OPEN_DOWNGRADE.
//!
//! This module mixes pynfs-derived core file-operation coverage with
//! RFC-driven and implementation-specific state and error-path tests.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;

use bytes::{Bytes, BytesMut};
use embednfs::{CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs};
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::sync::atomic::AtomicUsize;

use common::*;

// ===== OPEN + CLOSE (pynfs OPEN, CLOSE) =====

/// OPEN with `CLAIM_NULL` and `OPEN4_CREATE` creates a new file.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_open.py` (CODE `MKFILE`).
/// RFC: RFC 8881 §18.16.3.
#[tokio::test]
async fn test_open_create_new_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("new-file.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open-create", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
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

/// OPEN with `OPEN4_NOCREATE` on an existing file succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_open.py` (CODE `OPEN5`).
/// RFC: RFC 8881 §18.16.3.
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

/// OPEN with `OPEN4_NOCREATE` on a non-existent file returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.0/servertests/st_open.py` (CODE `OPEN6`).
/// RFC: RFC 8881 §18.16.3.
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

/// CLOSE on a valid open stateid succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_close.py` (CODE `CLOSE1`).
/// RFC: RFC 8881 §18.2.3.
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

/// CLOSE with a bogus stateid returns `NFS4ERR_BAD_STATEID`.
/// Origin: `pynfs/nfs4.0/servertests/st_close.py` (CODE `CLOSE4`).
/// RFC: RFC 8881 §18.2.3.
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

/// READ from a file with data returns the correct bytes.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_read.py` (CODE `RD1`).
/// RFC: RFC 8881 §18.22.3.
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
    let compound = encode_compound("read-data", &[&seq_op, &rootfh_op, &lookup_op, &read_op]);
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

/// READ from an empty file returns EOF with empty data.
/// Origin: RFC- and implementation-driven empty-file check.
/// RFC: RFC 8881 §18.22.3.
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
    let compound = encode_compound("read-empty", &[&seq_op, &rootfh_op, &lookup_op, &read_op]);
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

/// READ with an offset beyond EOF returns EOF with empty data.
/// Origin: `pynfs/nfs4.0/servertests/st_read.py` (CODE `RD5`).
/// RFC: RFC 8881 §18.22.3.
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
    let compound = encode_compound("read-beyond", &[&seq_op, &rootfh_op, &lookup_op, &read_op]);
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

/// READ on a directory returns `NFS4ERR_ISDIR`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_read.py` (CODE `RD7d`).
/// RFC: RFC 8881 §18.22.3.
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
    assert_eq!(op_status, NfsStat4::Isdir as u32);
}

// ===== WRITE (pynfs WRT) =====

/// WRITE to a file with an open stateid succeeds and the data can be read back.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_write.py` (CODE `WRT3`).
/// RFC: RFC 8881 §18.32.3.
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
    let compound = encode_compound("open-write", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
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

/// WRITE beyond EOF preserves a hole before the written bytes.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_write.py` (CODE `WRT1b`).
/// RFC: RFC 8881 §18.32.3.
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

    // Write beyond EOF.
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let write_op = encode_write(&stateid, 30, b"write data");
    let compound = encode_compound("write-hole", &[&seq_op, &putfh_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let read_op = encode_read(25, 20);
    let compound = encode_compound("read-hole", &[&seq_op, &putfh_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert_eq!(data, b"\0\0\0\0\0write data");
}

// ===== REMOVE (pynfs RM) =====

/// REMOVE of an existing file succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM1r`).
/// RFC: RFC 8881 §18.25.3.
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

/// REMOVE of a non-existent name returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM6`).
/// RFC: RFC 8881 §18.25.3.
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

/// Retrying REMOVE on the same cached slot replays the cached reply.
/// Origin: RFC 8881 replay-cache semantics; implementation-driven check.
/// RFC: RFC 8881 §2.10.6.1.3, §18.25.3.
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

/// RENAME of an existing file across directories succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_rename.py` (CODE `RNM1r`).
/// RFC: RFC 8881 §18.26.3.
#[tokio::test]
async fn test_rename_file() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let dir1 = fs
        .create(
            &ctx,
            &1,
            "dir1",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    let _dir2 = fs
        .create(
            &ctx,
            &1,
            "dir2",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    fs.create(
        &ctx,
        &dir1,
        "old-name.txt",
        CreateRequest {
            kind: CreateKind::File,
            attrs: SetAttrs::default(),
        },
    )
    .await
    .unwrap();
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_dir1 = encode_lookup("dir1");
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let lookup_dir2 = encode_lookup("dir2");
    let rename_op = encode_rename("old-name.txt", "new-name.txt");
    let compound = encode_compound(
        "rename",
        &[&seq_op, &rootfh_op, &lookup_dir1, &savefh_op, &rootfh_op2, &lookup_dir2, &rename_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp); // PUTROOTFH
    let _ = parse_op_header(&mut resp); // LOOKUP dir1
    let _ = parse_op_header(&mut resp); // SAVEFH
    let _ = parse_op_header(&mut resp); // PUTROOTFH
    let _ = parse_op_header(&mut resp); // LOOKUP dir2
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_RENAME);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    // Verify old name is gone, new name exists
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_dir1 = encode_lookup("dir1");
    let lookup_old = encode_lookup("old-name.txt");
    let compound = encode_compound("check-old", &[&seq_op, &rootfh_op, &lookup_dir1, &lookup_old]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let lookup_dir2 = encode_lookup("dir2");
    let lookup_new = encode_lookup("new-name.txt");
    let compound = encode_compound("check-new", &[&seq_op, &rootfh_op, &lookup_dir2, &lookup_new]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

/// RENAME of a non-existent source returns `NFS4ERR_NOENT`.
/// Origin: `pynfs/nfs4.0/servertests/st_rename.py` (CODE `RNM5`).
/// RFC: RFC 8881 §18.26.3.
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

// ===== SETATTR (pynfs SATT) =====

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

// ===== GETATTR (pynfs GATT) =====

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
    // At minimum: type, size, fileid, change should be supported
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

// ===== ACCESS (pynfs ACC) =====

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
    // Should support at least READ and LOOKUP on a directory
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

// ===== TEST_STATEID (pynfs TSID) =====

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

// ===== OPEN change info (edge cases from existing tests) =====

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

// ===== SECINFO_NO_NAME =====

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
    let compound = encode_compound(
        "secinfo-parent-root",
        &[&seq_op, &rootfh_op, &secinfo_op],
    );
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

// ===== VERIFY / NVERIFY (pynfs VF, NVF) =====

/// VERIFY with matching attributes succeeds.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF1*` family).
/// RFC: RFC 8881 §18.31.3.
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

/// VERIFY with mismatching attributes returns `NFS4ERR_NOT_SAME`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_verify.py` (CODE `VF3*` family).
/// RFC: RFC 8881 §18.31.3.
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

/// NVERIFY with matching attributes returns `NFS4ERR_SAME`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF1*` family).
/// RFC: RFC 8881 §18.15.3.
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

/// NVERIFY with mismatching attributes succeeds.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_nverify.py` (CODE `NVF2*` family).
/// RFC: RFC 8881 §18.15.3.
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
    skip_bitmap(&mut resp); // attrsset

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

// ===== OPEN share modes (pynfs OPEN) =====

/// OPEN with read-only share access allows subsequent READ.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_open.py` (read-only open behavior family).
/// RFC: RFC 8881 §18.16.3.
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

/// OPEN, CLOSE, and FREE_STATEID complete a valid stateid lifecycle.
/// Origin: RFC-driven state-management check.
/// RFC: RFC 8881 §18.38.3.
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
    // Should have returned the requested attributes
    assert!(!fattr.attr_vals.is_empty());
}

// ===== WRITE edge cases =====

/// WRITE to a new file is reflected in subsequent GETATTR size results.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_write.py` (CODE `WRT1`, `WRT1b`) plus GETATTR verification.
/// RFC: RFC 8881 §18.32.3, §18.7.3.
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

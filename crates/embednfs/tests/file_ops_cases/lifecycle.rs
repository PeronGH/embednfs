use super::*;

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

/// OPEN with `state_owner4.owner` longer than 1024 bytes returns `NFS4ERR_BADXDR`.
/// Origin: RFC 8881 `state_owner4` length bound; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §3.3.10.
#[tokio::test]
async fn test_open_owner_too_long_returns_badxdr() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;
    let long_owner = vec![b'o'; 1025];

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate_with_owner("ghost.txt", &long_owner);
    let compound = encode_compound("open-owner-too-long", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::BadXdr as u32);
    assert_eq!(num_results, 0);
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
    let fh = parse_getfh(&mut resp);

    // Close
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&fh);
    let close_op = encode_close(&stateid);
    let compound = encode_compound("close", &[&seq_op, &putfh_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
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
    let rootfh_op = encode_putrootfh();
    let close_op = encode_close(&bogus);
    let compound = encode_compound("close-bad", &[&seq_op, &rootfh_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
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

/// REMOVE without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM3`).
/// RFC: RFC 8881 §18.25.3.
#[tokio::test]
async fn test_remove_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let remove_op = encode_remove("ghost.txt");
    let compound = encode_compound("rm-nofh", &[&seq_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// REMOVE with a zero-length target returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM4`).
/// RFC: RFC 8881 §18.25.3.
#[tokio::test]
async fn test_remove_zero_length_target() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("");
    let compound = encode_compound("rm-empty", &[&seq_op, &rootfh_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Inval as u32);
}

/// REMOVE of `.` or `..` returns `NFS4ERR_BADNAME`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM7`) to our stricter RFC-targeted expectation.
/// RFC: RFC 8881 §18.25.3.
#[tokio::test]
async fn test_remove_dot_names_badname() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq, name) in [(3, 1, "."), (4, 2, "..")] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let remove_op = encode_remove(name);
        let compound = encode_compound("rm-dot", &[&seq_op, &rootfh_op, &remove_op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);

        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Badname as u32);
        assert_eq!(num_results, 3);
        let _ = parse_op_header(&mut resp);
        skip_sequence_res(&mut resp);
        let _ = parse_op_header(&mut resp);
        let (opnum, op_status) = parse_op_header(&mut resp);
        assert_eq!(opnum, OP_REMOVE);
        assert_eq!(op_status, NfsStat4::Badname as u32);
    }
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
    let _ = fs
        .create(
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
        &[
            &seq_op,
            &rootfh_op,
            &lookup_dir1,
            &savefh_op,
            &rootfh_op2,
            &lookup_dir2,
            &rename_op,
        ],
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
    let compound = encode_compound(
        "check-old",
        &[&seq_op, &rootfh_op, &lookup_dir1, &lookup_old],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let lookup_dir2 = encode_lookup("dir2");
    let lookup_new = encode_lookup("new-name.txt");
    let compound = encode_compound(
        "check-new",
        &[&seq_op, &rootfh_op, &lookup_dir2, &lookup_new],
    );
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

/// RENAME over a non-empty target directory leaves both names unchanged.
/// Origin: RFC 8881 §18.26.3 target replacement must fail atomically for non-empty directories.
/// RFC: RFC 8881 §18.26.3.
#[tokio::test]
async fn test_rename_over_nonempty_directory_is_atomic() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let _ = fs
        .create(
            &ctx,
            &1,
            "source.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let target_dir = fs
        .create(
            &ctx,
            &1,
            "target",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    let _ = fs
        .create(
            &ctx,
            &target_dir.handle,
            "nested.txt",
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
    let savefh_op = encode_savefh();
    let rename_op = encode_rename("source.txt", "target");
    let compound = encode_compound(
        "rename-notempty",
        &[&seq_op, &rootfh_op, &savefh_op, &rename_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Notempty as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_source = encode_lookup("source.txt");
    let compound = encode_compound("check-source", &[&seq_op, &rootfh_op, &lookup_source]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let lookup_target = encode_lookup("target");
    let lookup_nested = encode_lookup("nested.txt");
    let compound = encode_compound(
        "check-target",
        &[&seq_op, &rootfh_op, &lookup_target, &lookup_nested],
    );
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

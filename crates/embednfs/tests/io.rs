mod common;

use tokio::net::TcpStream;

use embednfs_proto::xdr::*;
use embednfs_proto::*;
use embednfs::{FileSystem, MemFs};

use common::*;

/// Full lifecycle: OPEN(create) → WRITE → READ → verify → CLOSE
#[tokio::test]
async fn test_open_write_read_close_lifecycle() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    // Step 1: OPEN (create) a new file
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("hello.txt", OPEN4_SHARE_ACCESS_BOTH);
    let compound = encode_compound("open-create", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "OPEN compound failed");
    assert_eq!(num_results, 3);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_SEQUENCE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    skip_sequence_res(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTROOTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32, "OPEN op failed");
    let open_stateid = parse_open_res(&mut resp);

    // Step 2: WRITE some data
    let test_data = b"Hello, NFS world!";
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("hello.txt");
    let write_op = encode_write(&open_stateid, 0, test_data);
    let compound = encode_compound("write", &[&seq_op, &rootfh_op, &lookup_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "WRITE compound failed");
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_WRITE);
    assert_eq!(op_status, NfsStat4::Ok as u32, "WRITE op failed");
    let count = parse_write_res(&mut resp);
    assert_eq!(count, test_data.len() as u32);

    // Step 3: READ back the data
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("hello.txt");
    let read_op = encode_read(&open_stateid, 0, 4096);
    let compound = encode_compound("read", &[&seq_op, &rootfh_op, &lookup_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "READ compound failed");
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32, "READ op failed");
    let (eof, data) = parse_read_res(&mut resp);
    assert!(eof);
    assert_eq!(data, test_data);

    // Step 4: CLOSE the file
    let seq_op = encode_sequence(&sessionid, 4, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("hello.txt");
    let close_op = encode_close(&open_stateid);
    let compound = encode_compound("close", &[&seq_op, &rootfh_op, &lookup_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "CLOSE compound failed");
}

/// Verify that OPEN for a nonexistent file with NOCREATE returns Noent
#[tokio::test]
async fn test_open_nocreate_nonexistent() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_nocreate("doesnt_exist.txt", OPEN4_SHARE_ACCESS_READ);
    let compound = encode_compound("open-noent", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
}

/// Write multiple chunks at different offsets and read the full file
#[tokio::test]
async fn test_write_multiple_offsets_and_read() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    // OPEN create
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("multi.dat", OPEN4_SHARE_ACCESS_BOTH);
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, op_status) = parse_op_header(&mut resp);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let open_stateid = parse_open_res(&mut resp);

    // Write first chunk at offset 0
    let chunk1 = b"AAAA";
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("multi.dat");
    let write_op = encode_write(&open_stateid, 0, chunk1);
    let compound = encode_compound("write1", &[&seq_op, &rootfh_op, &lookup_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "WRITE chunk1 failed");

    // Write second chunk at offset 4
    let chunk2 = b"BBBB";
    let seq_op = encode_sequence(&sessionid, 3, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("multi.dat");
    let write_op = encode_write(&open_stateid, 4, chunk2);
    let compound = encode_compound("write2", &[&seq_op, &rootfh_op, &lookup_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "WRITE chunk2 failed");

    // Read back the full file
    let seq_op = encode_sequence(&sessionid, 4, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("multi.dat");
    let read_op = encode_read(&open_stateid, 0, 4096);
    let compound = encode_compound("read-all", &[&seq_op, &rootfh_op, &lookup_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "READ failed");
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (eof, data) = parse_read_res(&mut resp);
    assert!(eof);
    assert_eq!(data, b"AAAABBBB");

    // Close
    let seq_op = encode_sequence(&sessionid, 5, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("multi.dat");
    let close_op = encode_close(&open_stateid);
    let compound = encode_compound("close", &[&seq_op, &rootfh_op, &lookup_op, &close_op]);
    let mut resp = send_rpc(&mut stream, 7, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "CLOSE failed");
}

/// Test OPEN with WANT_NO_DELEG (Linux kernel sets this flag)
#[tokio::test]
async fn test_open_with_want_no_deleg() {
    let port = start_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    // The Linux kernel commonly uses OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG
    let share_access = OPEN4_SHARE_ACCESS_BOTH | OPEN4_SHARE_ACCESS_WANT_NO_DELEG;
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("nodeleg.txt", share_access);
    let compound = encode_compound("open-nodeleg", &[&seq_op, &rootfh_op, &open_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "OPEN with WANT_NO_DELEG failed");

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// RFC 8881 §16.2.3.1.2: PUTFH resets current stateid.
/// After OPEN sets a stateid, PUTFH should clear it. The "current stateid"
/// special value (seqid=1, other=all-zero) should NOT resolve to the stale
/// open stateid after PUTFH. Instead, it passes through as-is and gets
/// rejected as NFS4ERR_BAD_STATEID since it's not a valid stateid.
#[tokio::test]
async fn test_putfh_resets_current_stateid() {
    let fs = populated_fs(&["alpha.txt"]).await;
    fs.write_file("/alpha.txt", 0, b"hello").await.unwrap();
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let sessionid = setup_session(&mut stream).await;

    // OPEN alpha.txt to get a stateid into current_stateid.
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("alpha.txt", OPEN4_SHARE_ACCESS_READ);
    let getfh_op = encode_getfh();
    let compound = encode_compound("open", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
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
    let _open_stateid = parse_open_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fh = parse_getfh_res(&mut resp);

    // PUTFH resets current_stateid. Using the "current stateid" special value
    // should fail because there's no current stateid to resolve.
    let seq_op2 = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&fh);
    let current_sid = Stateid4 { seqid: 1, other: [0u8; 12] };
    let read_op = encode_read(&current_sid, 0, 100);
    let compound = encode_compound("read-after-putfh", &[&seq_op2, &putfh_op, &read_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    // The compound should fail on the READ with NFS4ERR_BAD_STATEID.
    assert_eq!(status, NfsStat4::BadStateid as u32,
        "READ with current-stateid after PUTFH should fail: stateid was cleared");
    assert_eq!(num_results, 3); // SEQUENCE ok, PUTFH ok, READ fail

    // But using an explicit anonymous stateid (seqid=0, other=all-zero) should work.
    let seq_op3 = encode_sequence(&sessionid, 3, 0);
    let putfh_op2 = encode_putfh(&fh);
    let anon_sid = Stateid4 { seqid: 0, other: [0u8; 12] };
    let read_op2 = encode_read(&anon_sid, 0, 100);
    let compound = encode_compound("read-anon", &[&seq_op3, &putfh_op2, &read_op2]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "READ with anonymous stateid should succeed");
}

/// RFC 8881 §16.2.3.1.2: SAVEFH/RESTOREFH save and restore the current stateid.
/// Open a file (which sets current_stateid), SAVEFH, then PUTROOTFH (clears stateid),
/// then RESTOREFH should restore the saved stateid.
#[tokio::test]
async fn test_savefh_restorefh_preserves_stateid() {
    let fs = populated_fs(&["data.txt"]).await;
    fs.write_file("/data.txt", 0, b"saved-state").await.unwrap();
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let sessionid = setup_session(&mut stream).await;

    // OPEN file, SAVEFH (saves fh+stateid), PUTROOTFH (clears both), RESTOREFH (restores both),
    // then READ using current stateid — should work because RESTOREFH restored the open stateid.
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("data.txt", OPEN4_SHARE_ACCESS_READ);
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let restorefh_op = encode_restorefh();
    // Use "current stateid" special value — should resolve to the restored open stateid.
    let current_sid = Stateid4 { seqid: 1, other: [0u8; 12] };
    let read_op = encode_read(&current_sid, 0, 100);
    let compound = encode_compound(
        "savefh-restorefh",
        &[&seq_op, &rootfh_op, &open_op, &savefh_op, &rootfh_op2, &restorefh_op, &read_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32, "SAVEFH/RESTOREFH stateid roundtrip failed");
    assert_eq!(num_results, 7);

    // Skip through to the READ result.
    for _ in 0..6 {
        let (opnum, op_status) = parse_op_header(&mut resp);
        assert_eq!(op_status, NfsStat4::Ok as u32, "op {opnum} failed");
        match opnum {
            OP_SEQUENCE => skip_sequence_res(&mut resp),
            OP_OPEN => { let _ = parse_open_res(&mut resp); }
            _ => {} // PUTROOTFH, SAVEFH, RESTOREFH have no body on success
        }
    }
    // Parse READ result.
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (eof, data) = parse_read_res(&mut resp);
    assert!(eof);
    assert_eq!(data, b"saved-state");
}

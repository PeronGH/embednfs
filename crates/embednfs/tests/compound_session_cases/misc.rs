use super::*;

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
    let mut bogus_buf = BytesMut::new();
    99999u32.encode(&mut bogus_buf);
    let bogus_op = bogus_buf.to_vec();

    let compound = encode_compound("unknown-op", &[&seq_op, &bogus_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
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

    let csess1 = encode_create_session(clientid, sequenceid);
    let compound = encode_compound("csess1", &[&csess1]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let (_, _) = parse_op_header(&mut resp);
    let sid1 = parse_create_session_res(&mut resp);

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

/// BIND_CONN_TO_SESSION with a valid session succeeds.
/// Origin: RFC 8881 §18.34.3; no direct pynfs server41tests case.
/// RFC: RFC 8881 §18.34.3.
#[tokio::test]
async fn test_bind_conn_to_session_basic() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let bind_op = encode_bind_conn_to_session(&sessionid, 0);
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

/// Multiple slots can be used concurrently on the same session.
/// Origin: RFC 8881 §2.10.6.1; implementation-driven concurrency check.
/// RFC: RFC 8881 §2.10.6.1.
#[tokio::test]
async fn test_multiple_slots_concurrent() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let compound = encode_compound("slot0", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 1, 1);
    let compound = encode_compound("slot1", &[&seq_op, &rootfh_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

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

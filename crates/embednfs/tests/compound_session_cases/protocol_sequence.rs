use super::*;

// ===== NULL procedure (pynfs COMP1) =====

/// NULL procedure must return success with empty body.
/// Origin: RFC 8881 §17.1; no direct pynfs server41tests case.
/// RFC: RFC 8881 §17.1.
#[tokio::test]
async fn test_null_procedure() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    let mut resp = send_rpc(&mut stream, 1, 0, &[]).await;
    let (xid, accept_stat) = parse_rpc_reply_fields(&mut resp);
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
        let (_, accept_stat) = parse_rpc_reply_fields(&mut resp);
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
    let (_, accept_stat) = parse_rpc_reply_fields(&mut resp);
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
    let (_, accept_stat) = parse_rpc_reply_fields(&mut resp);
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

/// EXCHANGE_ID with unsupported non-`SP4_NONE` state protection returns `NFS4ERR_INVAL`.
/// Origin: RFC 8881 state-protection negotiation; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.35.3.
#[tokio::test]
async fn test_exchange_id_non_none_state_protect_returns_inval() {
    let port = start_server().await;
    let mut stream = connect(port).await;

    for (xid, op) in [
        (1, encode_exchange_id_with_mach_cred(b"mach-cred-client")),
        (
            2,
            encode_exchange_id_with_ssv(
                b"ssv-client",
                &[b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"],
                &[b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2a"],
            ),
        ),
    ] {
        let compound = encode_compound("exid-state-protect", &[&op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Inval as u32);
        assert_eq!(num_results, 1);
        let (opnum, op_status) = parse_op_header(&mut resp);
        assert_eq!(opnum, OP_EXCHANGE_ID);
        assert_eq!(op_status, NfsStat4::Inval as u32);
    }
}

/// EXCHANGE_ID with `client_owner4.co_ownerid` longer than 1024 bytes returns `NFS4ERR_BADXDR`.
/// Origin: RFC 8881 `client_owner4` length bound; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §2.4, §3.3.10.1.
#[tokio::test]
async fn test_exchange_id_ownerid_too_long_returns_badxdr() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let owner = vec![b'x'; 1025];

    let exchange_id_op = encode_exchange_id_with_name(&owner);
    let compound = encode_compound("exid-ownerid-too-long", &[&exchange_id_op]);
    let mut resp = send_rpc(&mut stream, 1, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::BadXdr as u32);
    assert_eq!(num_results, 0);
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
    let (_, accept_stat) = parse_rpc_reply_fields(&mut resp);
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

/// CREATE_SESSION accepts RFC-compliant RPCSEC_GSS callback security parameters.
/// Origin: RFC 8881 callback security parameter grammar; no direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.36.1, §18.33.1.
#[tokio::test]
async fn test_create_session_rpcsec_gss_callback_params_succeed() {
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

    let create_session_op =
        encode_create_session_rpcsec_gss(clientid, sequenceid, 1, b"fore-handle", b"back-handle");
    let compound = encode_compound("csess-gss", &[&create_session_op]);
    let mut resp = send_rpc(&mut stream, 2, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 1);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE_SESSION);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let sessionid = parse_create_session_res(&mut resp);
    assert_ne!(sessionid, [0u8; 16]);
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

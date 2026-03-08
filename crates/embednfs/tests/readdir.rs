mod common;

use bytes::BytesMut;
use tokio::net::TcpStream;

use embednfs_proto::xdr::*;
use embednfs_proto::*;
use embednfs::{FileSystem, MemFs};

use common::*;

#[tokio::test]
async fn test_readdir_reply_stays_within_maxcount_and_skips_dot_entries() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt", "delta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 512, 1536, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-bounds", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);

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
    let (body_len, _cookieverf, entries, _eof) = parse_readdir_body(&mut resp);
    assert!(body_len <= 1536, "readdir body exceeded maxcount: {body_len}");
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|(_, name, _)| name != "." && name != ".."));
    assert!(entries.iter().all(|(cookie, _, _)| *cookie >= 3));
}

#[tokio::test]
async fn test_readdir_returns_toosmall_when_entry_cannot_fit() {
    let fs = populated_fs(&["oversized.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 64, 64, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-toosmall", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Toosmall as u32);
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
    assert_eq!(op_status, NfsStat4::Toosmall as u32);
}

#[tokio::test]
async fn test_readdir_cookieverf_stable_for_unchanged_dir() {
    let fs = populated_fs(&["alpha.txt", "beta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-first", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, cookieverf, entries, _) = parse_readdir_body(&mut resp);
    assert!(entries.len() >= 2);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let readdir_op = encode_readdir_custom(entries[0].0, cookieverf, 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 4, 1, &encode_compound("readdir-cont", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, continued_verf, continued_entries, _) = parse_readdir_body(&mut resp);
    assert_eq!(continued_verf, cookieverf);
    assert!(!continued_entries.is_empty());
}

#[tokio::test]
async fn test_readdir_cookieverf_rejects_stale_continuation_after_mutation() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 3, 1, &encode_compound("readdir-before-mutate", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, cookieverf, entries, _) = parse_readdir_body(&mut resp);
    assert!(entries.len() >= 2);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let remove_op = encode_remove("gamma.txt");
    let mut resp = send_rpc(&mut stream, 4, 1, &encode_compound("mutate-dir", &[&seq_op, &rootfh_op, &remove_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let readdir_op = encode_readdir_custom(entries[0].0, cookieverf, 2048, 4096, &bits);
    let mut resp = send_rpc(&mut stream, 5, 1, &encode_compound("readdir-stale-verf", &[&seq_op, &rootfh_op, &readdir_op])).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::NotSame as u32);
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
    assert_eq!(op_status, NfsStat4::NotSame as u32);
}

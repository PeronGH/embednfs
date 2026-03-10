mod common;

use crate::common::*;
use embednfs_proto::{NfsStat4, OP_READ};

const LARGE_READ_BYTES: usize = 3 * 1024 * 1024;

/// Large READ replies are emitted across multiple RFC 5531 record fragments and still decode as one RPC reply.
/// Origin: transport interoperability smoke for outbound RPC-over-TCP fragmentation, after confirming `nfs4j` can reassemble multi-fragment replies.
/// RFC: RFC 5531 §11; RFC 8881 §18.22.3.
#[tokio::test]
async fn test_large_read_reply_uses_multiple_rpc_fragments() {
    let payload = vec![0x5a; LARGE_READ_BYTES];
    let fs = fs_with_data("big.bin", &payload).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("big.bin");
    let read_op = encode_read(0, LARGE_READ_BYTES as u32);
    let compound = encode_compound(
        "fragmented-read",
        &[&seq_op, &rootfh_op, &lookup_op, &read_op],
    );

    let (mut resp, fragment_count) = send_rpc_record(&mut stream, 3, 1, &compound).await;
    assert!(
        fragment_count > 1,
        "expected fragmented reply, got {fragment_count} fragment(s)"
    );

    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (eof, data) = parse_read_res(&mut resp);
    assert!(eof);
    assert_eq!(data.len(), LARGE_READ_BYTES);
    assert!(data.iter().all(|byte| *byte == 0x5a));
}

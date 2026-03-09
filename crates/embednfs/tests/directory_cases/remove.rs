use super::*;
use embednfs::{CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs};

/// REMOVE of a non-empty directory returns `NFS4ERR_NOTEMPTY`.
/// Origin: Linux kernel nfsd pattern; not a direct one-to-one pynfs case.
/// RFC: RFC 8881 §18.25.3.
#[tokio::test]
async fn test_remove_nonempty_directory() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let subdir_id = fs
        .create(
            &ctx,
            &1,
            "nonempty",
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
        &subdir_id,
        "child.txt",
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
    let remove_op = encode_remove("nonempty");
    let compound = encode_compound("rm-notempty", &[&seq_op, &rootfh_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Notempty as u32);
}

/// REMOVE of an empty directory succeeds.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_remove.py` (CODE `RM1d`).
/// RFC: RFC 8881 §18.25.3.
#[tokio::test]
async fn test_remove_empty_directory() {
    let fs = fs_with_subdir("empty-dir").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let remove_op = encode_remove("empty-dir");
    let compound = encode_compound("rm-emptydir", &[&seq_op, &rootfh_op, &remove_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
}

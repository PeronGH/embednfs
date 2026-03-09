use super::*;
use embednfs::{CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// OPENATTR on a file with xattrs sets the current filehandle to the attribute directory.
/// Origin: RFC- and macOS-client-driven; not a direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.17.
#[tokio::test]
async fn test_openattr_on_file_returns_attrdir() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound(
        "openattr",
        &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &getattr_op],
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
    assert_eq!(opnum, OP_OPENATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut attr_vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut attr_vals).unwrap();
    assert_eq!(file_type, NfsFtype4::AttrDir as u32);
}

/// OPENATTR followed by READDIR lists named attributes.
/// Origin: RFC- and macOS-client-driven; not a direct pynfs one-to-one case.
/// RFC: RFC 8881 §18.17.
#[tokio::test]
async fn test_openattr_readdir_lists_named_attrs() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 8192, &[FATTR4_FILEID, FATTR4_TYPE]);
    let compound = encode_compound(
        "openattr-readdir",
        &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &readdir_op],
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

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_, _, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "user.demo");
}

/// OPENATTR followed by READDIR on a file with no named attributes returns an empty list.
/// Origin: Apple/macOS named-attribute workflow, equivalent to the empty-list intent of `pynfs` XATT10.
/// RFC: RFC 8881 §18.17.
#[tokio::test]
async fn test_openattr_readdir_empty_named_attr_dir() {
    let fs = populated_fs(&["notes.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 8192, &[FATTR4_FILEID, FATTR4_TYPE]);
    let compound = encode_compound(
        "openattr-readdir-empty",
        &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &readdir_op],
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
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_, _, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert!(entries.is_empty());
}

/// Named attribute lookup and read works through the synthetic attribute directory.
/// Origin: RFC- and macOS-client-driven named-attribute workflow.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_lookup_and_read() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let lookup_xattr_op = encode_lookup("user.demo");
    let read_op = encode_read(0, 1024);
    let compound = encode_compound(
        "named-attr-read",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &lookup_xattr_op,
            &read_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 6);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert_eq!(data.as_ref(), b"value");
}

/// Looking up a missing named attribute returns `NFS4ERR_NOENT`.
/// Origin: Apple/macOS named-attribute workflow, equivalent to the missing-attribute intent of `pynfs` XATT2.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_lookup_missing_returns_noent() {
    let fs = populated_fs(&["notes.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let lookup_xattr_op = encode_lookup("user.missing");
    let compound = encode_compound(
        "named-attr-missing",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &lookup_xattr_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 5);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LOOKUP);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// Named attributes support open-create, write, close, read-back, and remove.
/// Origin: RFC- and macOS-client-driven named-attribute workflow.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_open_create_write_close_and_remove() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let _file_id = fs
        .create(
            &ctx,
            &1,
            "notes.txt",
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
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(true);
    let open_xattr_op = encode_open_create("user.created");
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "named-attr-open-create",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &open_xattr_op,
            &getfh_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 6);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let stateid = skip_open_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let xattr_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&xattr_fh);
    let write_op = encode_write(&stateid, 0, b"hello-xattr");
    let close_op = encode_close(&stateid);
    let compound = encode_compound(
        "named-attr-write-close",
        &[&seq_op, &putfh_op, &write_op, &close_op],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_PUTFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_WRITE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let written = u32::decode(&mut resp).unwrap();
    assert_eq!(written, 11);
    let _ = u32::decode(&mut resp).unwrap();
    let _ = decode_fixed_opaque(&mut resp, 8).unwrap();
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CLOSE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let _ = parse_stateid(&mut resp);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 8192, &[FATTR4_FILEID, FATTR4_TYPE]);
    let compound = encode_compound(
        "named-attr-readdir-after-write",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &readdir_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, _, entries, _) = parse_readdir_body(&mut resp);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "user.created");

    let seq_op = encode_sequence(&sessionid, 4, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let remove_op = encode_remove("user.created");
    let compound = encode_compound(
        "named-attr-remove",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &remove_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 6, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 5);
}

/// OPENATTR + OPEN(CREATE, GUARDED) on an existing named attribute returns `NFS4ERR_EXIST`.
/// Origin: Apple/macOS named-attribute workflow, equivalent to the exclusive-create intent of `pynfs` XATT6.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_guarded_create_existing_returns_exist() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(true);
    let open_xattr_op = encode_open_create_guarded("user.demo");
    let compound = encode_compound(
        "named-attr-guarded-exist",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &open_xattr_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Exist as u32);
    assert_eq!(num_results, 5);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Exist as u32);
}

/// OPENATTR + OPEN(NOCREATE) on a missing named attribute returns `NFS4ERR_NOENT`.
/// Origin: Apple/macOS named-attribute workflow, equivalent to the replace-missing intent of `pynfs` XATT5.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_open_nocreate_missing_returns_noent() {
    let fs = populated_fs(&["notes.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(true);
    let open_xattr_op = encode_open_nocreate("user.missing");
    let compound = encode_compound(
        "named-attr-open-missing",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &open_xattr_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 5);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// Reopening an existing named attribute and writing replaces its content.
/// Origin: Apple/macOS named-attribute workflow, covering the update-existing intent of `pynfs` XATT7.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_reopen_and_replace_value() {
    let fs = fs_with_xattr("notes.txt", "user.demo", b"value1").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(true);
    let open_xattr_op = encode_open_nocreate_with_access(
        "user.demo",
        OPEN4_SHARE_ACCESS_BOTH,
        OPEN4_SHARE_DENY_NONE,
    );
    let getfh_op = encode_getfh();
    let compound = encode_compound(
        "named-attr-reopen",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &open_xattr_op,
            &getfh_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 6);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_OPEN);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let stateid = skip_open_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let xattr_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&xattr_fh);
    let write_op = encode_write(&stateid, 0, b"value2");
    let close_op = encode_close(&stateid);
    let compound = encode_compound(
        "named-attr-rewrite",
        &[&seq_op, &putfh_op, &write_op, &close_op],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let lookup_xattr_op = encode_lookup("user.demo");
    let read_op = encode_read(0, 1024);
    let compound = encode_compound(
        "named-attr-read-replaced",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &lookup_xattr_op,
            &read_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READ);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let eof = bool::decode(&mut resp).unwrap();
    let data = decode_opaque(&mut resp).unwrap();
    assert!(eof);
    assert_eq!(data.as_ref(), b"value2");
}

/// Removing a missing named attribute returns `NFS4ERR_NOENT`.
/// Origin: Apple/macOS named-attribute workflow, equivalent to the remove-missing intent of `pynfs` XATT8.
/// RFC: RFC 8881 §5.3.
#[tokio::test]
async fn test_named_attr_remove_missing_returns_noent() {
    let fs = populated_fs(&["notes.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_file_op = encode_lookup("notes.txt");
    let openattr_op = encode_openattr(false);
    let remove_op = encode_remove("user.missing");
    let compound = encode_compound(
        "named-attr-remove-missing",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_file_op,
            &openattr_op,
            &remove_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Noent as u32);
    assert_eq!(num_results, 5);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_REMOVE);
    assert_eq!(op_status, NfsStat4::Noent as u32);
}

/// GETATTR on a file caches its named-attribute summary.
/// Origin: implementation-specific cache behavior.
/// RFC: RFC 8881 §5.3, §18.7.3.
#[tokio::test]
async fn test_getattr_file_named_attr_summary_is_cached() {
    let inner = fs_with_xattr("cached.txt", "user.demo", b"value").await;
    let list_count = Arc::new(AtomicUsize::new(0));
    let fs = CountingNamedAttrFs {
        inner,
        list_count: list_count.clone(),
    };
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq) in [(3, 1), (4, 2)] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let lookup_op = encode_lookup("cached.txt");
        let getattr_op = encode_getattr(&[FATTR4_NAMED_ATTR]);
        let compound = encode_compound(
            "getattr-file-cache",
            &[&seq_op, &rootfh_op, &lookup_op, &getattr_op],
        );
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, _) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Ok as u32);
    }

    assert_eq!(list_count.load(Ordering::Relaxed), 0);
}

/// GETATTR on a named-attribute directory caches its summary metadata.
/// Origin: implementation-specific cache behavior.
/// RFC: RFC 8881 §5.3, §18.7.3.
#[tokio::test]
async fn test_getattr_named_attr_dir_summary_is_cached() {
    let inner = fs_with_xattr("cached.txt", "user.demo", b"value").await;
    let list_count = Arc::new(AtomicUsize::new(0));
    let fs = CountingNamedAttrFs {
        inner,
        list_count: list_count.clone(),
    };
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq) in [(3, 1), (4, 2)] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let lookup_op = encode_lookup("cached.txt");
        let openattr_op = encode_openattr(false);
        let getattr_op = encode_getattr(&[FATTR4_TYPE, FATTR4_SIZE]);
        let compound = encode_compound(
            "getattr-attrdir-cache",
            &[&seq_op, &rootfh_op, &lookup_op, &openattr_op, &getattr_op],
        );
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, _) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Ok as u32);
    }

    assert_eq!(list_count.load(Ordering::Relaxed), 1);
}

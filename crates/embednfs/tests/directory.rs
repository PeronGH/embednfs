//! Tests for directory operations: READDIR, CREATE (mkdir), OPENATTR,
//! and named-attribute workflows.
//!
//! This module mixes pynfs-derived READDIR coverage with macOS-client-driven
//! OPENATTR/named-attribute flows and implementation-specific cache checks.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;

use bytes::Bytes;
use embednfs::{CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs};
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;

// ===== READDIR (pynfs RDDR) =====

/// READDIR on an empty directory returns EOF with no entries.
/// Origin: `pynfs/nfs4.0/lib/nfs4/servertests/st_readdir.py` (CODE `RDDR1`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_empty_directory() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir-empty", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_body_len, _cookieverf, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert!(entries.is_empty());
}

/// READDIR on a populated directory lists all entries.
/// Origin: `pynfs/nfs4.0/lib/nfs4/servertests/st_readdir.py` (CODE `RDDR2`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_lists_all_entries() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir-all", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_, _, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert_eq!(entries.len(), 3);
    let names: Vec<&str> = entries.iter().map(|(_, name, _)| name.as_str()).collect();
    assert!(names.contains(&"alpha.txt"));
    assert!(names.contains(&"beta.txt"));
    assert!(names.contains(&"gamma.txt"));
}

/// READDIR must not include `.` or `..` entries.
/// Origin: derived from `pynfs/nfs4.0/lib/nfs4/servertests/st_readdir.py` (`RDDR1`, `RDDR2`) plus Linux kernel nfsd expectations.
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_excludes_dot_entries() {
    let fs = populated_fs(&["file.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir-nodots", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, _, entries, _) = parse_readdir_body(&mut resp);
    for (_, name, _) in &entries {
        assert_ne!(name, ".");
        assert_ne!(name, "..");
    }
}

/// READDIR cookies start at 3 because 0 is the initial cookie and 1-2 are reserved for `.` and `..`.
/// Origin: Linux kernel nfsd and client-behavior-derived check; no direct one-to-one pynfs case.
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_cookies_start_at_3() {
    let fs = populated_fs(&["one.txt", "two.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir-cookies", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, _, entries, _) = parse_readdir_body(&mut resp);
    for (cookie, _, _) in &entries {
        assert!(*cookie >= 3, "cookie {} < 3", cookie);
    }
}

/// READDIR reply stays within `maxcount` for an Apple-style readdirplus probe.
/// Origin: Apple/macOS client behavior; not a direct pynfs case.
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_reply_stays_within_maxcount_and_skips_dot_entries() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt", "delta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 512, 1536, &bits);
    let mut resp = send_rpc(
        &mut stream,
        3,
        1,
        &encode_compound("readdir-bounds", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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
    assert!(
        body_len <= 1536,
        "readdir body exceeded maxcount: {body_len}"
    );
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|(_, name, _)| name != "." && name != "..")
    );
    assert!(entries.iter().all(|(cookie, _, _)| *cookie >= 3));
}

/// READDIR returns `NFS4ERR_TOOSMALL` when an entry cannot fit within `maxcount`.
/// Origin: `pynfs/nfs4.0/lib/nfs4/servertests/st_readdir.py` (CODE `RDDR8`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_returns_toosmall_when_entry_cannot_fit() {
    let fs = populated_fs(&["oversized.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let bits = apple_readdirplus_bits();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 64, 64, &bits);
    let mut resp = send_rpc(
        &mut stream,
        3,
        1,
        &encode_compound("readdir-toosmall", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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

/// READDIR cookie verifier is stable while the directory is unchanged.
/// Origin: Linux kernel nfsd pattern; not a direct one-to-one pynfs case.
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_cookieverf_stable_for_unchanged_dir() {
    let fs = populated_fs(&["alpha.txt", "beta.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(
        &mut stream,
        3,
        1,
        &encode_compound("readdir-first", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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
    let mut resp = send_rpc(
        &mut stream,
        4,
        1,
        &encode_compound("readdir-cont", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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

/// READDIR continuation rejects a stale cookie verifier after directory mutation.
/// Origin: Linux kernel nfsd pattern; not a direct one-to-one pynfs case.
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_cookieverf_rejects_stale_continuation_after_mutation() {
    let fs = populated_fs(&["alpha.txt", "beta.txt", "gamma.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let bits = apple_readdirplus_bits();
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 2048, 4096, &bits);
    let mut resp = send_rpc(
        &mut stream,
        3,
        1,
        &encode_compound("readdir-before-mutate", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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
    let mut resp = send_rpc(
        &mut stream,
        4,
        1,
        &encode_compound("mutate-dir", &[&seq_op, &rootfh_op, &remove_op]),
    )
    .await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let readdir_op = encode_readdir_custom(entries[0].0, cookieverf, 2048, 4096, &bits);
    let mut resp = send_rpc(
        &mut stream,
        5,
        1,
        &encode_compound("readdir-stale-verf", &[&seq_op, &rootfh_op, &readdir_op]),
    )
    .await;
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

// ===== OPENATTR =====

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
    assert_eq!(data, b"value");
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

    // OPEN+CREATE xattr
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

    // WRITE
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
    let _ = u32::decode(&mut resp).unwrap(); // committed
    let _ = decode_fixed_opaque(&mut resp, 8).unwrap();
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CLOSE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let _ = parse_stateid(&mut resp);

    // Verify xattr via READDIR
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

    // Remove xattr
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

// ===== Named-attr caching =====

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

/// READDIR on a subdirectory works the same as READDIR on the root directory.
/// Origin: derived from `pynfs/nfs4.0/lib/nfs4/servertests/st_readdir.py` (CODE `RDDR2`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_subdirectory() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let subdir_id = fs
        .create(
            &ctx,
            &1,
            "sub",
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
        "inner.txt",
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
    let lookup_op = encode_lookup("sub");
    let readdir_op = encode_readdir();
    let compound = encode_compound(
        "readdir-sub",
        &[&seq_op, &rootfh_op, &lookup_op, &readdir_op],
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
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (_, _, entries, eof) = parse_readdir_body(&mut resp);
    assert!(eof);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, "inner.txt");
}

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
/// Origin: derived from `pynfs/nfs4.0/lib/nfs4/servertests/st_remove.py` (CODE `RM1d`).
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

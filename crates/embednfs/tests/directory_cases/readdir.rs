use super::*;

// ===== READDIR (pynfs RDDR) =====

/// READDIR on an empty directory returns EOF with no entries.
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR1`).
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
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR2`).
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
/// Origin: derived from `pynfs/nfs4.0/servertests/st_readdir.py` (`RDDR1`, `RDDR2`) plus Linux kernel nfsd expectations.
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

/// READDIR without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR6`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir-nofh", &[&seq_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// READDIR with `maxcount=0` returns `NFS4ERR_TOOSMALL`.
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR7`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_maxcount_zero_returns_toosmall() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 0, &[FATTR4_FILEID]);
    let compound = encode_compound("readdir-maxcount-zero", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Toosmall as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Toosmall as u32);
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
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR8`).
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

/// READDIR with write-only attrs returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR9`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_write_only_attrs_invalid() {
    let fs = populated_fs(&["alpha.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let readdir_op = encode_readdir_custom(0, [0u8; 8], 4096, 8192, &[FATTR4_TIME_MODIFY_SET]);
    let compound = encode_compound("readdir-writeonly", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
    assert_eq!(num_results, 3);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READDIR);
    assert_eq!(op_status, NfsStat4::Inval as u32);
}

/// READDIR with reserved cookies returns `NFS4ERR_BAD_COOKIE`.
/// Origin: `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR10`).
/// RFC: RFC 8881 §18.23.3.
#[tokio::test]
async fn test_readdir_reserved_cookies_bad_cookie() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq, cookie) in [(3, 1, 1u64), (4, 2, 2u64)] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let readdir_op = encode_readdir_custom(cookie, [0u8; 8], 4096, 8192, &[FATTR4_FILEID]);
        let compound = encode_compound("readdir-bad-cookie", &[&seq_op, &rootfh_op, &readdir_op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);

        let (status, _, num_results) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::BadCookie as u32);
        assert_eq!(num_results, 3);
        let _ = parse_op_header(&mut resp);
        skip_sequence_res(&mut resp);
        let _ = parse_op_header(&mut resp);
        let (opnum, op_status) = parse_op_header(&mut resp);
        assert_eq!(opnum, OP_READDIR);
        assert_eq!(op_status, NfsStat4::BadCookie as u32);
    }
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

/// READDIR on a subdirectory works the same as READDIR on the root directory.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_readdir.py` (CODE `RDDR2`).
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

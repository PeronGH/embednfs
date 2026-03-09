use super::*;

/// CREATE with type `NF4LNK` creates a symlink.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKLINK`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_symlink() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_symlink("mylink", "/some/target");
    let compound = encode_compound("symlink", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
}

/// CREATE symlink with an existing name returns `NFS4ERR_EXIST`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKLINK`, second-create EXIST behavior).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_symlink_existing_name() {
    let fs = populated_fs(&["taken.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_symlink("taken.txt", "/target");
    let compound = encode_compound("slink-exist", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Exist as u32);
}

/// READLINK returns the symlink target.
/// Origin: `pynfs/nfs4.0/servertests/st_readlink.py` (CODE `RDLK1`).
/// RFC: RFC 8881 §18.24.3.
#[tokio::test]
async fn test_readlink_returns_target() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_symlink("rdlink", "/my/target/path");
    let compound = encode_compound("create-link", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let lookup_op = encode_lookup("rdlink");
    let readlink_op = encode_readlink();
    let compound = encode_compound("readlink", &[&seq_op, &rootfh_op, &lookup_op, &readlink_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_READLINK);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let target = String::decode(&mut resp).unwrap();
    assert_eq!(target, "/my/target/path");
}

/// READLINK on a non-symlink returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_readlink.py` (CODE `RDLK2r`).
/// RFC: RFC 8881 §18.24.3.
#[tokio::test]
async fn test_readlink_on_regular_file() {
    let fs = populated_fs(&["regular.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("regular.txt");
    let readlink_op = encode_readlink();
    let compound = encode_compound(
        "readlink-file",
        &[&seq_op, &rootfh_op, &lookup_op, &readlink_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
}

/// READLINK without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_readlink.py` (CODE `RDLK3`).
/// RFC: RFC 8881 §18.24.3.
#[tokio::test]
async fn test_readlink_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let readlink_op = encode_readlink();
    let compound = encode_compound("readlink-nofh", &[&seq_op, &readlink_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// LINK creates a hard link in the target directory.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK1r`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_creates_hard_link() {
    let fs = populated_fs(&["source.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("source.txt");
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let link_op = encode_link("hardlink.txt");
    let compound = encode_compound(
        "link",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_op,
            &savefh_op,
            &rootfh_op2,
            &link_op,
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
    assert_eq!(opnum, OP_LINK);
    assert_eq!(op_status, NfsStat4::Ok as u32);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("source.txt");
    let getattr_op = encode_getattr(&[FATTR4_FILEID]);
    let compound = encode_compound(
        "link-source-fileid",
        &[&seq_op, &rootfh_op, &lookup_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let source_fileid = u64::decode(&mut vals).unwrap();

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("hardlink.txt");
    let getattr_op = encode_getattr(&[FATTR4_FILEID]);
    let compound = encode_compound(
        "link-target-fileid",
        &[&seq_op, &rootfh_op, &lookup_op, &getattr_op],
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
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut vals = Bytes::from(fattr.attr_vals);
    let target_fileid = u64::decode(&mut vals).unwrap();

    assert_eq!(source_fileid, target_fileid);
}

/// LINK with an existing target name returns `NFS4ERR_EXIST`.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK5`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_existing_name() {
    let fs = populated_fs(&["src.txt", "dst.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("src.txt");
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let link_op = encode_link("dst.txt");
    let compound = encode_compound(
        "link-exist",
        &[
            &seq_op,
            &rootfh_op,
            &lookup_op,
            &savefh_op,
            &rootfh_op2,
            &link_op,
        ],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Exist as u32);
}

/// LINK without a saved filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK2`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_no_saved_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let link_op = encode_link("badlink.txt");
    let compound = encode_compound("link-nosaved", &[&seq_op, &rootfh_op, &link_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// LINK without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK3`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_no_current_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let link_op = encode_link("dst.txt");
    let compound = encode_compound("link-nocfh", &[&seq_op, &link_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
    assert_eq!(num_results, 2);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_LINK);
    assert_eq!(op_status, NfsStat4::Nofilehandle as u32);
}

/// LINK with a zero-length name returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK6`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_zero_length_name() {
    let fs = populated_fs(&["src.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("src.txt");
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let link_op = encode_link("");
    let compound = encode_compound(
        "link-empty",
        &[&seq_op, &rootfh_op, &lookup_op, &savefh_op, &rootfh_op2, &link_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
}

/// LINK with a long name returns `NFS4ERR_NAMETOOLONG`.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK7`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_name_too_long() {
    let fs = populated_fs(&["src.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;
    let long_name = "x".repeat(300);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let lookup_op = encode_lookup("src.txt");
    let savefh_op = encode_savefh();
    let rootfh_op2 = encode_putrootfh();
    let link_op = encode_link(&long_name);
    let compound = encode_compound(
        "link-long",
        &[&seq_op, &rootfh_op, &lookup_op, &savefh_op, &rootfh_op2, &link_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nametoolong as u32);
}

/// LINK with `.` or `..` returns `NFS4ERR_BADNAME`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK9`) to our stricter RFC-targeted expectation.
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_dot_names_badname() {
    let fs = populated_fs(&["src.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq, name) in [(3, 1, "."), (4, 2, "..")] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let lookup_op = encode_lookup("src.txt");
        let savefh_op = encode_savefh();
        let rootfh_op2 = encode_putrootfh();
        let link_op = encode_link(name);
        let compound = encode_compound(
            "link-dot",
            &[&seq_op, &rootfh_op, &lookup_op, &savefh_op, &rootfh_op2, &link_op],
        );
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, _) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Badname as u32);
    }
}

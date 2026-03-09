use super::*;

// ===== CREATE directory (pynfs MKDIR) =====

/// CREATE with type `NF4DIR` creates a directory.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKDIR`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir("newdir");
    let getfh_op = encode_getfh();
    let compound = encode_compound("mkdir", &[&seq_op, &rootfh_op, &create_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);

    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 4);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_CREATE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    // CREATE response: change_info + bitmap
    skip_change_info(&mut resp);
    skip_bitmap(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETFH);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let dir_fh = parse_getfh(&mut resp);
    assert!(!dir_fh.is_empty());
}

/// A newly created directory appears in READDIR results.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKDIR`) plus `st_readdir.py` (CODE `RDDR2`).
/// RFC: RFC 8881 §18.4.3, §18.23.3.
#[tokio::test]
async fn test_create_directory_visible_in_readdir() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // CREATE
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir("visible-dir");
    let compound = encode_compound("mkdir", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // READDIR
    let seq_op = encode_sequence(&sessionid, 2, 0);
    let readdir_op = encode_readdir();
    let compound = encode_compound("readdir", &[&seq_op, &rootfh_op, &readdir_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (_, _, entries, _) = parse_readdir_body(&mut resp);
    let names: Vec<&str> = entries.iter().map(|(_, n, _)| n.as_str()).collect();
    assert!(names.contains(&"visible-dir"));
}

/// CREATE directory with an existing name returns `NFS4ERR_EXIST`.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKDIR`, second-create EXIST behavior).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_existing_name() {
    let fs = fs_with_subdir("existing").await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir("existing");
    let compound = encode_compound("mkdir-exist", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Exist as u32);
}

/// CREATE directory without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `CR8`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let create_op = encode_create_dir("nofh-dir");
    let compound = encode_compound("mkdir-nofh", &[&seq_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// CREATE with a zero-length name returns `NFS4ERR_INVAL`.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `CR9`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_zero_length_name() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir("");
    let compound = encode_compound("mkdir-empty", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Inval as u32);
}

/// CREATE with object type `NF4REG` returns `NFS4ERR_BADTYPE`.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `CR10`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_regular_file_badtype() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_type(NfsFtype4::Reg as u32, "badtype.txt");
    let compound = encode_compound("create-reg", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Badtype as u32);
}

/// CREATE with `.` or `..` returns `NFS4ERR_BADNAME`.
/// Origin: adapted from `pynfs/nfs4.0/servertests/st_create.py` (CODE `CR13`) to our stricter RFC-targeted expectation.
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_dot_names_badname() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    for (xid, seq, name) in [(3, 1, "."), (4, 2, "..")] {
        let seq_op = encode_sequence(&sessionid, seq, 0);
        let rootfh_op = encode_putrootfh();
        let create_op = encode_create_dir(name);
        let compound = encode_compound("mkdir-dot", &[&seq_op, &rootfh_op, &create_op]);
        let mut resp = send_rpc(&mut stream, xid, 1, &compound).await;
        parse_rpc_reply(&mut resp);
        let (status, _, _) = parse_compound_header(&mut resp);
        assert_eq!(status, NfsStat4::Badname as u32);
    }
}

/// CREATE with a long name returns `NFS4ERR_NAMETOOLONG`.
/// Origin: `pynfs/nfs4.0/servertests/st_create.py` (CODE `CR15`).
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_name_too_long() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;
    let long_name = "x".repeat(300);

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir(&long_name);
    let compound = encode_compound("mkdir-long", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nametoolong as u32);
}

/// A created directory reports type `NF4DIR`.
/// Origin: derived from `pynfs/nfs4.0/servertests/st_create.py` (CODE `MKDIR`) plus GETATTR verification.
/// RFC: RFC 8881 §18.4.3.
#[tokio::test]
async fn test_create_directory_type_is_dir() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_dir("typed-dir");
    let getattr_op = encode_getattr(&[FATTR4_TYPE]);
    let compound = encode_compound(
        "mkdir-type",
        &[&seq_op, &rootfh_op, &create_op, &getattr_op],
    );
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    skip_change_info(&mut resp);
    skip_bitmap(&mut resp);

    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_GETATTR);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let fattr = Fattr4::decode(&mut resp).unwrap();
    let mut attr_vals = Bytes::from(fattr.attr_vals);
    let file_type = u32::decode(&mut attr_vals).unwrap();
    assert_eq!(file_type, NfsFtype4::Dir as u32);
}

// ===== CREATE symlink (pynfs SLINK) =====

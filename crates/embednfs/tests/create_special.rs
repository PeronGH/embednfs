//! Tests for CREATE (mkdir, symlink), LINK, READLINK, and COMMIT operations.
//!
//! This module covers non-regular-object creation plus link, readlink, and
//! commit behavior using a mix of pynfs-derived and RFC-driven cases.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;

use bytes::Bytes;
use embednfs_proto::xdr::*;
use embednfs_proto::*;

use common::*;

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

// ===== READLINK (pynfs RDLNK) =====

/// READLINK returns the symlink target.
/// Origin: `pynfs/nfs4.0/servertests/st_readlink.py` (CODE `RDLK1`).
/// RFC: RFC 8881 §18.24.3.
#[tokio::test]
async fn test_readlink_returns_target() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // Create symlink
    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let create_op = encode_create_symlink("rdlink", "/my/target/path");
    let compound = encode_compound("create-link", &[&seq_op, &rootfh_op, &create_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);

    // READLINK
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

// ===== LINK (hard links, pynfs LNK) =====

/// LINK creates a hard link in the target directory.
/// Origin: `pynfs/nfs4.0/servertests/st_link.py` (CODE `LINK1r`).
/// RFC: RFC 8881 §18.9.3.
#[tokio::test]
async fn test_link_creates_hard_link() {
    let fs = populated_fs(&["source.txt"]).await;
    let port = start_server_with_fs(fs).await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    // PUTROOTFH, LOOKUP source.txt (sets current FH to file),
    // SAVEFH (save file FH), PUTROOTFH (set current to dir), LINK
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
    let _ = parse_op_header(&mut resp); // PUTROOTFH
    let _ = parse_op_header(&mut resp); // LOOKUP
    let _ = parse_op_header(&mut resp); // SAVEFH
    let _ = parse_op_header(&mut resp); // PUTROOTFH
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
    // No SAVEFH, so saved FH is empty
    let link_op = encode_link("badlink.txt");
    let compound = encode_compound("link-nosaved", &[&seq_op, &rootfh_op, &link_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    // RFC 8881 §18.9.3: LINK without a saved FH returns NFS4ERR_NOFILEHANDLE
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

// ===== COMMIT (pynfs CMT) =====

/// COMMIT after an `UNSTABLE4` write succeeds.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT1a`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_on_file() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let open_op = encode_open_create("commit.txt");
    let getfh_op = encode_getfh();
    let compound = encode_compound("open-for-commit", &[&seq_op, &rootfh_op, &open_op, &getfh_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let _ = parse_op_header(&mut resp);
    let stateid = skip_open_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let file_fh = parse_getfh(&mut resp);

    let seq_op = encode_sequence(&sessionid, 2, 0);
    let putfh_op = encode_putfh(&file_fh);
    let write_op = encode_write_with_stability(&stateid, 0, UNSTABLE4, b"unstable-data");
    let compound = encode_compound("write-unstable", &[&seq_op, &putfh_op, &write_op]);
    let mut resp = send_rpc(&mut stream, 4, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_WRITE);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let (count, _) = parse_write_res(&mut resp);
    assert_eq!(count, 13);

    let seq_op = encode_sequence(&sessionid, 3, 0);
    let putfh_op = encode_putfh(&file_fh);
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit", &[&seq_op, &putfh_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 5, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, num_results) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Ok as u32);
    assert_eq!(num_results, 3);

    let _ = parse_op_header(&mut resp);
    skip_sequence_res(&mut resp);
    let _ = parse_op_header(&mut resp);
    let (opnum, op_status) = parse_op_header(&mut resp);
    assert_eq!(opnum, OP_COMMIT);
    assert_eq!(op_status, NfsStat4::Ok as u32);
    let verf = decode_fixed_opaque(&mut resp, 8).unwrap();
    assert_eq!(verf.len(), 8);
}

/// COMMIT without a current filehandle returns `NFS4ERR_NOFILEHANDLE`.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT3`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_no_fh() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit-nofh", &[&seq_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Nofilehandle as u32);
}

/// COMMIT on a directory returns `NFS4ERR_ISDIR`.
/// Origin: `pynfs/nfs4.0/servertests/st_commit.py` (CODE `CMT2d`).
/// RFC: RFC 8881 §18.3.3.
#[tokio::test]
async fn test_commit_on_directory() {
    let port = start_server().await;
    let mut stream = connect(port).await;
    let sessionid = setup_session(&mut stream).await;

    let seq_op = encode_sequence(&sessionid, 1, 0);
    let rootfh_op = encode_putrootfh();
    let commit_op = encode_commit(0, 0);
    let compound = encode_compound("commit-dir", &[&seq_op, &rootfh_op, &commit_op]);
    let mut resp = send_rpc(&mut stream, 3, 1, &compound).await;
    parse_rpc_reply(&mut resp);
    let (status, _, _) = parse_compound_header(&mut resp);
    assert_eq!(status, NfsStat4::Isdir as u32);
}

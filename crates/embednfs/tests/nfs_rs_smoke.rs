mod common;

use crate::common::*;

fn expected_names(names: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| (*name).to_string()).collect();
    names.sort();
    names
}

/// nfs-rs completes a basic create, write, commit, read, getattr, and remove workflow.
/// Origin: foreign-client interoperability smoke test via `nfs-rs` against `embednfs`.
/// RFC: RFC 8881 §18.3.3, §18.7.3, §18.16.3, §18.22.3, §18.25.3, §18.32.3.
#[test]
fn test_nfs_rs_basic_file_workflow() {
    let server = start_external_server();
    let mount = mount_nfs_rs(server.port());

    let created = mount.create_path("/smoke-basic.txt", 0o664).unwrap();
    let payload = b"foreign-client-basic".to_vec();
    let written = mount.write(&created.fh, 0, &payload).unwrap();
    assert_eq!(written as usize, payload.len());

    mount.commit(&created.fh, 0, written).unwrap();
    assert_eq!(mount.read(&created.fh, 0, 4096).unwrap(), payload);

    let attrs = mount.getattr(&created.fh).unwrap();
    assert_eq!(attrs.filesize, payload.len() as u64);
    assert_eq!(attrs.file_mode & 0o777, 0o664);

    mount.remove_path("/smoke-basic.txt").unwrap();
    assert_eq!(readdir_names(mount.as_ref(), "/"), Vec::<String>::new());
}

/// nfs-rs completes directory, readdir, rename, symlink, readlink, and cleanup workflows.
/// Origin: foreign-client interoperability smoke test via `nfs-rs` against `embednfs`.
/// RFC: RFC 8881 §18.4.3, §18.23.3, §18.24.3, §18.25.3, §18.26.3.
#[test]
fn test_nfs_rs_namespace_workflow() {
    let server = start_external_server();
    let mount = mount_nfs_rs(server.port());

    let _ = mount.mkdir_path("/smoke-ns", 0o755).unwrap();
    let _ = mount.create_path("/smoke-ns/original.txt", 0o640).unwrap();
    assert_eq!(
        readdir_names(mount.as_ref(), "/smoke-ns"),
        expected_names(&["original.txt"])
    );
    assert_eq!(
        readdirplus_names(mount.as_ref(), "/smoke-ns"),
        expected_names(&["original.txt"])
    );

    let plus_entries = mount.readdirplus_path("/smoke-ns").unwrap();
    assert_eq!(plus_entries.len(), 1);
    assert_eq!(plus_entries[0].file_name, "original.txt");
    assert!(plus_entries[0].attr.is_some());

    mount
        .rename_path("/smoke-ns/original.txt", "/smoke-ns/renamed.txt")
        .unwrap();
    let _ = mount
        .symlink_path("/smoke-ns/renamed.txt", "/smoke-ns/link.txt")
        .unwrap();
    assert_eq!(
        readdir_names(mount.as_ref(), "/smoke-ns"),
        expected_names(&["link.txt", "renamed.txt"])
    );
    assert_eq!(
        mount.readlink_path("/smoke-ns/link.txt").unwrap(),
        "/smoke-ns/renamed.txt"
    );

    mount.remove_path("/smoke-ns/link.txt").unwrap();
    mount.remove_path("/smoke-ns/renamed.txt").unwrap();
    mount.rmdir_path("/smoke-ns").unwrap();
    assert_eq!(readdir_names(mount.as_ref(), "/"), Vec::<String>::new());
}

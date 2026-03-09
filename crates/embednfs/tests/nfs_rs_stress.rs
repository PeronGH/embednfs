mod common;

use std::collections::BTreeMap;

use nfs_rs::Mount;

use crate::common::*;

fn expected_names(model: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    model.keys().cloned().collect()
}

fn assert_managed_state(
    mount: &dyn Mount,
    inbox: &BTreeMap<String, Vec<u8>>,
    archive: &BTreeMap<String, Vec<u8>>,
) {
    assert_eq!(readdir_names(mount, "/stress"), vec!["archive", "inbox"]);
    assert_eq!(readdir_names(mount, "/stress/inbox"), expected_names(inbox));
    assert_eq!(
        readdir_names(mount, "/stress/archive"),
        expected_names(archive)
    );

    for (name, expected) in inbox {
        let path = format!("/stress/inbox/{name}");
        assert_eq!(mount.read_path(&path, 0, 4096).unwrap(), *expected);
    }

    for (name, expected) in archive {
        let path = format!("/stress/archive/{name}");
        assert_eq!(mount.read_path(&path, 0, 4096).unwrap(), *expected);
    }
}

/// nfs-rs can drive a deterministic single-client churn workload without diverging from expected namespace state.
/// Origin: deterministic foreign-client stress test via `nfs-rs` against `embednfs`.
/// RFC: RFC 8881 §18.3.3, §18.16.3, §18.22.3, §18.23.3, §18.25.3, §18.26.3, §18.32.3.
#[ignore = "stress coverage"]
#[test]
fn test_nfs_rs_single_client_deterministic_churn() {
    let server = start_external_server();
    let mount = mount_nfs_rs(server.port());
    let mut inbox = BTreeMap::<String, Vec<u8>>::new();
    let mut archive = BTreeMap::<String, Vec<u8>>::new();

    mount.mkdir_path("/stress", 0o755).unwrap();
    mount.mkdir_path("/stress/inbox", 0o755).unwrap();
    mount.mkdir_path("/stress/archive", 0o755).unwrap();
    assert_managed_state(mount.as_ref(), &inbox, &archive);

    for round in 0..48 {
        let name = format!("item-{round:03}.txt");
        let inbox_path = format!("/stress/inbox/{name}");
        let archive_path = format!("/stress/archive/{name}");

        let created = mount.create_path(&inbox_path, 0o664).unwrap();
        let mut payload = format!("round-{round:03}-payload").into_bytes();
        let written = mount.write(&created.fh, 0, &payload).unwrap();
        assert_eq!(written as usize, payload.len());
        mount.commit(&created.fh, 0, written).unwrap();
        assert_eq!(mount.read(&created.fh, 0, 4096).unwrap(), payload);
        inbox.insert(name.clone(), payload.clone());
        assert_managed_state(mount.as_ref(), &inbox, &archive);

        mount.rename_path(&inbox_path, &archive_path).unwrap();
        inbox.remove(&name);
        archive.insert(name.clone(), payload.clone());

        if round % 2 == 0 {
            let suffix = format!("::append-{round:03}").into_bytes();
            let appended = mount
                .write_path(&archive_path, payload.len() as u64, &suffix)
                .unwrap();
            assert_eq!(appended as usize, suffix.len());
            payload.extend_from_slice(&suffix);
            archive.insert(name.clone(), payload.clone());
        }

        if round % 3 == 2 {
            mount.remove_path(&archive_path).unwrap();
            archive.remove(&name);
        }

        // Keep this first stress lane focused on churn semantics rather than
        // multi-page READDIR traversal, which belongs in a dedicated test.
        while archive.len() > 6 {
            let oldest = archive.keys().next().cloned().unwrap();
            let path = format!("/stress/archive/{oldest}");
            mount.remove_path(&path).unwrap();
            archive.remove(&oldest);
        }

        assert_managed_state(mount.as_ref(), &inbox, &archive);
    }

    for name in archive.keys().cloned().collect::<Vec<_>>() {
        let path = format!("/stress/archive/{name}");
        mount.remove_path(&path).unwrap();
        archive.remove(&name);
    }
    assert_managed_state(mount.as_ref(), &inbox, &archive);

    mount.rmdir_path("/stress/inbox").unwrap();
    mount.rmdir_path("/stress/archive").unwrap();
    mount.rmdir_path("/stress").unwrap();
    assert_eq!(readdir_names(mount.as_ref(), "/"), Vec::<String>::new());
}

mod common;

use std::time::Duration;

use crate::common::*;

const NFS4J_SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

/// nfs4j completes a basic create, write, read, getattr, readdir, rename, and cleanup workflow.
/// Origin: foreign-client interoperability smoke test via the pinned `nfs4j` harness against `embednfs`.
/// RFC: RFC 8881 §18.4.3, §18.7.3, §18.16.3, §18.22.3, §18.23.3, §18.25.3, §18.26.3, §18.32.3.
#[ignore = "requires external nfs4j harness"]
#[test]
fn test_nfs4j_smoke_workflow() {
    let _ = ensure_nfs4j_jar().unwrap_or_else(|err| panic!("{err}"));
    let server = start_external_server();
    let output = run_nfs4j_harness("smoke", server.port(), NFS4J_SMOKE_TIMEOUT)
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(
        output.stdout.contains("smoke ok"),
        "nfs4j smoke did not report success\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
}

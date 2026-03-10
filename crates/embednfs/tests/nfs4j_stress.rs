mod common;

use std::time::Duration;

use crate::common::*;

const NFS4J_STRESS_TIMEOUT: Duration = Duration::from_secs(90);

/// nfs4j sustains the mixed-load stress workload against `embednfs` without losing data or namespace coherence.
/// Origin: foreign-client stress test via the pinned `nfs4j` harness, emphasizing large I/O, overlapping activity, and repeated traversal.
/// RFC: RFC 8881 §18.7.3, §18.16.3, §18.22.3, §18.23.3, §18.25.3, §18.26.3, §18.32.3.
#[ignore = "requires external nfs4j harness"]
#[test]
fn test_nfs4j_parallel_mixed_load_stress() {
    let _ = ensure_nfs4j_jar().unwrap_or_else(|err| panic!("{err}"));
    let server = start_external_server();
    let output = run_nfs4j_harness("stress", server.port(), NFS4J_STRESS_TIMEOUT)
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(
        output.stdout.contains("stress ok"),
        "nfs4j stress did not report success\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
}

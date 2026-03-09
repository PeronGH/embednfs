mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use nfs_rs::Mount;

use crate::common::*;

const IO_WORKERS: usize = 4;
const METADATA_WORKERS: usize = 2;
const TRAVERSAL_WORKERS: usize = 2;
const TOTAL_WORKERS: usize = IO_WORKERS + METADATA_WORKERS + TRAVERSAL_WORKERS;

const STRESS_DURATION: Duration = Duration::from_secs(12);
const STRESS_MOUNT_OPTIONS: NfsRsMountOptions = NfsRsMountOptions {
    rsize: Some(1_048_576),
    wsize: Some(1_048_576),
};

const LARGE_FILE_SIZE: usize = 32 * 1024 * 1024;
const LARGE_CHUNK_SIZE: usize = 1_048_576;
const LARGE_CHUNK_COUNT: usize = LARGE_FILE_SIZE / LARGE_CHUNK_SIZE;
const SAMPLE_SIZE: usize = 4096;
const METADATA_FILE_COUNT: usize = 6;
const METADATA_FILE_SIZE: usize = 64 * 1024;

const MIN_IO_PASSES: usize = 2;
const MIN_METADATA_CYCLES: usize = 50;
const MIN_TRAVERSAL_SCANS: usize = 100;

const STRESS_ROOT: &str = "/stress";
const IO_ROOT: &str = "/stress/io";
const META_ROOT: &str = "/stress/meta";

#[derive(Clone, Copy, Debug)]
struct WorkerReport {
    label: &'static str,
    id: usize,
    completed: usize,
}

fn mount_stress_nfs_rs(port: u16) -> Box<dyn Mount> {
    mount_nfs_rs_with_options(port, STRESS_MOUNT_OPTIONS)
}

fn io_dir(worker_id: usize) -> String {
    format!("{IO_ROOT}/io-{worker_id}")
}

fn hot_file(worker_id: usize) -> String {
    format!("{}/hot.bin", io_dir(worker_id))
}

fn status_file(worker_id: usize) -> String {
    format!("{}/status.txt", io_dir(worker_id))
}

fn metadata_dirs(worker_id: usize) -> (String, String) {
    (
        format!("{META_ROOT}/meta-{worker_id}-a"),
        format!("{META_ROOT}/meta-{worker_id}-b"),
    )
}

fn expected_root_entries() -> Vec<String> {
    let mut entries = vec!["io".to_string(), "meta".to_string()];
    entries.sort();
    entries
}

fn expected_io_root_entries() -> Vec<String> {
    let mut entries = (0..IO_WORKERS)
        .map(|id| format!("io-{id}"))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn expected_meta_root_entries() -> Vec<String> {
    let mut entries = (0..METADATA_WORKERS)
        .flat_map(|id| [format!("meta-{id}-a"), format!("meta-{id}-b")])
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn pattern_byte(worker_id: usize, pass: usize, chunk_idx: usize) -> u8 {
    ((worker_id as u32 * 31 + pass as u32 * 17 + chunk_idx as u32 * 7) % 251 + 1) as u8
}

fn metadata_byte(worker_id: usize, cycle: usize, file_idx: usize) -> u8 {
    ((worker_id as u32 * 19 + cycle as u32 * 11 + file_idx as u32 * 5) % 251 + 1) as u8
}

fn fixed_status_payload(worker_id: usize, pass: usize) -> Vec<u8> {
    format!("worker={worker_id:02} pass={pass:08}\n").into_bytes()
}

fn read_exact_path(
    mount: &dyn Mount,
    path: &str,
    offset: u64,
    count: usize,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::with_capacity(count);
    let mut cursor = offset;
    let mut remaining = count;
    while remaining > 0 {
        let chunk = mount
            .read_path(path, cursor, remaining.min(u32::MAX as usize) as u32)
            .map_err(|err| format!("read_path({path}) failed: {err}"))?;
        if chunk.is_empty() {
            return Err(format!(
                "read_path({path}) returned EOF after {} of {count} bytes",
                data.len()
            ));
        }
        cursor += chunk.len() as u64;
        remaining -= chunk.len();
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn probe_metadata_file(
    mount: &dyn Mount,
    dir_a: &str,
    dir_b: &str,
    name: &str,
) -> Result<Option<String>, String> {
    let path_a = format!("{dir_a}/{name}");
    match mount.getattr_path(&path_a) {
        Ok(_) => return Ok(Some(path_a)),
        Err(err) if !is_transient_metadata_error(&err.to_string()) => {
            return Err(format!("getattr_path({path_a}) failed: {err}"));
        }
        Err(_) => {}
    }

    let path_b = format!("{dir_b}/{name}");
    match mount.getattr_path(&path_b) {
        Ok(_) => return Ok(Some(path_b)),
        Err(err) if !is_transient_metadata_error(&err.to_string()) => {
            return Err(format!("getattr_path({path_b}) failed: {err}"));
        }
        Err(_) => {}
    }

    Ok(None)
}

fn is_transient_metadata_error(err: &str) -> bool {
    err.contains("no such file or directory")
        || err.contains("invalid file handle")
        || err.contains("stale")
}

fn assert_hot_file_samples(
    mount: &dyn Mount,
    path: &str,
    worker_id: usize,
    pass: usize,
) -> Result<(), String> {
    for chunk_idx in [0usize, 8, 16, 24] {
        let offset = (chunk_idx * LARGE_CHUNK_SIZE) as u64;
        let sample = read_exact_path(mount, path, offset, SAMPLE_SIZE)?;
        let expected = pattern_byte(worker_id, pass, chunk_idx);
        if !sample.iter().all(|byte| *byte == expected) {
            return Err(format!(
                "sample mismatch in {path} at chunk {chunk_idx} for pass {pass}"
            ));
        }
    }
    Ok(())
}

fn assert_full_hot_file(
    mount: &dyn Mount,
    path: &str,
    worker_id: usize,
    pass: usize,
) -> Result<(), String> {
    let data = read_exact_path(mount, path, 0, LARGE_FILE_SIZE)?;
    for chunk_idx in 0..LARGE_CHUNK_COUNT {
        let expected = pattern_byte(worker_id, pass, chunk_idx);
        let start = chunk_idx * LARGE_CHUNK_SIZE;
        let end = start + LARGE_CHUNK_SIZE;
        if !data[start..end].iter().all(|byte| *byte == expected) {
            return Err(format!(
                "full-read mismatch in {path} at chunk {chunk_idx} for pass {pass}"
            ));
        }
    }
    Ok(())
}

fn write_hot_file_pass(
    mount: &dyn Mount,
    path: &str,
    worker_id: usize,
    pass: usize,
) -> Result<(), String> {
    let mut chunk = vec![0u8; LARGE_CHUNK_SIZE];
    for chunk_idx in 0..LARGE_CHUNK_COUNT {
        chunk.fill(pattern_byte(worker_id, pass, chunk_idx));
        mount
            .write_path(path, (chunk_idx * LARGE_CHUNK_SIZE) as u64, &chunk)
            .map_err(|err| format!("write_path({path}) failed: {err}"))?;
    }
    mount
        .commit_path(path, 0, LARGE_FILE_SIZE as u32)
        .map_err(|err| format!("commit_path({path}) failed: {err}"))?;
    Ok(())
}

fn setup_stress_tree(mount: &dyn Mount) -> Result<(), String> {
    mount
        .mkdir_path(STRESS_ROOT, 0o755)
        .map_err(|err| format!("mkdir_path({STRESS_ROOT}) failed: {err}"))?;
    mount
        .mkdir_path(IO_ROOT, 0o755)
        .map_err(|err| format!("mkdir_path({IO_ROOT}) failed: {err}"))?;
    mount
        .mkdir_path(META_ROOT, 0o755)
        .map_err(|err| format!("mkdir_path({META_ROOT}) failed: {err}"))?;

    for worker_id in 0..IO_WORKERS {
        let dir = io_dir(worker_id);
        mount
            .mkdir_path(&dir, 0o755)
            .map_err(|err| format!("mkdir_path({dir}) failed: {err}"))?;
        mount
            .create_path(&hot_file(worker_id), 0o664)
            .map_err(|err| format!("create_path({}) failed: {err}", hot_file(worker_id)))?;
        write_hot_file_pass(mount, &hot_file(worker_id), worker_id, 0)?;
        mount
            .create_path(&status_file(worker_id), 0o644)
            .map_err(|err| format!("create_path({}) failed: {err}", status_file(worker_id)))?;
        let status = fixed_status_payload(worker_id, 0);
        mount
            .write_path(&status_file(worker_id), 0, &status)
            .map_err(|err| format!("write_path({}) failed: {err}", status_file(worker_id)))?;
    }

    for worker_id in 0..METADATA_WORKERS {
        let (dir_a, dir_b) = metadata_dirs(worker_id);
        mount
            .mkdir_path(&dir_a, 0o755)
            .map_err(|err| format!("mkdir_path({dir_a}) failed: {err}"))?;
        mount
            .mkdir_path(&dir_b, 0o755)
            .map_err(|err| format!("mkdir_path({dir_b}) failed: {err}"))?;
        for file_idx in 0..METADATA_FILE_COUNT {
            let path = format!("{dir_a}/file-{file_idx}.bin");
            let created = mount
                .create_path(&path, 0o640)
                .map_err(|err| format!("create_path({path}) failed: {err}"))?;
            let payload = vec![metadata_byte(worker_id, 0, file_idx); METADATA_FILE_SIZE];
            mount
                .write(&created.fh, 0, &payload)
                .map_err(|err| format!("write({path}) failed: {err}"))?;
        }
    }

    Ok(())
}

fn io_worker(
    worker_id: usize,
    port: u16,
    start_barrier: Arc<Barrier>,
    deadline: Instant,
) -> Result<WorkerReport, String> {
    let mount = mount_stress_nfs_rs(port);
    let hot_path = hot_file(worker_id);
    let status_path = status_file(worker_id);
    let mut passes = 0usize;

    start_barrier.wait();
    while Instant::now() < deadline {
        let pass = passes + 1;
        write_hot_file_pass(mount.as_ref(), &hot_path, worker_id, pass)?;
        let attrs = mount
            .getattr_path(&hot_path)
            .map_err(|err| format!("getattr_path({hot_path}) failed: {err}"))?;
        if attrs.filesize != LARGE_FILE_SIZE as u64 {
            return Err(format!(
                "unexpected size for {hot_path}: {} != {}",
                attrs.filesize, LARGE_FILE_SIZE
            ));
        }

        assert_hot_file_samples(mount.as_ref(), &hot_path, worker_id, pass)?;

        if pass.is_multiple_of(4) {
            assert_full_hot_file(mount.as_ref(), &hot_path, worker_id, pass)?;
        }

        let status = fixed_status_payload(worker_id, pass);
        mount
            .write_path(&status_path, 0, &status)
            .map_err(|err| format!("write_path({status_path}) failed: {err}"))?;
        passes += 1;
    }

    if passes < MIN_IO_PASSES {
        return Err(format!(
            "io worker {worker_id} completed only {passes} passes"
        ));
    }

    Ok(WorkerReport {
        label: "io",
        id: worker_id,
        completed: passes,
    })
}

fn metadata_worker(
    worker_id: usize,
    port: u16,
    start_barrier: Arc<Barrier>,
    deadline: Instant,
) -> Result<WorkerReport, String> {
    let mount = mount_stress_nfs_rs(port);
    let (dir_a, dir_b) = metadata_dirs(worker_id);
    let mut in_dir_a = [true; METADATA_FILE_COUNT];
    let mut cycles = 0usize;

    start_barrier.wait();
    while Instant::now() < deadline {
        let primary = cycles % METADATA_FILE_COUNT;
        let secondary = (cycles + 3) % METADATA_FILE_COUNT;

        let primary_from = if in_dir_a[primary] { &dir_a } else { &dir_b };
        let primary_to = if in_dir_a[primary] { &dir_b } else { &dir_a };
        let primary_from_path = format!("{primary_from}/file-{primary}.bin");
        let primary_to_path = format!("{primary_to}/file-{primary}.bin");
        mount
            .rename_path(&primary_from_path, &primary_to_path)
            .map_err(|err| {
                format!("rename_path({primary_from_path} -> {primary_to_path}) failed: {err}")
            })?;
        in_dir_a[primary] = !in_dir_a[primary];

        let rewrite = vec![metadata_byte(worker_id, cycles, primary); METADATA_FILE_SIZE];
        mount
            .write_path(&primary_to_path, 0, &rewrite)
            .map_err(|err| format!("write_path({primary_to_path}) failed: {err}"))?;
        let attrs = mount
            .getattr_path(&primary_to_path)
            .map_err(|err| format!("getattr_path({primary_to_path}) failed: {err}"))?;
        if attrs.filesize != METADATA_FILE_SIZE as u64 {
            return Err(format!(
                "unexpected size for {primary_to_path}: {} != {}",
                attrs.filesize, METADATA_FILE_SIZE
            ));
        }

        let secondary_current_dir = if in_dir_a[secondary] { &dir_a } else { &dir_b };
        let secondary_next_dir = if in_dir_a[secondary] { &dir_b } else { &dir_a };
        let secondary_current_path = format!("{secondary_current_dir}/file-{secondary}.bin");
        let secondary_next_path = format!("{secondary_next_dir}/file-{secondary}.bin");

        mount
            .remove_path(&secondary_current_path)
            .map_err(|err| format!("remove_path({secondary_current_path}) failed: {err}"))?;
        let created = mount
            .create_path(&secondary_next_path, 0o640)
            .map_err(|err| format!("create_path({secondary_next_path}) failed: {err}"))?;
        let replacement = vec![metadata_byte(worker_id, cycles + 1, secondary); METADATA_FILE_SIZE];
        mount
            .write(&created.fh, 0, &replacement)
            .map_err(|err| format!("write({secondary_next_path}) failed: {err}"))?;
        let sample = read_exact_path(mount.as_ref(), &secondary_next_path, 0, SAMPLE_SIZE)?;
        let expected = metadata_byte(worker_id, cycles + 1, secondary);
        if !sample.iter().all(|byte| *byte == expected) {
            return Err(format!(
                "sample mismatch in {secondary_next_path} for cycle {cycles}"
            ));
        }
        in_dir_a[secondary] = !in_dir_a[secondary];

        let names_a = readdir_names(mount.as_ref(), &dir_a);
        let names_b = readdir_names(mount.as_ref(), &dir_b);
        if names_a.len() > METADATA_FILE_COUNT || names_b.len() > METADATA_FILE_COUNT {
            return Err(format!(
                "metadata directory entry count exceeded bounds: {} + {}",
                names_a.len(),
                names_b.len()
            ));
        }
        if names_a.len() + names_b.len() != METADATA_FILE_COUNT {
            return Err(format!(
                "metadata directory entry count drifted: {} + {} != {}",
                names_a.len(),
                names_b.len(),
                METADATA_FILE_COUNT
            ));
        }

        cycles += 1;
    }

    if cycles < MIN_METADATA_CYCLES {
        return Err(format!(
            "metadata worker {worker_id} completed only {cycles} cycles"
        ));
    }

    Ok(WorkerReport {
        label: "metadata",
        id: worker_id,
        completed: cycles,
    })
}

fn traversal_worker(
    worker_id: usize,
    port: u16,
    start_barrier: Arc<Barrier>,
    deadline: Instant,
) -> Result<WorkerReport, String> {
    let mount = mount_stress_nfs_rs(port);
    let expected_root = expected_root_entries();
    let expected_io_root = expected_io_root_entries();
    let expected_meta_root = expected_meta_root_entries();
    let mut scans = 0usize;

    start_barrier.wait();
    while Instant::now() < deadline {
        if readdir_names(mount.as_ref(), STRESS_ROOT) != expected_root {
            return Err("root directory listing changed unexpectedly".to_string());
        }
        if readdir_names(mount.as_ref(), IO_ROOT) != expected_io_root {
            return Err("io root directory listing changed unexpectedly".to_string());
        }
        if readdir_names(mount.as_ref(), META_ROOT) != expected_meta_root {
            return Err("meta root directory listing changed unexpectedly".to_string());
        }

        for io_worker_id in 0..IO_WORKERS {
            let dir = io_dir(io_worker_id);
            if readdirplus_names(mount.as_ref(), &dir)
                != vec!["hot.bin".to_string(), "status.txt".to_string()]
            {
                return Err(format!("unexpected entries in {dir}"));
            }

            let attrs = mount
                .getattr_path(&hot_file(io_worker_id))
                .map_err(|err| format!("getattr_path({}) failed: {err}", hot_file(io_worker_id)))?;
            if attrs.filesize != LARGE_FILE_SIZE as u64 {
                return Err(format!(
                    "unexpected hot file size in {}: {}",
                    hot_file(io_worker_id),
                    attrs.filesize
                ));
            }

            let sample_offset =
                ((scans + worker_id + io_worker_id) % LARGE_CHUNK_COUNT * LARGE_CHUNK_SIZE) as u64;
            let sample = read_exact_path(
                mount.as_ref(),
                &hot_file(io_worker_id),
                sample_offset,
                SAMPLE_SIZE,
            )?;
            if sample.len() != SAMPLE_SIZE {
                return Err(format!(
                    "short hot file sample in {}",
                    hot_file(io_worker_id)
                ));
            }

            let status = read_exact_path(mount.as_ref(), &status_file(io_worker_id), 0, 24)?;
            if !status.starts_with(b"worker=") {
                return Err(format!(
                    "unexpected status payload in {}",
                    status_file(io_worker_id)
                ));
            }
        }

        for metadata_worker_id in 0..METADATA_WORKERS {
            let (dir_a, dir_b) = metadata_dirs(metadata_worker_id);
            let names_a = readdir_names(mount.as_ref(), &dir_a);
            let names_b = readdir_names(mount.as_ref(), &dir_b);
            if names_a.len() > METADATA_FILE_COUNT || names_b.len() > METADATA_FILE_COUNT {
                return Err(format!(
                    "metadata scan found too many entries: {} + {}",
                    names_a.len(),
                    names_b.len()
                ));
            }

            for name in names_a.iter().chain(names_b.iter()).take(2) {
                let Some(path) = probe_metadata_file(mount.as_ref(), &dir_a, &dir_b, name)? else {
                    continue;
                };
                let attrs = match mount.getattr_path(&path) {
                    Ok(attrs) => attrs,
                    Err(err) if is_transient_metadata_error(&err.to_string()) => continue,
                    Err(err) => return Err(format!("getattr_path({path}) failed: {err}")),
                };
                if attrs.filesize != METADATA_FILE_SIZE as u64 {
                    continue;
                }
                let sample = match read_exact_path(mount.as_ref(), &path, 0, SAMPLE_SIZE) {
                    Ok(sample) => sample,
                    Err(err) if is_transient_metadata_error(&err) => continue,
                    Err(err) => return Err(err),
                };
                if sample.len() != SAMPLE_SIZE {
                    return Err(format!("short metadata sample in {path}"));
                }
            }
        }

        scans += 1;
    }

    if scans < MIN_TRAVERSAL_SCANS {
        return Err(format!(
            "traversal worker {worker_id} completed only {scans} scans"
        ));
    }

    Ok(WorkerReport {
        label: "traversal",
        id: worker_id,
        completed: scans,
    })
}

/// nfs-rs can sustain a concurrent mixed-load stress workload for about twelve seconds without losing data or namespace coherence.
/// Origin: Apple-informed foreign-client stress test via `nfs-rs`, emphasizing large I/O, overlapping activity, and repeated traversal.
/// RFC: RFC 8881 §18.3.3, §18.7.3, §18.22.3, §18.23.3, §18.25.3, §18.26.3, §18.32.3.
#[ignore = "stress coverage"]
#[test]
fn test_nfs_rs_parallel_mixed_load_stress() {
    let server = start_external_server();
    let setup_mount = mount_stress_nfs_rs(server.port());
    setup_stress_tree(setup_mount.as_ref()).unwrap();

    let deadline = Instant::now() + STRESS_DURATION;
    let start_barrier = Arc::new(Barrier::new(TOTAL_WORKERS));
    let mut handles = Vec::with_capacity(TOTAL_WORKERS);

    for worker_id in 0..IO_WORKERS {
        let port = server.port();
        let start_barrier = Arc::clone(&start_barrier);
        handles.push(thread::spawn(move || {
            io_worker(worker_id, port, start_barrier, deadline)
        }));
    }

    for worker_id in 0..METADATA_WORKERS {
        let port = server.port();
        let start_barrier = Arc::clone(&start_barrier);
        handles.push(thread::spawn(move || {
            metadata_worker(worker_id, port, start_barrier, deadline)
        }));
    }

    for worker_id in 0..TRAVERSAL_WORKERS {
        let port = server.port();
        let start_barrier = Arc::clone(&start_barrier);
        handles.push(thread::spawn(move || {
            traversal_worker(worker_id, port, start_barrier, deadline)
        }));
    }

    let mut reports = Vec::with_capacity(TOTAL_WORKERS);
    for handle in handles {
        let report = handle.join().unwrap().unwrap_or_else(|err| panic!("{err}"));
        reports.push(report);
    }

    assert_eq!(reports.len(), TOTAL_WORKERS);
    for report in reports {
        assert!(
            report.completed > 0,
            "{} worker {} made no progress",
            report.label,
            report.id
        );
    }
}

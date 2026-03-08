//! End-to-end tests using libnfs (a battle-tested NFSv4 C client library).
//!
//! These tests compile and run a C program that exercises the server using
//! libnfs, validating the full protocol stack against a real, independent
//! NFSv4 client implementation.

use std::process::Command;
use std::sync::Once;
use std::time::Duration;

use embednfs::{MemFs, NfsServer};

static COMPILE_ONCE: Once = Once::new();
static mut COMPILE_SUCCESS: bool = false;

const LIBNFS_TEST_C: &str = include_str!("libnfs_e2e.c");

fn compile_test_binary() {
    COMPILE_ONCE.call_once(|| {
        // Write source to temp file
        std::fs::write("/tmp/embednfs_e2e_test.c", LIBNFS_TEST_C).unwrap();

        let status = Command::new("gcc")
            .args([
                "-o",
                "/tmp/embednfs_e2e_test",
                "/tmp/embednfs_e2e_test.c",
                "-lnfs",
                "-Wall",
                "-Wextra",
            ])
            .status()
            .expect("failed to run gcc — is gcc installed?");

        unsafe {
            COMPILE_SUCCESS = status.success();
        }
    });

    assert!(
        unsafe { COMPILE_SUCCESS },
        "failed to compile libnfs test program — is libnfs-dev installed?"
    );
}

async fn start_server() -> u16 {
    let server = NfsServer::new(MemFs::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });
    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

fn run_libnfs_test(port: u16, test_name: &str) -> std::process::Output {
    Command::new("/tmp/embednfs_e2e_test")
        .args([&port.to_string(), test_name])
        .output()
        .expect("failed to execute libnfs test binary")
}

fn assert_test_passed(output: &std::process::Output, test_name: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "libnfs test '{test_name}' failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
        output.status,
    );
    eprintln!("--- libnfs {test_name} ---\n{stdout}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_mount() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "mount");
    assert_test_passed(&output, "mount");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_create_write_read() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "create_write_read");
    assert_test_passed(&output, "create_write_read");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_stat() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "stat");
    assert_test_passed(&output, "stat");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_mkdir_readdir() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "mkdir_readdir");
    assert_test_passed(&output, "mkdir_readdir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_rename() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "rename");
    assert_test_passed(&output, "rename");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_unlink_rmdir() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "unlink_rmdir");
    assert_test_passed(&output, "unlink_rmdir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_libnfs_full() {
    compile_test_binary();
    let port = start_server().await;
    let output = run_libnfs_test(port, "full");
    assert_test_passed(&output, "full");
}

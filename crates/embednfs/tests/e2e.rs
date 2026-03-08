//! End-to-end tests using the nfs4_client crate (a real NFSv4.1 client).
//!
//! These tests validate the server against a properly implemented,
//! independent NFSv4.1 client — not hand-rolled RPC encoding.

use std::net::TcpStream;
use std::time::Duration;

use embednfs::{FileSystem, MemFs, NfsServer};
use nfs4_client::Client;

async fn start_server() -> u16 {
    start_server_with_fs(MemFs::new()).await
}

async fn start_server_with_fs(fs: MemFs) -> u16 {
    let server = NfsServer::new(fs);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
}

/// Full session establishment: EXCHANGE_ID → CREATE_SESSION → RECLAIM_COMPLETE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_session_establishment() {
    let port = start_server().await;
    let mut transport = connect(port);
    let _client = Client::new(&mut transport).unwrap();
}

/// GETATTR on the root directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_getattr_root() {
    let port = start_server().await;
    let mut transport = connect(port);
    let mut client = Client::new(&mut transport).unwrap();
    let _res = client.get_attr(&mut transport, "/").unwrap();
    // If get_attr succeeded, the server returned valid attributes.
}

/// LOOKUP a file that exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_lookup_file() {
    let fs = MemFs::new();
    fs.create_file("/hello.txt").await.unwrap();
    let port = start_server_with_fs(fs).await;
    let mut transport = connect(port);
    let mut client = Client::new(&mut transport).unwrap();
    let _fh = client.look_up(&mut transport, "hello.txt").unwrap();
}

/// LOOKUP a file that does not exist should fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_lookup_nonexistent() {
    let port = start_server().await;
    let mut transport = connect(port);
    let mut client = Client::new(&mut transport).unwrap();
    let result = client.look_up(&mut transport, "nonexistent.txt");
    assert!(result.is_err());
}

/// Create a file via OPEN, write data, read it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_create_write_read() {
    let port = start_server().await;
    let mut transport = connect(port);
    let mut client = Client::new(&mut transport).unwrap();

    // Get root filehandle.
    let root_fh = client.look_up(&mut transport, ".").unwrap_or_else(|_| {
        // Some servers don't support looking up "."; use PutRootFh+GetFh instead.
        // For now, just skip if this fails.
        panic!("could not get root fh");
    });

    // Create a file.
    let fh = client
        .create_file(&mut transport, root_fh, "test.txt")
        .unwrap();

    // Write data.
    let data = b"hello from nfs4_client!".to_vec();
    let write_res = client
        .write(&mut transport, fh.clone(), 0, data.clone())
        .unwrap();
    assert_eq!(write_res.count as usize, data.len());

    // Read it back.
    let mut buf = Vec::new();
    client.read_all(&mut transport, fh, &mut buf).unwrap();
    assert_eq!(buf, data);
}

/// Write at multiple offsets and verify reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_write_multiple_offsets() {
    let fs = MemFs::new();
    fs.create_file("/data.bin").await.unwrap();
    let port = start_server_with_fs(fs).await;
    let mut transport = connect(port);
    let mut client = Client::new(&mut transport).unwrap();

    let fh = client.look_up(&mut transport, "data.bin").unwrap();

    // Write "AAAA" at offset 0.
    client
        .write(&mut transport, fh.clone(), 0, b"AAAA".to_vec())
        .unwrap();

    // Write "BBBB" at offset 4.
    client
        .write(&mut transport, fh.clone(), 4, b"BBBB".to_vec())
        .unwrap();

    // Read all.
    let mut buf = Vec::new();
    client.read_all(&mut transport, fh, &mut buf).unwrap();
    assert_eq!(buf, b"AAAABBBB");
}

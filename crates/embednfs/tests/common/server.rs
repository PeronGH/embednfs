use std::time::Duration;

use tokio::net::TcpStream;

use embednfs::{FileSystem, MemFs, NfsServer};

pub async fn start_server() -> u16 {
    start_server_with_fs(MemFs::new()).await
}

pub async fn start_server_with_fs<F: FileSystem>(fs: F) -> u16 {
    let server = NfsServer::new(fs);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    std::mem::drop(tokio::spawn(async move {
        server.serve(listener).await.unwrap();
    }));

    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

pub async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap()
}

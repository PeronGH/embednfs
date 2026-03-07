/// Example NFSv4.1 server using the in-memory filesystem.
use nfs4_server::{NfsServer, MemFs};
use tracing_subscriber;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let fs = MemFs::new();
    let server = NfsServer::new(fs);

    // Listen on port 2049 (standard NFS port)
    server.listen("0.0.0.0:2049").await
}

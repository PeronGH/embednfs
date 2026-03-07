/// Example NFSv4.1 server using the in-memory filesystem.
use nfs4_server::{NfsServer, MemFs};
use tracing_subscriber;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Set RUST_LOG=debug to see per-operation traces (useful for debugging Finder issues)
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let fs = MemFs::new();
    let server = NfsServer::new(fs);

    // Listen on port 2049 (standard NFS port)
    server.listen("0.0.0.0:2049").await
}

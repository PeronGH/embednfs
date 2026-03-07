/// Example NFSv4.1 server using the in-memory filesystem.
use embednfs::{MemFs, NfsServer};
use tracing_subscriber;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let fs = MemFs::new();
    let server = NfsServer::new(fs);

    // Listen on port 2049 (standard NFS port)
    server.listen("0.0.0.0:2049").await
}

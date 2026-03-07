# embednfs

An embeddable NFSv4.1 server library in Rust. Implement a path-based filesystem trait; the library handles the wire protocol, session management, and serves it over TCP.

The primary use case is embedding as a localhost NFS server — a FUSE replacement that needs no kernel modules. macOS and Linux ship NFSv4.1 clients in-kernel, so the mount just works.

## Architecture

This is a Cargo workspace with three crates:

- **`embednfs-proto`** — XDR encoding/decoding and NFSv4.1 protocol types (RFC 8881, RFC 5531)
- **`embednfs`** — Embeddable server library with filesystem trait, session management, and COMPOUND handler
- **`embednfs-cli`** — CLI/demo binary for running the server locally

## Quick Start

```rust
use embednfs::{MemFs, NfsServer};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let fs = MemFs::new();
    let server = NfsServer::new(fs);
    server.listen("0.0.0.0:2049").await
}
```

Then mount:

```bash
# Linux
mkdir -p /mnt/embednfs
mount -t nfs4 -o vers=4.1,proto=tcp,port=2049 127.0.0.1:/ /mnt/embednfs

# macOS
mkdir -p /tmp/embednfs
mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ /tmp/embednfs
```

Note: on macOS, `vers=4` means NFSv4.0. Use `vers=4.1` explicitly.

## Implementing a Filesystem

Implement the `FileSystem` trait:

```rust
use async_trait::async_trait;
use embednfs::fs::*;

struct MyFs;

#[async_trait]
impl FileSystem for MyFs {
    async fn metadata(&self, path: &str) -> FsResult<Metadata> { /* ... */ }
    async fn list(&self, path: &str) -> FsResult<Vec<PathDirEntry>> { /* ... */ }
    async fn read(&self, path: &str, offset: u64, count: u32) -> FsResult<Vec<u8>> { /* ... */ }
    async fn create_file(&self, path: &str) -> FsResult<()> { /* ... */ }
    async fn create_dir(&self, path: &str) -> FsResult<()> { /* ... */ }
    async fn create_symlink(&self, path: &str, target: &str) -> FsResult<()> { /* ... */ }
    async fn read_symlink(&self, path: &str) -> FsResult<String> { /* ... */ }
    async fn remove(&self, path: &str, expected_revision: Option<&str>) -> FsResult<()> { /* ... */ }
    async fn rename(&self, from: &str, to: &str, expected_revision: Option<&str>) -> FsResult<()> { /* ... */ }
}
```

The server handles filehandles, state, and path traversal. Your implementation only deals with paths, content, and metadata.

## Supported Operations

| Operation | Status |
|-----------|--------|
| EXCHANGE_ID / CREATE_SESSION | Supported |
| SEQUENCE | Supported |
| PUTROOTFH / PUTFH / GETFH | Supported |
| LOOKUP / LOOKUPP | Supported |
| GETATTR / SETATTR | Supported (`SETATTR` is intentionally limited) |
| ACCESS | Supported |
| OPEN / CLOSE / OPEN_DOWNGRADE | Supported |
| READ / WRITE / COMMIT | Supported |
| CREATE (mkdir, symlink) | Supported |
| READDIR | Supported |
| READLINK | Supported |
| REMOVE | Supported |
| RENAME | Supported |
| LINK | Not supported |
| BIND_CONN_TO_SESSION | Supported |
| SAVEFH / RESTOREFH | Supported |
| SECINFO / SECINFO_NO_NAME | Supported |
| RECLAIM_COMPLETE | Supported |
| DESTROY_SESSION / DESTROY_CLIENTID | Supported |
| DELEGRETURN / FREE_STATEID | Supported |

## Testing

```bash
# Unit tests
cargo test --workspace

# End-to-end with libnfs (requires libnfs-dev)
cargo run --release &
# Then run the libnfs test client
```

## License

MIT

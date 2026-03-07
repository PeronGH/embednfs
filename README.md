# embednfs

A production-quality NFSv4.1 server library in Rust. Implement a filesystem trait; the library handles the wire protocol, state management, and serves it over TCP.

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
mount -t nfs4 -o vers=4.1,proto=tcp,port=2049 127.0.0.1:/ /mnt/nfs

# macOS
mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ /mnt/nfs
```

Note: on macOS, `vers=4` means NFSv4.0. Use `vers=4.1` explicitly.

## Implementing a Filesystem

Implement the `NfsFileSystem` trait:

```rust
use async_trait::async_trait;
use embednfs::fs::*;

struct MyFs;

#[async_trait]
impl NfsFileSystem for MyFs {
    async fn getattr(&self, id: FileId) -> NfsResult<FileAttr> { /* ... */ }
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId> { /* ... */ }
    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>> { /* ... */ }
    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)> { /* ... */ }
    // ... and other operations
}
```

The root directory must have `FileId = 1`. The server handles all protocol details — your implementation only deals with files, directories, and metadata.

## Supported Operations

| Operation | Status |
|-----------|--------|
| EXCHANGE_ID / CREATE_SESSION | Supported |
| SEQUENCE | Supported |
| PUTROOTFH / PUTFH / GETFH | Supported |
| LOOKUP / LOOKUPP | Supported |
| GETATTR / SETATTR | Supported |
| ACCESS | Supported |
| OPEN / CLOSE / OPEN_DOWNGRADE | Supported |
| READ / WRITE / COMMIT | Supported |
| CREATE (mkdir, symlink) | Supported |
| READDIR | Supported |
| READLINK | Supported |
| REMOVE | Supported |
| RENAME | Supported |
| LINK | Supported |
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

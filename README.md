# nfsserve4-rs

A production-quality NFSv4.1 (and NFSv4.0) server library in Rust. Implement a filesystem trait; the library handles the wire protocol, state management, and serves it over TCP.

The primary use case is embedding as a localhost NFS server — a FUSE replacement that needs no kernel modules. macOS and Linux ship NFSv4 clients in-kernel, so the mount just works.

## Architecture

This is a Cargo workspace with three crates:

- **`nfs4-proto`** — XDR encoding/decoding and all NFSv4 protocol types (RFC 8881, RFC 5531)
- **`nfs4-server`** — Server library with filesystem trait, session management, and COMPOUND handler
- **`nfs4-serve`** — Example binary using the in-memory filesystem

## Quick Start

```rust
use nfs4_server::{NfsServer, MemFs};

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
mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 127.0.0.1:/ /mnt/nfs

# macOS
mount -t nfs -o vers=4,tcp,port=2049 127.0.0.1:/ /mnt/nfs
```

## Implementing a Filesystem

Implement the `NfsFileSystem` trait:

```rust
use async_trait::async_trait;
use nfs4_server::fs::*;

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
| EXCHANGE_ID / CREATE_SESSION | Supported (NFSv4.1) |
| SETCLIENTID / SETCLIENTID_CONFIRM | Supported (NFSv4.0) |
| SEQUENCE | Supported |
| PUTROOTFH / PUTFH / GETFH | Supported |
| LOOKUP / LOOKUPP | Supported |
| GETATTR / SETATTR | Supported |
| ACCESS | Supported |
| OPEN / CLOSE / OPEN_CONFIRM | Supported |
| READ / WRITE / COMMIT | Supported |
| CREATE (mkdir, symlink) | Supported |
| READDIR | Supported |
| READLINK | Supported |
| REMOVE | Supported |
| RENAME | Supported |
| LINK | Supported |
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

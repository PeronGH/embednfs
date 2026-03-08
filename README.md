# embednfs

An embeddable NFSv4.1 server library in Rust. You implement a small filesystem trait; the library handles the wire protocol, sessions, filehandles, locking, and TCP serving.

The implementation target is Apple/macOS NFSv4.1 client compatibility first, with a localhost FUSE-replacement use case. The public API is intentionally opinionated and minimal.

## Support Boundary

This project currently makes two important non-promises:

- It does **not** guarantee correct or robust behavior over a real network. The target deployment is localhost. Running it over non-localhost transport may work in some cases, but that is not a supported or validated use case.
- It does **not** guarantee correct behavior for non-macOS clients. The implementation and live validation target the macOS kernel NFSv4.1 client and Finder workflows. Other clients may work, but they are not a compatibility target.

In short: the supported target is **macOS over localhost**.

## Architecture

This is a Cargo workspace with three crates:

- **`embednfs-proto`** — XDR encoding/decoding and NFSv4.1 protocol types
- **`embednfs`** — Embeddable server library with the filesystem traits and COMPOUND handler
- **`embednfs-cli`** — CLI/demo binary for running the server locally

## Quick Start

```rust
use embednfs::{MemFs, NfsServer};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let fs = MemFs::new();
    let server = NfsServer::new(fs);
    server.listen("127.0.0.1:2049").await
}
```

Then mount:

```bash
# macOS
mkdir -p /tmp/embednfs
mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ /tmp/embednfs
```

Note: on macOS, `vers=4` means NFSv4.0. Use `vers=4.1` explicitly.

Non-macOS clients are not a supported compatibility target, even if they happen to mount successfully.

## Filesystem API

The public API is split into a small required core trait plus opt-in extension traits.

### Core Trait

```rust
use async_trait::async_trait;
use embednfs::{DirEntry, FileId, FsInfo, NfsFileSystem, NodeInfo, NfsResult};

#[async_trait]
pub trait NfsFileSystem: Send + Sync + 'static {
    fn root(&self) -> FileId { 1 }

    async fn stat(&self, id: FileId) -> NfsResult<NodeInfo>;
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;
    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId>;
    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>>;
    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)>;
    async fn write(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32>;
    async fn truncate(&self, id: FileId, size: u64) -> NfsResult<()>;
    async fn create_file(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;
    async fn create_dir(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;
    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()>;
    async fn rename(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()>;

    fn fs_info(&self) -> FsInfo {
        FsInfo::default()
    }
}
```

Core types:

- `NodeInfo { kind, size }` is the only required per-node metadata
- `DirEntry { fileid, name }` is the only required directory-entry payload
- `FileId` identifies real filesystem objects only; the server synthesizes attrdirs, named-attr files, and other protocol-only objects internally

### Extension Traits

The server will use these when present:

- `NfsNamedAttrs` for macOS named attributes / xattrs / named streams
- `NfsSymlinks` for `CREATE symlink` and `READLINK`
- `NfsHardLinks` for `LINK`
- `NfsSync` for explicit `COMMIT`

If an extension trait is absent, the server returns the appropriate NFS unsupported/type errors and does not advertise the feature where that matters.

## Apple-Focused Operation Support

Implemented for normal Apple/macOS client flows:

- `EXCHANGE_ID`, `CREATE_SESSION`, `SEQUENCE`, `DESTROY_SESSION`, `DESTROY_CLIENTID`
- `PUTROOTFH`, `PUTFH`, `GETFH`, `LOOKUP`, `LOOKUPP`, `SAVEFH`, `RESTOREFH`
- `GETATTR`, `ACCESS`, `OPEN`, `CLOSE`, `OPEN_DOWNGRADE`
- `READ`, `WRITE`, `COMMIT`, `READDIR`, `SETATTR`
- `CREATE` for directories and symlinks
- `REMOVE`, `RENAME`
- `LOCK`, `LOCKT`, `LOCKU`
- `SECINFO_NO_NAME`
- `OPENATTR`
- `NVERIFY`
- `RECLAIM_COMPLETE`, `FREE_STATEID`

Supported through extensions:

- `READLINK`
- `LINK`
- macOS named-attribute and xattr flows behind `OPENATTR`

Kept as cheap compatibility ops:

- `SECINFO`
- `PUTPUBFH`
- `VERIFY`
- `TEST_STATEID`
- `DELEGPURGE`
- `BIND_CONN_TO_SESSION`
- `DELEGRETURN`

Explicitly unsupported:

- `BACKCHANNEL_CTL`
- `GETDEVICEINFO`, `GETDEVICELIST`
- `GET_DIR_DELEGATION`
- `LAYOUTGET`, `LAYOUTRETURN`, `LAYOUTCOMMIT`
- `SET_SSV`
- `WANT_DELEGATION`

Rejected in NFSv4.1 because they are v4.0-only:

- `OPEN_CONFIRM`
- `RENEW`
- `SETCLIENTID`
- `SETCLIENTID_CONFIRM`
- `RELEASE_LOCKOWNER`

## Testing

```bash
cargo clippy --workspace
cargo test --workspace
```

The integration suite exercises the full RPC path over TCP and includes raw `OPENATTR`/named-attribute flows for macOS-style clients.

## License

MIT

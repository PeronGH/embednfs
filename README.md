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
mkdir -p /mnt/embednfs
mount -t nfs4 -o vers=4.1,proto=tcp,port=2049 127.0.0.1:/ /mnt/embednfs

# macOS
mkdir -p /tmp/embednfs
mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ /tmp/embednfs
```

Note: on macOS, `vers=4` means NFSv4.0. Use `vers=4.1` explicitly.

## Implementing a Filesystem

Implement the full `NfsFileSystem` surface:

```rust
use async_trait::async_trait;
use embednfs::fs::{
    DirEntry, FileAttr, FileId, FsInfo, NfsFileSystem, NfsResult, SetFileAttr,
};

#[async_trait]
pub trait NfsFileSystem: Send + Sync + 'static {
    async fn getattr(&self, id: FileId) -> NfsResult<FileAttr>;
    async fn setattr(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr>;
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;
    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId>;
    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>>;
    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)>;
    async fn write(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32>;
    async fn create(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId>;
    async fn mkdir(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId>;
    async fn symlink(
        &self,
        dir_id: FileId,
        name: &str,
        target: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId>;
    async fn readlink(&self, id: FileId) -> NfsResult<String>;
    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()>;
    async fn rename(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()>;
    async fn link(&self, id: FileId, dir_id: FileId, name: &str) -> NfsResult<()>;
    async fn commit(&self, id: FileId) -> NfsResult<()>;

    fn fs_info(&self) -> FsInfo {
        FsInfo::default()
    }
}
```

The root directory must have `FileId = 1`. The server handles protocol state, file handles, sessions, and COMPOUND sequencing; your implementation only deals with files, directories, and metadata.

A few operation mappings are worth calling out:

- `OPEN` with `OPEN4_CREATE` calls `create()`
- `CREATE` currently handles directory and symlink creation and calls `mkdir()` / `symlink()`
- `LOOKUPP` calls `lookup_parent()`
- `COMMIT` calls `commit()`
- `fs_info()` is optional; the default implementation returns generic filesystem limits

## Supported Operations

The server currently decodes the full NFSv4.1 operation enum it knows about, but not every operation is equally complete. Current coverage in `crates/embednfs/src/server.rs` is:

Supported for normal use:

- `EXCHANGE_ID`, `CREATE_SESSION`, `SEQUENCE`, `BIND_CONN_TO_SESSION`
- `PUTROOTFH`, `PUTPUBFH`, `PUTFH`, `GETFH`, `SAVEFH`, `RESTOREFH`
- `LOOKUP`, `LOOKUPP`, `GETATTR`, `SETATTR`
- `READ`, `WRITE`, `COMMIT`, `READDIR`, `READLINK`
- `REMOVE`, `RENAME`, `LINK`
- `DESTROY_SESSION`, `DESTROY_CLIENTID`
- `VERIFY`, `NVERIFY`

Implemented with limited semantics:

- `OPEN`, `CLOSE`, `OPEN_DOWNGRADE`: open-state bookkeeping and regular-file creation via `OPEN(CREATE)` are implemented, but there is no delegation support and only a subset of claim modes is handled
- `CREATE`: supports `NF4DIR` and `NF4LNK`; other `CREATE` object types return `NFS4ERR_NOTSUPP`
- `ACCESS`: reports server-supported access bits, but does not do per-user authorization checks
- `LOCK`, `LOCKT`, `LOCKU`: stateid bookkeeping is implemented, but lock-conflict tracking is not
- `FREE_STATEID`, `TEST_STATEID`, `RECLAIM_COMPLETE`, `DELEGRETURN`, `DELEGPURGE`: minimal acknowledgement / cleanup paths
- `SECINFO`, `SECINFO_NO_NAME`: currently advertise `AUTH_SYS` and `AUTH_NONE`

Currently return `NFS4ERR_NOTSUPP`:

- `OPENATTR`
- `LAYOUTGET`, `LAYOUTRETURN`, `LAYOUTCOMMIT`
- `GET_DIR_DELEGATION`, `WANT_DELEGATION`
- `BACKCHANNEL_CTL`, `GETDEVICEINFO`, `GETDEVICELIST`, `SET_SSV`

Rejected in NFSv4.1 because they are NFSv4.0-only:

- `OPEN_CONFIRM`, `RENEW`, `SETCLIENTID`, `SETCLIENTID_CONFIRM`, `RELEASE_LOCKOWNER`

## Testing

```bash
cargo test --workspace
```

## License

MIT

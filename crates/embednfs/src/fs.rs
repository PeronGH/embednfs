/// Filesystem trait for the embeddable NFSv4.1 server.
///
/// The public API is intentionally object-centric and minimal. Implementors
/// provide stable `FileId` values for real filesystem objects, and the server
/// layers NFS-specific state, filehandles, locking, and optional capabilities
/// such as named attributes on top.
use async_trait::async_trait;
use std::fmt;

/// Unique file identifier (inode number equivalent).
pub type FileId = u64;

/// Basic node kinds required by the core filesystem trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Directory,
    Symlink,
}

/// Minimal node information required from a filesystem implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfo {
    pub kind: NodeKind,
    pub size: u64,
}

/// A directory entry returned by `readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub fileid: FileId,
    pub name: String,
}

/// Controls how a named attribute should be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrSetMode {
    CreateOrReplace,
    CreateOnly,
    ReplaceOnly,
}

/// NFS error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsError {
    Ok,
    Perm,
    Noent,
    Io,
    Access,
    Exist,
    Xdev,
    Notdir,
    Isdir,
    Inval,
    Fbig,
    Nospc,
    Rofs,
    Nametoolong,
    Notempty,
    Stale,
    Notsupp,
    Serverfault,
    BadHandle,
}

impl fmt::Display for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for NfsError {}

impl NfsError {
    pub(crate) fn to_nfsstat4(self) -> embednfs_proto::NfsStat4 {
        use embednfs_proto::NfsStat4;
        match self {
            NfsError::Ok => NfsStat4::Ok,
            NfsError::Perm => NfsStat4::Perm,
            NfsError::Noent => NfsStat4::Noent,
            NfsError::Io => NfsStat4::Io,
            NfsError::Access => NfsStat4::Access,
            NfsError::Exist => NfsStat4::Exist,
            NfsError::Xdev => NfsStat4::Xdev,
            NfsError::Notdir => NfsStat4::Notdir,
            NfsError::Isdir => NfsStat4::Isdir,
            NfsError::Inval => NfsStat4::Inval,
            NfsError::Fbig => NfsStat4::Fbig,
            NfsError::Nospc => NfsStat4::Nospc,
            NfsError::Rofs => NfsStat4::Rofs,
            NfsError::Nametoolong => NfsStat4::Nametoolong,
            NfsError::Notempty => NfsStat4::Notempty,
            NfsError::Stale => NfsStat4::Stale,
            NfsError::Notsupp => NfsStat4::Notsupp,
            NfsError::Serverfault => NfsStat4::Serverfault,
            NfsError::BadHandle => NfsStat4::Badhandle,
        }
    }
}

pub type NfsResult<T> = Result<T, NfsError>;

/// Optional named-attribute support used for Apple/macOS xattr flows.
#[async_trait]
pub trait NfsNamedAttrs: Send + Sync {
    /// List all named attributes attached to an object.
    async fn list_xattrs(&self, id: FileId) -> NfsResult<Vec<String>>;

    /// Fetch a full named-attribute value.
    async fn get_xattr(&self, id: FileId, name: &str) -> NfsResult<Vec<u8>>;

    /// Set or replace a named-attribute value.
    async fn set_xattr(
        &self,
        id: FileId,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> NfsResult<()>;

    /// Remove a named attribute.
    async fn remove_xattr(&self, id: FileId, name: &str) -> NfsResult<()>;
}

/// Optional symlink support.
#[async_trait]
pub trait NfsSymlinks: Send + Sync {
    /// Create a symlink in a directory and return its `FileId`.
    async fn symlink(&self, dir_id: FileId, name: &str, target: &str) -> NfsResult<FileId>;

    /// Read a symlink target.
    async fn readlink(&self, id: FileId) -> NfsResult<String>;
}

/// Optional hard-link support.
#[async_trait]
pub trait NfsHardLinks: Send + Sync {
    /// Create a hard link to an existing file.
    async fn link(&self, id: FileId, dir_id: FileId, name: &str) -> NfsResult<()>;
}

/// Optional flush/commit support.
#[async_trait]
pub trait NfsSync: Send + Sync {
    /// Flush any buffered data for a file.
    async fn commit(&self, id: FileId) -> NfsResult<()>;
}

/// The core filesystem trait.
#[async_trait]
pub trait NfsFileSystem: Send + Sync + 'static {
    /// Return the root object ID. The default root is `1`.
    fn root(&self) -> FileId {
        1
    }

    /// Return minimal information about an object.
    async fn stat(&self, id: FileId) -> NfsResult<NodeInfo>;

    /// Look up a child entry by name in a directory.
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;

    /// Look up the parent of an object.
    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId>;

    /// List a directory's entries.
    ///
    /// Do not synthesize `"."` or `".."`; the server handles cookie and reply
    /// formatting for the entries returned here.
    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>>;

    /// Read file data.
    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)>;

    /// Write file data. Returns bytes written.
    async fn write(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32>;

    /// Truncate or extend a file to the given size.
    async fn truncate(&self, id: FileId, size: u64) -> NfsResult<()>;

    /// Create a regular file and return its `FileId`.
    async fn create_file(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;

    /// Create a directory and return its `FileId`.
    async fn create_dir(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;

    /// Remove a file or empty directory by name.
    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()>;

    /// Rename or move an entry.
    async fn rename(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()>;

    /// Optional symlink capability.
    fn symlinks(&self) -> Option<&dyn NfsSymlinks> {
        None
    }

    /// Optional hard-link capability.
    fn hard_links(&self) -> Option<&dyn NfsHardLinks> {
        None
    }

    /// Optional named-attribute capability.
    fn named_attrs(&self) -> Option<&dyn NfsNamedAttrs> {
        None
    }

    /// Optional explicit flush capability.
    fn syncer(&self) -> Option<&dyn NfsSync> {
        None
    }

    /// Filesystem-level information.
    fn fs_info(&self) -> FsInfo {
        FsInfo::default()
    }
}

/// Filesystem-level information.
#[derive(Debug, Clone)]
pub struct FsInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub avail_files: u64,
    pub max_file_size: u64,
    pub max_name: u32,
    pub max_read: u32,
    pub max_write: u32,
}

impl Default for FsInfo {
    fn default() -> Self {
        FsInfo {
            total_bytes: 1 << 40, // 1 TB
            free_bytes: 1 << 39,  // 512 GB
            avail_bytes: 1 << 39,
            total_files: 1 << 30,
            free_files: 1 << 29,
            avail_files: 1 << 29,
            max_file_size: 1 << 40,
            max_name: 255,
            max_read: 1048576, // 1 MB
            max_write: 1048576,
        }
    }
}

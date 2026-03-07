/// Filesystem trait for NFSv4.1 server.
///
/// Implement this trait to expose any data source as an NFS filesystem.
/// The server library handles all protocol details — implementors only
/// need to think in terms of files, directories, and metadata.

use async_trait::async_trait;
use std::fmt;

/// Unique file identifier (inode number equivalent).
pub type FileId = u64;

/// File type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Socket,
    Fifo,
}

/// File attributes (metadata).
#[derive(Debug, Clone)]
pub struct FileAttr {
    pub fileid: FileId,
    pub file_type: FileType,
    pub size: u64,
    pub used: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub owner_group: String,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    /// Birth/creation time (macOS expects this).
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub change_id: u64,
    /// Device numbers for block/char devices
    pub rdev_major: u32,
    pub rdev_minor: u32,
    /// macOS flags: archive, hidden, system
    pub archive: bool,
    pub hidden: bool,
    pub system: bool,
}

impl Default for FileAttr {
    fn default() -> Self {
        FileAttr {
            fileid: 0,
            file_type: FileType::Regular,
            size: 0,
            used: 0,
            mode: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            owner: "nobody".into(),
            owner_group: "nogroup".into(),
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            crtime_sec: 0,
            crtime_nsec: 0,
            change_id: 0,
            rdev_major: 0,
            rdev_minor: 0,
            archive: false,
            hidden: false,
            system: false,
        }
    }
}

/// A directory entry returned by readdir.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub fileid: FileId,
    pub name: String,
    pub attr: FileAttr,
}

/// Set-time specification.
#[derive(Debug, Clone, Copy)]
pub enum SetTime {
    ServerTime,
    ClientTime(i64, u32),
}

/// Attributes to set (only fields that are Some get applied).
#[derive(Debug, Clone, Default)]
pub struct SetFileAttr {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
    /// Birth/creation time (macOS sends this).
    pub crtime: Option<SetTime>,
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
    pub fn to_nfsstat4(self) -> nfs4_proto::NfsStat4 {
        use nfs4_proto::NfsStat4;
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

/// The filesystem trait. Implement this to serve files over NFS.
///
/// All methods receive the file identifier as a `FileId` (u64). The server
/// library manages the mapping between NFS file handles and FileIds.
///
/// The root directory always has FileId 1.
#[async_trait]
pub trait NfsFileSystem: Send + Sync + 'static {
    /// Get file attributes by file ID.
    async fn getattr(&self, id: FileId) -> NfsResult<FileAttr>;

    /// Set file attributes.
    async fn setattr(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr>;

    /// Look up a child entry by name in a directory.
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;

    /// Look up the parent of a directory.
    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId>;

    /// Read directory entries. Returns all entries (. and .. are added by the server).
    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>>;

    /// Read file data.
    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)>;

    /// Write file data. Returns bytes written.
    async fn write(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32>;

    /// Create a regular file. Returns the new file ID.
    async fn create(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId>;

    /// Create a directory. Returns the new directory ID.
    async fn mkdir(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId>;

    /// Create a symbolic link. Returns the new symlink ID.
    async fn symlink(&self, dir_id: FileId, name: &str, target: &str, attrs: &SetFileAttr) -> NfsResult<FileId>;

    /// Read a symbolic link target.
    async fn readlink(&self, id: FileId) -> NfsResult<String>;

    /// Remove a file or empty directory.
    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()>;

    /// Rename/move an entry.
    async fn rename(&self, from_dir: FileId, from_name: &str, to_dir: FileId, to_name: &str) -> NfsResult<()>;

    /// Create a hard link.
    async fn link(&self, id: FileId, dir_id: FileId, name: &str) -> NfsResult<()>;

    /// Commit buffered data to stable storage.
    async fn commit(&self, id: FileId) -> NfsResult<()>;

    /// Filesystem info.
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
            total_bytes: 1 << 40,    // 1 TB
            free_bytes: 1 << 39,     // 512 GB
            avail_bytes: 1 << 39,
            total_files: 1 << 30,
            free_files: 1 << 29,
            avail_files: 1 << 29,
            max_file_size: 1 << 40,
            max_name: 255,
            max_read: 1048576,       // 1 MB
            max_write: 1048576,
        }
    }
}

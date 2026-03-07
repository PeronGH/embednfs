/// Filesystem trait for NFSv4.1 server.
///
/// Implement this trait to expose any data source as an NFS filesystem.
/// The server library handles all protocol details — implementors only
/// need to think in terms of files, directories, and metadata.
use async_trait::async_trait;
use std::fmt;

/// Unique file identifier (inode number equivalent).
pub(crate) type FileId = u64;

/// Opaque revision token used for optimistic concurrency when available.
pub type Revision = String;

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

/// Backend write support level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCapability {
    ReplaceOnly,
    RandomWrite,
    Both,
}

impl WriteCapability {
    /// Whether the backend can replace whole-file contents in one operation.
    pub fn supports_replace(self) -> bool {
        matches!(self, WriteCapability::ReplaceOnly | WriteCapability::Both)
    }

    /// Whether the backend can service offset writes directly.
    pub fn supports_random_write(self) -> bool {
        matches!(self, WriteCapability::RandomWrite | WriteCapability::Both)
    }
}

/// Synthetic POSIX defaults presented to NFS clients.
#[derive(Debug, Clone)]
pub struct PosixDefaults {
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub owner_group: String,
    pub file_mode: u32,
    pub dir_mode: u32,
    pub symlink_mode: u32,
}

impl Default for PosixDefaults {
    fn default() -> Self {
        PosixDefaults {
            uid: 0,
            gid: 0,
            owner: "nobody".into(),
            owner_group: "nogroup".into(),
            file_mode: 0o644,
            dir_mode: 0o755,
            symlink_mode: 0o777,
        }
    }
}

/// Capabilities advertised by the backend.
#[derive(Debug, Clone)]
pub struct FsCapabilities {
    pub write_capability: WriteCapability,
    pub range_reads: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
    pub fs_info: FsInfo,
    pub posix: PosixDefaults,
}

impl Default for FsCapabilities {
    fn default() -> Self {
        FsCapabilities {
            write_capability: WriteCapability::Both,
            range_reads: true,
            case_insensitive: false,
            case_preserving: true,
            fs_info: FsInfo::default(),
            posix: PosixDefaults::default(),
        }
    }
}

/// Minimal metadata the high-level API exposes.
#[derive(Debug, Clone)]
pub struct Metadata {
    pub file_type: FileType,
    pub size: u64,
    pub mtime_sec: Option<i64>,
    pub mtime_nsec: Option<u32>,
    pub ctime_sec: Option<i64>,
    pub ctime_nsec: Option<u32>,
    pub crtime_sec: Option<i64>,
    pub crtime_nsec: Option<u32>,
    pub revision: Option<Revision>,
    pub readonly: bool,
    pub executable: bool,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            file_type: FileType::Regular,
            size: 0,
            mtime_sec: None,
            mtime_nsec: None,
            ctime_sec: None,
            ctime_nsec: None,
            crtime_sec: None,
            crtime_nsec: None,
            revision: None,
            readonly: false,
            executable: false,
        }
    }
}

/// Directory entry returned by the high-level API.
#[derive(Debug, Clone)]
pub struct PathDirEntry {
    pub name: String,
    pub metadata: Metadata,
}

/// File attributes (metadata).
#[derive(Debug, Clone)]
pub(crate) struct FileAttr {
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
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct DirEntry {
    pub fileid: FileId,
    pub name: String,
    pub attr: FileAttr,
}

/// Set-time specification.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SetTime {
    ServerTime,
    ClientTime(i64, u32),
}

/// Attributes to set (only fields that are Some get applied).
#[derive(Debug, Clone, Default)]
pub(crate) struct SetFileAttr {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
    /// Birth/creation time (macOS sends this).
    pub crtime: Option<SetTime>,
}

/// Filesystem error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
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
    Delay,
    Locked,
    Openmode,
    BadOwner,
    AttrNotsupp,
    FileOpen,
    WrongType,
    Symlink,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FsError {}

impl FsError {
    pub fn to_nfsstat4(self) -> embednfs_proto::NfsStat4 {
        use embednfs_proto::NfsStat4;
        match self {
            FsError::Ok => NfsStat4::Ok,
            FsError::Perm => NfsStat4::Perm,
            FsError::Noent => NfsStat4::Noent,
            FsError::Io => NfsStat4::Io,
            FsError::Access => NfsStat4::Access,
            FsError::Exist => NfsStat4::Exist,
            FsError::Xdev => NfsStat4::Xdev,
            FsError::Notdir => NfsStat4::Notdir,
            FsError::Isdir => NfsStat4::Isdir,
            FsError::Inval => NfsStat4::Inval,
            FsError::Fbig => NfsStat4::Fbig,
            FsError::Nospc => NfsStat4::Nospc,
            FsError::Rofs => NfsStat4::Rofs,
            FsError::Nametoolong => NfsStat4::Nametoolong,
            FsError::Notempty => NfsStat4::Notempty,
            FsError::Stale => NfsStat4::Stale,
            FsError::Notsupp => NfsStat4::Notsupp,
            FsError::Serverfault => NfsStat4::Serverfault,
            FsError::BadHandle => NfsStat4::Badhandle,
            FsError::Delay => NfsStat4::Delay,
            FsError::Locked => NfsStat4::Locked,
            FsError::Openmode => NfsStat4::Openmode,
            FsError::BadOwner => NfsStat4::BadOwner,
            FsError::AttrNotsupp => NfsStat4::AttrNotsupp,
            FsError::FileOpen => NfsStat4::FileOpen,
            FsError::WrongType => NfsStat4::WrongType,
            FsError::Symlink => NfsStat4::Symlink,
        }
    }
}

pub type FsResult<T> = Result<T, FsError>;
pub(crate) type NfsError = FsError;
pub(crate) type NfsResult<T> = FsResult<T>;

/// A simple, path-based filesystem API.
#[async_trait]
pub trait FileSystem: Send + Sync + 'static {
    /// Filesystem capabilities and synthetic POSIX defaults.
    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities::default()
    }

    /// Fetch metadata for an absolute path.
    async fn metadata(&self, path: &str) -> FsResult<Metadata>;

    /// List all immediate children of a directory.
    async fn list(&self, path: &str) -> FsResult<Vec<PathDirEntry>>;

    /// Read file data from the given offset.
    async fn read(&self, path: &str, offset: u64, count: u32) -> FsResult<Vec<u8>>;

    /// Create an empty regular file.
    async fn create_file(&self, path: &str) -> FsResult<()>;

    /// Create a directory.
    async fn create_dir(&self, path: &str) -> FsResult<()>;

    /// Create a symbolic link.
    async fn create_symlink(&self, path: &str, target: &str) -> FsResult<()>;

    /// Read a symbolic link target.
    async fn read_symlink(&self, path: &str) -> FsResult<String>;

    /// Remove a file or empty directory.
    async fn remove(&self, path: &str, expected_revision: Option<&str>) -> FsResult<()>;

    /// Rename or move an entry.
    async fn rename(&self, from: &str, to: &str, expected_revision: Option<&str>) -> FsResult<()>;

    /// Replace a file with the given full contents.
    async fn replace_file(
        &self,
        _path: &str,
        _data: &[u8],
        _expected_revision: Option<&str>,
    ) -> FsResult<()> {
        Err(FsError::Notsupp)
    }

    /// Write bytes directly to a file at the given offset.
    async fn write_file(&self, _path: &str, _offset: u64, _data: &[u8]) -> FsResult<u32> {
        Err(FsError::Notsupp)
    }

    /// Adjust a file's length.
    async fn set_len(&self, _path: &str, _size: u64) -> FsResult<()> {
        Err(FsError::Notsupp)
    }

    /// Flush file contents to stable storage when supported.
    async fn sync(&self, _path: &str) -> FsResult<()> {
        Ok(())
    }
}

/// The filesystem trait. Implement this to serve files over NFS.
///
/// All methods receive the file identifier as a `FileId` (u64). The server
/// library manages the mapping between NFS file handles and FileIds.
///
/// The root directory always has FileId 1.
#[allow(dead_code)]
#[async_trait]
pub(crate) trait NfsFileSystem: Send + Sync + 'static {
    /// Get file attributes by file ID.
    async fn getattr(&self, id: FileId) -> NfsResult<FileAttr>;

    /// Set file attributes.
    async fn setattr(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr>;

    /// Look up a child entry by name in a directory.
    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId>;

    /// Look up the parent of a directory.
    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId>;

    /// Read actual directory entries.
    ///
    /// Do not synthesize `"."` or `".."`; the server handles cookie and reply
    /// formatting for the entries returned here.
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
    async fn symlink(
        &self,
        dir_id: FileId,
        name: &str,
        target: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId>;

    /// Read a symbolic link target.
    async fn readlink(&self, id: FileId) -> NfsResult<String>;

    /// Remove a file or empty directory.
    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()>;

    /// Rename/move an entry.
    async fn rename(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()>;

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

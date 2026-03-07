use super::FileType;

/// Unique file identifier (inode number equivalent).
pub(crate) type FileId = u64;

/// File attributes used internally when translating to NFS attrs.
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
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub change_id: u64,
    pub rdev_major: u32,
    pub rdev_minor: u32,
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

/// Internal directory entry representation.
#[derive(Debug, Clone)]
pub(crate) struct DirEntry {
    pub name: String,
    pub attr: FileAttr,
}

/// Set-time specification used for decoded NFS setattr requests.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SetTime {
    ServerTime,
    ClientTime(i64, u32),
}

/// Internal setattr request representation.
#[derive(Debug, Clone, Default)]
pub(crate) struct SetFileAttr {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
    pub crtime: Option<SetTime>,
}

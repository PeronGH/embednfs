use crate::fs::FileId;

/// Internal object identity used by the server for filehandles and state.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum ServerObject {
    Fs(FileId),
    NamedAttrDir(FileId),
    NamedAttrFile { parent: FileId, name: String },
}

/// Internal file kinds used for NFS attribute encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerFileType {
    Regular,
    Directory,
    Symlink,
    NamedAttrDir,
    NamedAttr,
}

/// Internal synthesized attribute record used by the protocol layer.
#[derive(Debug, Clone)]
pub(crate) struct ServerFileAttr {
    pub fileid: u64,
    pub file_type: ServerFileType,
    pub size: u64,
    pub used: u64,
    pub mode: u32,
    pub nlink: u32,
    #[allow(dead_code)]
    pub uid: u32,
    #[allow(dead_code)]
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
    pub has_named_attrs: bool,
}

/// SETATTR time specification used internally by the server.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SetTime {
    ServerTime,
    ClientTime(i64, u32),
}

/// Parsed SETATTR/create attribute request used internally by the server.
#[derive(Debug, Clone, Default)]
pub(crate) struct SetAttrRequest {
    pub size: Option<u64>,
    pub archive: Option<bool>,
    pub hidden: Option<bool>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub system: Option<bool>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
    pub crtime: Option<SetTime>,
}

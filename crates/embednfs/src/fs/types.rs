/// Opaque revision token used for optimistic concurrency when available.
pub type Revision = String;

/// File types surfaced by the public filesystem API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
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

/// Directory entry returned by the filesystem API.
#[derive(Debug, Clone)]
pub struct PathDirEntry {
    pub name: String,
    pub metadata: Metadata,
}

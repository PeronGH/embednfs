//! In-memory filesystem implementation.

mod api;
mod ops;
mod path;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::fs::{FileAttr, FileId, FileType, Metadata};

/// An in-memory filesystem.
pub struct MemFs {
    inner: RwLock<MemFsInner>,
    next_id: AtomicU64,
    change_counter: AtomicU64,
}

struct MemFsInner {
    inodes: HashMap<FileId, Inode>,
}

struct Inode {
    attr: FileAttr,
    data: InodeData,
}

enum InodeData {
    File(Vec<u8>),
    Directory(HashMap<String, FileId>),
    Symlink(String),
}

impl MemFs {
    /// Create a new in-memory filesystem with an empty root directory.
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let now_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        inodes.insert(
            1,
            Inode {
                attr: FileAttr {
                    fileid: 1,
                    file_type: FileType::Directory,
                    size: 4096,
                    used: 4096,
                    mode: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    owner: "root".into(),
                    owner_group: "root".into(),
                    atime_sec: now_sec,
                    atime_nsec: 0,
                    mtime_sec: now_sec,
                    mtime_nsec: 0,
                    ctime_sec: now_sec,
                    ctime_nsec: 0,
                    crtime_sec: now_sec,
                    crtime_nsec: 0,
                    change_id: 1,
                    rdev_major: 0,
                    rdev_minor: 0,
                    archive: false,
                    hidden: false,
                    system: false,
                },
                data: InodeData::Directory(HashMap::new()),
            },
        );

        MemFs {
            inner: RwLock::new(MemFsInner { inodes }),
            next_id: AtomicU64::new(2),
            change_counter: AtomicU64::new(2),
        }
    }

    fn next_change(&self) -> u64 {
        self.change_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn now() -> (i64, u32) {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (dur.as_secs() as i64, dur.subsec_nanos())
    }

    fn metadata_from_attr(attr: &FileAttr) -> Metadata {
        Metadata {
            file_type: attr.file_type,
            size: attr.size,
            mtime_sec: Some(attr.mtime_sec),
            mtime_nsec: Some(attr.mtime_nsec),
            ctime_sec: Some(attr.ctime_sec),
            ctime_nsec: Some(attr.ctime_nsec),
            crtime_sec: Some(attr.crtime_sec),
            crtime_nsec: Some(attr.crtime_nsec),
            revision: Some(attr.change_id.to_string()),
            readonly: attr.mode & 0o222 == 0,
            executable: attr.mode & 0o111 != 0,
        }
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

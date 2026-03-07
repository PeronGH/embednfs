/// In-memory filesystem implementation.
///
/// Provides a fully functional in-memory filesystem for testing and as
/// a reference implementation of the [`NfsFileSystem`] trait.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use crate::fs::*;

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

        let root_attr = FileAttr {
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
        };

        // No . or .. stored; they're synthesized by the server
        inodes.insert(1, Inode {
            attr: root_attr,
            data: InodeData::Directory(HashMap::new()),
        });

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
}

#[async_trait]
impl NfsFileSystem for MemFs {
    async fn getattr(&self, id: FileId) -> NfsResult<FileAttr> {
        let inner = self.inner.read().await;
        inner.inodes.get(&id)
            .map(|i| i.attr.clone())
            .ok_or(NfsError::Stale)
    }

    async fn setattr(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        let (now_s, now_ns) = Self::now();

        if let Some(size) = attrs.size {
            if let InodeData::File(ref mut data) = inode.data {
                data.resize(size as usize, 0);
                inode.attr.size = size;
                inode.attr.used = size;
            }
        }
        if let Some(mode) = attrs.mode {
            inode.attr.mode = mode;
        }
        if let Some(uid) = attrs.uid {
            inode.attr.uid = uid;
        }
        if let Some(gid) = attrs.gid {
            inode.attr.gid = gid;
        }
        if let Some(atime) = attrs.atime {
            match atime {
                SetTime::ServerTime => {
                    inode.attr.atime_sec = now_s;
                    inode.attr.atime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    inode.attr.atime_sec = s;
                    inode.attr.atime_nsec = ns;
                }
            }
        }
        if let Some(mtime) = attrs.mtime {
            match mtime {
                SetTime::ServerTime => {
                    inode.attr.mtime_sec = now_s;
                    inode.attr.mtime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    inode.attr.mtime_sec = s;
                    inode.attr.mtime_nsec = ns;
                }
            }
        }

        inode.attr.ctime_sec = now_s;
        inode.attr.ctime_nsec = now_ns;
        inode.attr.change_id = self.next_change();

        Ok(inode.attr.clone())
    }

    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => {
                entries.get(name).copied().ok_or(NfsError::Noent)
            }
            _ => Err(NfsError::Notdir),
        }
    }

    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId> {
        if id == 1 {
            return Ok(1); // Root is its own parent
        }
        let inner = self.inner.read().await;
        // Search all directories for this id
        for (dir_id, inode) in &inner.inodes {
            if let InodeData::Directory(entries) = &inode.data {
                for (_, child_id) in entries {
                    if *child_id == id {
                        return Ok(*dir_id);
                    }
                }
            }
        }
        Err(NfsError::Noent)
    }

    async fn readdir(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => {
                let mut result = Vec::with_capacity(entries.len());
                for (name, child_id) in entries {
                    if let Some(child) = inner.inodes.get(child_id) {
                        result.push(DirEntry {
                            fileid: *child_id,
                            name: name.clone(),
                            attr: child.attr.clone(),
                        });
                    }
                }
                // Sort for deterministic order
                result.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(result)
            }
            _ => Err(NfsError::Notdir),
        }
    }

    async fn read(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::File(data) => {
                let offset = offset as usize;
                if offset >= data.len() {
                    return Ok((vec![], true));
                }
                let end = (offset + count as usize).min(data.len());
                let chunk = data[offset..end].to_vec();
                let eof = end >= data.len();
                Ok((chunk, eof))
            }
            _ => Err(NfsError::Inval),
        }
    }

    async fn write(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        match &mut inode.data {
            InodeData::File(file_data) => {
                let offset = offset as usize;
                let end = offset + data.len();
                if end > file_data.len() {
                    file_data.resize(end, 0);
                }
                file_data[offset..end].copy_from_slice(data);
                inode.attr.size = file_data.len() as u64;
                inode.attr.used = file_data.len() as u64;
                let (s, ns) = Self::now();
                inode.attr.mtime_sec = s;
                inode.attr.mtime_nsec = ns;
                inode.attr.ctime_sec = s;
                inode.attr.ctime_nsec = ns;
                inode.attr.change_id = self.next_change();
                Ok(data.len() as u32)
            }
            _ => Err(NfsError::Inval),
        }
    }

    async fn create(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId> {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (now_s, now_ns) = Self::now();
        let mode = attrs.mode.unwrap_or(0o644);

        let file_attr = FileAttr {
            fileid: new_id,
            file_type: FileType::Regular,
            size: 0,
            used: 0,
            mode,
            nlink: 1,
            uid: attrs.uid.unwrap_or(0),
            gid: attrs.gid.unwrap_or(0),
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: now_s,
            atime_nsec: now_ns,
            mtime_sec: now_s,
            mtime_nsec: now_ns,
            ctime_sec: now_s,
            ctime_nsec: now_ns,
            crtime_sec: now_s,
            crtime_nsec: now_ns,
            change_id: self.next_change(),
            rdev_major: 0,
            rdev_minor: 0,
        };

        let mut inner = self.inner.write().await;
        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
                dir.attr.change_id = self.next_change();
                let (s, ns) = Self::now();
                dir.attr.mtime_sec = s;
                dir.attr.mtime_nsec = ns;
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(new_id, Inode {
            attr: file_attr,
            data: InodeData::File(Vec::new()),
        });

        Ok(new_id)
    }

    async fn mkdir(&self, dir_id: FileId, name: &str, attrs: &SetFileAttr) -> NfsResult<FileId> {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (now_s, now_ns) = Self::now();
        let mode = attrs.mode.unwrap_or(0o755);

        let dir_attr = FileAttr {
            fileid: new_id,
            file_type: FileType::Directory,
            size: 4096,
            used: 4096,
            mode,
            nlink: 2,
            uid: attrs.uid.unwrap_or(0),
            gid: attrs.gid.unwrap_or(0),
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: now_s,
            atime_nsec: now_ns,
            mtime_sec: now_s,
            mtime_nsec: now_ns,
            ctime_sec: now_s,
            ctime_nsec: now_ns,
            crtime_sec: now_s,
            crtime_nsec: now_ns,
            change_id: self.next_change(),
            rdev_major: 0,
            rdev_minor: 0,
        };

        let mut inner = self.inner.write().await;
        let parent = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut parent.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
                parent.attr.nlink += 1;
                parent.attr.change_id = self.next_change();
                let (s, ns) = Self::now();
                parent.attr.mtime_sec = s;
                parent.attr.mtime_nsec = ns;
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(new_id, Inode {
            attr: dir_attr,
            data: InodeData::Directory(HashMap::new()),
        });

        Ok(new_id)
    }

    async fn symlink(&self, dir_id: FileId, name: &str, target: &str, attrs: &SetFileAttr) -> NfsResult<FileId> {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (now_s, now_ns) = Self::now();

        let link_attr = FileAttr {
            fileid: new_id,
            file_type: FileType::Symlink,
            size: target.len() as u64,
            used: target.len() as u64,
            mode: attrs.mode.unwrap_or(0o777),
            nlink: 1,
            uid: attrs.uid.unwrap_or(0),
            gid: attrs.gid.unwrap_or(0),
            owner: "root".into(),
            owner_group: "root".into(),
            atime_sec: now_s,
            atime_nsec: now_ns,
            mtime_sec: now_s,
            mtime_nsec: now_ns,
            ctime_sec: now_s,
            ctime_nsec: now_ns,
            crtime_sec: now_s,
            crtime_nsec: now_ns,
            change_id: self.next_change(),
            rdev_major: 0,
            rdev_minor: 0,
        };

        let mut inner = self.inner.write().await;
        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
                dir.attr.change_id = self.next_change();
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(new_id, Inode {
            attr: link_attr,
            data: InodeData::Symlink(target.to_string()),
        });

        Ok(new_id)
    }

    async fn readlink(&self, id: FileId) -> NfsResult<String> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(NfsError::Inval),
        }
    }

    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let dir = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => {
                    *entries.get(name).ok_or(NfsError::Noent)?
                }
                _ => return Err(NfsError::Notdir),
            }
        };

        // Check if child is a non-empty directory
        if let Some(child) = inner.inodes.get(&child_id) {
            if let InodeData::Directory(entries) = &child.data {
                if !entries.is_empty() {
                    return Err(NfsError::Notempty);
                }
            }
        }

        // Remove from parent
        let dir = inner.inodes.get_mut(&dir_id).unwrap();
        if let InodeData::Directory(entries) = &mut dir.data {
            entries.remove(name);
        }
        dir.attr.change_id = self.next_change();
        let (s, ns) = Self::now();
        dir.attr.mtime_sec = s;
        dir.attr.mtime_nsec = ns;

        // Remove inode
        inner.inodes.remove(&child_id);

        Ok(())
    }

    async fn rename(&self, from_dir: FileId, from_name: &str, to_dir: FileId, to_name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        // Get source file id
        let child_id = {
            let dir = inner.inodes.get(&from_dir).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => {
                    *entries.get(from_name).ok_or(NfsError::Noent)?
                }
                _ => return Err(NfsError::Notdir),
            }
        };

        // Remove from source dir
        {
            let dir = inner.inodes.get_mut(&from_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &mut dir.data {
                entries.remove(from_name);
            }
            dir.attr.change_id = self.next_change();
        }

        // If target exists, remove it
        {
            let tgt_dir = inner.inodes.get(&to_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &tgt_dir.data {
                if let Some(&old_id) = entries.get(to_name) {
                    inner.inodes.remove(&old_id);
                }
            }
        }

        // Add to target dir
        {
            let tgt_dir = inner.inodes.get_mut(&to_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &mut tgt_dir.data {
                entries.insert(to_name.to_string(), child_id);
            }
            tgt_dir.attr.change_id = self.next_change();
        }

        Ok(())
    }

    async fn link(&self, id: FileId, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        // Verify source exists
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        if inode.attr.file_type == FileType::Directory {
            return Err(NfsError::Isdir); // Can't hard link directories
        }

        // Add to target directory
        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), id);
                dir.attr.change_id = self.next_change();
            }
            _ => return Err(NfsError::Notdir),
        }

        // Increment link count
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        inode.attr.nlink += 1;

        Ok(())
    }

    async fn commit(&self, _id: FileId) -> NfsResult<()> {
        Ok(()) // In-memory; always committed
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_read() {
        let fs = MemFs::new();
        let id = fs.create(1, "test.txt", &SetFileAttr::default()).await.unwrap();
        let written = fs.write(id, 0, b"hello world").await.unwrap();
        assert_eq!(written, 11);
        let (data, eof) = fs.read(id, 0, 1024).await.unwrap();
        assert_eq!(data, b"hello world");
        assert!(eof);
    }

    #[tokio::test]
    async fn test_mkdir_and_readdir() {
        let fs = MemFs::new();
        let dir_id = fs.mkdir(1, "subdir", &SetFileAttr::default()).await.unwrap();
        let entries = fs.readdir(1).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "subdir");
        assert_eq!(entries[0].fileid, dir_id);
    }

    #[tokio::test]
    async fn test_remove() {
        let fs = MemFs::new();
        let _id = fs.create(1, "to_delete.txt", &SetFileAttr::default()).await.unwrap();
        fs.remove(1, "to_delete.txt").await.unwrap();
        assert!(fs.lookup(1, "to_delete.txt").await.is_err());
    }

    #[tokio::test]
    async fn test_rename() {
        let fs = MemFs::new();
        fs.create(1, "old.txt", &SetFileAttr::default()).await.unwrap();
        fs.rename(1, "old.txt", 1, "new.txt").await.unwrap();
        assert!(fs.lookup(1, "old.txt").await.is_err());
        assert!(fs.lookup(1, "new.txt").await.is_ok());
    }
}

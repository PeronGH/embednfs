/// In-memory filesystem implementation.
///
/// Provides a fully functional in-memory filesystem for testing and as
/// a reference implementation of the public filesystem traits.
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use crate::fs::*;

/// An in-memory filesystem.
pub struct MemFs {
    inner: RwLock<MemFsInner>,
    next_id: AtomicU64,
}

struct MemFsInner {
    inodes: HashMap<FileId, Inode>,
}

struct Inode {
    kind: NodeKind,
    data: InodeData,
    xattrs: HashMap<String, Vec<u8>>,
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
        inodes.insert(
            1,
            Inode {
                kind: NodeKind::Directory,
                data: InodeData::Directory(HashMap::new()),
                xattrs: HashMap::new(),
            },
        );

        MemFs {
            inner: RwLock::new(MemFsInner { inodes }),
            next_id: AtomicU64::new(2),
        }
    }

    fn next_id(&self) -> FileId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn inode_size(inode: &Inode) -> u64 {
        match &inode.data {
            InodeData::File(data) => data.len() as u64,
            InodeData::Directory(entries) => entries.len() as u64,
            InodeData::Symlink(target) => target.len() as u64,
        }
    }

    fn has_remaining_links(inner: &MemFsInner, target: FileId) -> bool {
        inner.inodes.values().any(|inode| match &inode.data {
            InodeData::Directory(entries) => entries.values().any(|id| *id == target),
            _ => false,
        })
    }
}

#[async_trait]
impl NfsFileSystem for MemFs {
    async fn stat(&self, id: FileId) -> NfsResult<NodeInfo> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        Ok(NodeInfo {
            kind: inode.kind,
            size: Self::inode_size(inode),
        })
    }

    async fn lookup(&self, dir_id: FileId, name: &str) -> NfsResult<FileId> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => entries.get(name).copied().ok_or(NfsError::Noent),
            _ => Err(NfsError::Notdir),
        }
    }

    async fn lookup_parent(&self, id: FileId) -> NfsResult<FileId> {
        if id == 1 {
            return Ok(1);
        }

        let inner = self.inner.read().await;
        for (dir_id, inode) in &inner.inodes {
            if let InodeData::Directory(entries) = &inode.data {
                if entries.values().any(|child| *child == id) {
                    return Ok(*dir_id);
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
                let mut result: Vec<DirEntry> = entries
                    .iter()
                    .map(|(name, fileid)| DirEntry {
                        fileid: *fileid,
                        name: name.clone(),
                    })
                    .collect();
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
                Ok((data[offset..end].to_vec(), end == data.len()))
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
                Ok(data.len() as u32)
            }
            _ => Err(NfsError::Inval),
        }
    }

    async fn truncate(&self, id: FileId, size: u64) -> NfsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        match &mut inode.data {
            InodeData::File(file_data) => {
                file_data.resize(size as usize, 0);
                Ok(())
            }
            _ => Err(NfsError::Inval),
        }
    }

    async fn create_file(&self, dir_id: FileId, name: &str) -> NfsResult<FileId> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(
            new_id,
            Inode {
                kind: NodeKind::File,
                data: InodeData::File(Vec::new()),
                xattrs: HashMap::new(),
            },
        );

        Ok(new_id)
    }

    async fn create_dir(&self, dir_id: FileId, name: &str) -> NfsResult<FileId> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(
            new_id,
            Inode {
                kind: NodeKind::Directory,
                data: InodeData::Directory(HashMap::new()),
                xattrs: HashMap::new(),
            },
        );

        Ok(new_id)
    }

    async fn remove(&self, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let dir = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => *entries.get(name).ok_or(NfsError::Noent)?,
                _ => return Err(NfsError::Notdir),
            }
        };

        if let Some(child) = inner.inodes.get(&child_id) {
            if let InodeData::Directory(entries) = &child.data {
                if !entries.is_empty() {
                    return Err(NfsError::Notempty);
                }
            }
        }

        let dir = inner.inodes.get_mut(&dir_id).unwrap();
        if let InodeData::Directory(entries) = &mut dir.data {
            entries.remove(name);
        }

        if !Self::has_remaining_links(&inner, child_id) {
            inner.inodes.remove(&child_id);
        }

        Ok(())
    }

    async fn rename(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let dir = inner.inodes.get(&from_dir).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => *entries.get(from_name).ok_or(NfsError::Noent)?,
                _ => return Err(NfsError::Notdir),
            }
        };

        {
            let dir = inner.inodes.get_mut(&from_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &mut dir.data {
                entries.remove(from_name);
            }
        }

        let removed_target = {
            let tgt = inner.inodes.get_mut(&to_dir).ok_or(NfsError::Stale)?;
            match &mut tgt.data {
                InodeData::Directory(entries) => entries.insert(to_name.to_string(), child_id),
                _ => return Err(NfsError::Notdir),
            }
        };

        if let Some(old_id) = removed_target {
            if !Self::has_remaining_links(&inner, old_id) {
                inner.inodes.remove(&old_id);
            }
        }

        Ok(())
    }

    fn symlinks(&self) -> Option<&dyn NfsSymlinks> {
        Some(self)
    }

    fn hard_links(&self) -> Option<&dyn NfsHardLinks> {
        Some(self)
    }

    fn named_attrs(&self) -> Option<&dyn NfsNamedAttrs> {
        Some(self)
    }

    fn syncer(&self) -> Option<&dyn NfsSync> {
        Some(self)
    }
}

#[async_trait]
impl NfsSymlinks for MemFs {
    async fn symlink(&self, dir_id: FileId, name: &str, target: &str) -> NfsResult<FileId> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), new_id);
            }
            _ => return Err(NfsError::Notdir),
        }

        inner.inodes.insert(
            new_id,
            Inode {
                kind: NodeKind::Symlink,
                data: InodeData::Symlink(target.to_string()),
                xattrs: HashMap::new(),
            },
        );

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
}

#[async_trait]
impl NfsHardLinks for MemFs {
    async fn link(&self, id: FileId, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        if inode.kind == NodeKind::Directory {
            return Err(NfsError::Isdir);
        }

        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        match &mut dir.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(NfsError::Exist);
                }
                entries.insert(name.to_string(), id);
                Ok(())
            }
            _ => Err(NfsError::Notdir),
        }
    }
}

#[async_trait]
impl NfsNamedAttrs for MemFs {
    async fn list_xattrs(&self, id: FileId) -> NfsResult<Vec<String>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        let mut names: Vec<String> = inode.xattrs.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    async fn get_xattr(&self, id: FileId, name: &str) -> NfsResult<Vec<u8>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        inode.xattrs.get(name).cloned().ok_or(NfsError::Noent)
    }

    async fn set_xattr(
        &self,
        id: FileId,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> NfsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        let exists = inode.xattrs.contains_key(name);
        match mode {
            XattrSetMode::CreateOrReplace => {}
            XattrSetMode::CreateOnly if exists => return Err(NfsError::Exist),
            XattrSetMode::ReplaceOnly if !exists => return Err(NfsError::Noent),
            XattrSetMode::CreateOnly | XattrSetMode::ReplaceOnly => {}
        }
        inode.xattrs.insert(name.to_string(), value.to_vec());
        Ok(())
    }

    async fn remove_xattr(&self, id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        inode
            .xattrs
            .remove(name)
            .map(|_| ())
            .ok_or(NfsError::Noent)
    }
}

#[async_trait]
impl NfsSync for MemFs {
    async fn commit(&self, _id: FileId) -> NfsResult<()> {
        Ok(())
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
        let id = fs.create_file(1, "test.txt").await.unwrap();
        let written = fs.write(id, 0, b"hello world").await.unwrap();
        assert_eq!(written, 11);
        let (data, eof) = fs.read(id, 0, 1024).await.unwrap();
        assert_eq!(data, b"hello world");
        assert!(eof);
    }

    #[tokio::test]
    async fn test_mkdir_and_readdir() {
        let fs = MemFs::new();
        let dir_id = fs.create_dir(1, "subdir").await.unwrap();
        let entries = fs.readdir(1).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "subdir");
        assert_eq!(entries[0].fileid, dir_id);
    }

    #[tokio::test]
    async fn test_remove() {
        let fs = MemFs::new();
        let _id = fs.create_file(1, "to_delete.txt").await.unwrap();
        fs.remove(1, "to_delete.txt").await.unwrap();
        assert!(fs.lookup(1, "to_delete.txt").await.is_err());
    }

    #[tokio::test]
    async fn test_rename() {
        let fs = MemFs::new();
        fs.create_file(1, "old.txt").await.unwrap();
        fs.rename(1, "old.txt", 1, "new.txt").await.unwrap();
        assert!(fs.lookup(1, "old.txt").await.is_err());
        assert!(fs.lookup(1, "new.txt").await.is_ok());
    }

    #[tokio::test]
    async fn test_named_attrs_roundtrip() {
        let fs = MemFs::new();
        let id = fs.create_file(1, "notes.txt").await.unwrap();

        fs.set_xattr(id, "user.demo", b"value", XattrSetMode::CreateOnly)
            .await
            .unwrap();
        assert_eq!(fs.get_xattr(id, "user.demo").await.unwrap(), b"value");
        assert_eq!(fs.list_xattrs(id).await.unwrap(), vec!["user.demo".to_string()]);

        fs.remove_xattr(id, "user.demo").await.unwrap();
        assert!(matches!(fs.get_xattr(id, "user.demo").await, Err(NfsError::Noent)));
    }
}

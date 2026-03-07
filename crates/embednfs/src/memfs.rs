/// In-memory filesystem implementation.
///
/// Provides a fully functional in-memory filesystem for testing and as
/// a reference implementation of the [`FileSystem`] trait.
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs;
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
            archive: false,
            hidden: false,
            system: false,
        };

        // No . or .. stored; they're synthesized by the server
        inodes.insert(
            1,
            Inode {
                attr: root_attr,
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

    fn split_components(path: &str) -> NfsResult<Vec<&str>> {
        if !path.starts_with('/') {
            return Err(NfsError::Inval);
        }
        if path == "/" {
            return Ok(Vec::new());
        }
        let trimmed = path.trim_end_matches('/');
        let mut components = Vec::new();
        for component in trimmed.trim_start_matches('/').split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(NfsError::Inval);
            }
            components.push(component);
        }
        Ok(components)
    }

    fn split_parent(path: &str) -> NfsResult<(String, String)> {
        let trimmed = if path == "/" {
            return Err(NfsError::Inval);
        } else {
            path.trim_end_matches('/')
        };
        if !trimmed.starts_with('/') {
            return Err(NfsError::Inval);
        }
        let (parent, name) = trimmed.rsplit_once('/').ok_or(NfsError::Inval)?;
        if name.is_empty() || name == "." || name == ".." {
            return Err(NfsError::Inval);
        }
        let parent = if parent.is_empty() { "/" } else { parent };
        Ok((parent.to_string(), name.to_string()))
    }

    async fn resolve_path(&self, path: &str) -> NfsResult<FileId> {
        let components = Self::split_components(path)?;
        let inner = self.inner.read().await;
        let mut current = 1;
        for component in components {
            let inode = inner.inodes.get(&current).ok_or(NfsError::Stale)?;
            match &inode.data {
                InodeData::Directory(entries) => {
                    current = *entries.get(component).ok_or(NfsError::Noent)?;
                }
                _ => return Err(NfsError::Notdir),
            }
        }
        Ok(current)
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

#[async_trait]
impl FileSystem for MemFs {
    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities::default()
    }

    async fn metadata(&self, path: &str) -> FsResult<Metadata> {
        let id = self.resolve_path(path).await?;
        let attr = self.getattr_id(id).await?;
        Ok(Self::metadata_from_attr(&attr))
    }

    async fn list(&self, path: &str) -> FsResult<Vec<PathDirEntry>> {
        let dir_id = self.resolve_path(path).await?;
        let entries = self.readdir_id(dir_id).await?;
        Ok(entries
            .into_iter()
            .map(|entry| PathDirEntry {
                name: entry.name,
                metadata: Self::metadata_from_attr(&entry.attr),
            })
            .collect())
    }

    async fn read(&self, path: &str, offset: u64, count: u32) -> FsResult<Vec<u8>> {
        let id = self.resolve_path(path).await?;
        let (data, _eof) = self.read_id(id, offset, count).await?;
        Ok(data)
    }

    async fn create_file(&self, path: &str) -> FsResult<()> {
        let (parent, name) = Self::split_parent(path)?;
        let parent_id = self.resolve_path(&parent).await?;
        self.create_in_dir(parent_id, &name, &SetFileAttr::default())
            .await
            .map(|_| ())
    }

    async fn create_dir(&self, path: &str) -> FsResult<()> {
        let (parent, name) = Self::split_parent(path)?;
        let parent_id = self.resolve_path(&parent).await?;
        self.mkdir_in_dir(parent_id, &name, &SetFileAttr::default())
            .await
            .map(|_| ())
    }

    async fn create_symlink(&self, path: &str, target: &str) -> FsResult<()> {
        let (parent, name) = Self::split_parent(path)?;
        let parent_id = self.resolve_path(&parent).await?;
        self.symlink_in_dir(parent_id, &name, target, &SetFileAttr::default())
            .await
            .map(|_| ())
    }

    async fn read_symlink(&self, path: &str) -> FsResult<String> {
        let id = self.resolve_path(path).await?;
        self.readlink_id(id).await
    }

    async fn remove(&self, path: &str, _expected_revision: Option<&str>) -> FsResult<()> {
        let (parent, name) = Self::split_parent(path)?;
        let parent_id = self.resolve_path(&parent).await?;
        self.remove_from_dir(parent_id, &name).await
    }

    async fn rename(
        &self,
        from: &str,
        to: &str,
        _expected_revision: Option<&str>,
    ) -> FsResult<()> {
        let (from_parent, from_name) = Self::split_parent(from)?;
        let (to_parent, to_name) = Self::split_parent(to)?;
        let from_parent_id = self.resolve_path(&from_parent).await?;
        let to_parent_id = self.resolve_path(&to_parent).await?;
        self.rename_in_dirs(from_parent_id, &from_name, to_parent_id, &to_name)
            .await
    }

    async fn replace_file(
        &self,
        path: &str,
        local_path: &Path,
        _expected_revision: Option<&str>,
    ) -> FsResult<()> {
        let data = fs::read(local_path).await.map_err(|_| FsError::Io)?;
        let id = match self.resolve_path(path).await {
            Ok(id) => id,
            Err(NfsError::Noent) => {
                self.create_file(path).await?;
                self.resolve_path(path).await?
            }
            Err(err) => return Err(err),
        };

        self.setattr_id(
            id,
            SetFileAttr {
                size: Some(0),
                ..SetFileAttr::default()
            },
        )
        .await?;
        if !data.is_empty() {
            self.write_id(id, 0, &data).await?;
        }
        Ok(())
    }

    async fn write_file(&self, path: &str, offset: u64, data: &[u8]) -> FsResult<u32> {
        let id = self.resolve_path(path).await?;
        self.write_id(id, offset, data).await
    }

    async fn set_len(&self, path: &str, size: u64) -> FsResult<()> {
        let id = self.resolve_path(path).await?;
        self.setattr_id(
            id,
            SetFileAttr {
                size: Some(size),
                ..SetFileAttr::default()
            },
        )
        .await
        .map(|_| ())
    }

    async fn sync(&self, path: &str) -> FsResult<()> {
        let id = self.resolve_path(path).await?;
        self.commit_id(id).await
    }
}

impl MemFs {
    async fn getattr_id(&self, id: FileId) -> NfsResult<FileAttr> {
        let inner = self.inner.read().await;
        inner
            .inodes
            .get(&id)
            .map(|i| i.attr.clone())
            .ok_or(NfsError::Stale)
    }

    async fn setattr_id(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(&id).ok_or(NfsError::Stale)?;
        let (now_s, now_ns) = Self::now();

        if let Some(size) = attrs.size
            && let InodeData::File(ref mut data) = inode.data
        {
            data.resize(size as usize, 0);
            inode.attr.size = size;
            inode.attr.used = size;
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
        if let Some(crtime) = attrs.crtime {
            match crtime {
                SetTime::ServerTime => {
                    inode.attr.crtime_sec = now_s;
                    inode.attr.crtime_nsec = now_ns;
                }
                SetTime::ClientTime(s, ns) => {
                    inode.attr.crtime_sec = s;
                    inode.attr.crtime_nsec = ns;
                }
            }
        }

        inode.attr.ctime_sec = now_s;
        inode.attr.ctime_nsec = now_ns;
        inode.attr.change_id = self.next_change();

        Ok(inode.attr.clone())
    }

    async fn readdir_id(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>> {
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

    async fn read_id(&self, id: FileId, offset: u64, count: u32) -> NfsResult<(Vec<u8>, bool)> {
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

    async fn write_id(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32> {
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

    async fn create_in_dir(
        &self,
        dir_id: FileId,
        name: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId> {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (now_s, now_ns) = Self::now();
        let mode = attrs.mode.unwrap_or(0o644);

        let (cr_s, cr_ns) = match attrs.crtime {
            Some(SetTime::ClientTime(s, ns)) => (s, ns),
            _ => (now_s, now_ns),
        };

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
            crtime_sec: cr_s,
            crtime_nsec: cr_ns,
            change_id: self.next_change(),
            rdev_major: 0,
            rdev_minor: 0,
            archive: false,
            hidden: false,
            system: false,
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

        inner.inodes.insert(
            new_id,
            Inode {
                attr: file_attr,
                data: InodeData::File(Vec::new()),
            },
        );

        Ok(new_id)
    }

    async fn mkdir_in_dir(
        &self,
        dir_id: FileId,
        name: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId> {
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
            archive: false,
            hidden: false,
            system: false,
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

        inner.inodes.insert(
            new_id,
            Inode {
                attr: dir_attr,
                data: InodeData::Directory(HashMap::new()),
            },
        );

        Ok(new_id)
    }

    async fn symlink_in_dir(
        &self,
        dir_id: FileId,
        name: &str,
        target: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId> {
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
            archive: false,
            hidden: false,
            system: false,
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

        inner.inodes.insert(
            new_id,
            Inode {
                attr: link_attr,
                data: InodeData::Symlink(target.to_string()),
            },
        );

        Ok(new_id)
    }

    async fn readlink_id(&self, id: FileId) -> NfsResult<String> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(NfsError::Inval),
        }
    }

    async fn remove_from_dir(&self, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let dir = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => *entries.get(name).ok_or(NfsError::Noent)?,
                _ => return Err(NfsError::Notdir),
            }
        };

        // Check if child is a non-empty directory
        if let Some(child) = inner.inodes.get(&child_id)
            && let InodeData::Directory(entries) = &child.data
            && !entries.is_empty()
        {
            return Err(NfsError::Notempty);
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

    async fn rename_in_dirs(
        &self,
        from_dir: FileId,
        from_name: &str,
        to_dir: FileId,
        to_name: &str,
    ) -> NfsResult<()> {
        let mut inner = self.inner.write().await;

        // Get source file id
        let child_id = {
            let dir = inner.inodes.get(&from_dir).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => *entries.get(from_name).ok_or(NfsError::Noent)?,
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
            if let InodeData::Directory(entries) = &tgt_dir.data
                && let Some(&old_id) = entries.get(to_name)
            {
                inner.inodes.remove(&old_id);
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

    async fn commit_id(&self, _id: FileId) -> NfsResult<()> {
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
        fs.create_file("/test.txt").await.unwrap();
        let written = fs.write_file("/test.txt", 0, b"hello world").await.unwrap();
        assert_eq!(written, 11);
        let data = FileSystem::read(&fs, "/test.txt", 0, 1024).await.unwrap();
        assert_eq!(data, b"hello world");
    }

    #[tokio::test]
    async fn test_mkdir_and_readdir() {
        let fs = MemFs::new();
        fs.create_dir("/subdir").await.unwrap();
        let entries = fs.list("/").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "subdir");
        assert_eq!(entries[0].metadata.file_type, FileType::Directory);
    }

    #[tokio::test]
    async fn test_remove() {
        let fs = MemFs::new();
        fs.create_file("/to_delete.txt").await.unwrap();
        FileSystem::remove(&fs, "/to_delete.txt", None)
            .await
            .unwrap();
        assert!(fs.metadata("/to_delete.txt").await.is_err());
    }

    #[tokio::test]
    async fn test_rename() {
        let fs = MemFs::new();
        fs.create_file("/old.txt").await.unwrap();
        FileSystem::rename(&fs, "/old.txt", "/new.txt", None)
            .await
            .unwrap();
        assert!(fs.metadata("/old.txt").await.is_err());
        assert!(fs.metadata("/new.txt").await.is_ok());
    }

    #[tokio::test]
    async fn test_path_based_filesystem_roundtrip() {
        let fs = MemFs::new();
        fs.create_dir("/docs").await.unwrap();
        fs.create_file("/docs/readme.txt").await.unwrap();
        fs.write_file("/docs/readme.txt", 0, b"hello path api")
            .await
            .unwrap();

        let metadata = fs.metadata("/docs/readme.txt").await.unwrap();
        assert_eq!(metadata.size, 14);
        assert_eq!(metadata.file_type, FileType::Regular);

        let entries = fs.list("/docs").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "readme.txt");

        let data = FileSystem::read(&fs, "/docs/readme.txt", 0, 64)
            .await
            .unwrap();
        assert_eq!(data, b"hello path api");
    }

    #[tokio::test]
    async fn test_replace_file_overwrites_previous_contents() {
        let fs = MemFs::new();
        fs.create_file("/replace.txt").await.unwrap();
        fs.write_file("/replace.txt", 0, b"stale data").await.unwrap();

        let local_path = std::env::temp_dir().join("embednfs-replace-test.txt");
        fs::write(&local_path, b"fresh").await.unwrap();
        fs.replace_file("/replace.txt", &local_path, None)
            .await
            .unwrap();

        let data = FileSystem::read(&fs, "/replace.txt", 0, 64)
            .await
            .unwrap();
        assert_eq!(data, b"fresh");

        let _ = std::fs::remove_file(local_path);
    }
}

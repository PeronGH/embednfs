use std::collections::HashMap;
use std::sync::atomic::Ordering;

use crate::fs::{
    DirEntry, FileAttr, FileId, FileType, NfsError, NfsResult, SetFileAttr, SetTime,
};

use super::{Inode, InodeData, MemFs};

impl MemFs {
    pub(super) async fn getattr_id(&self, id: FileId) -> NfsResult<FileAttr> {
        let inner = self.inner.read().await;
        inner
            .inodes
            .get(&id)
            .map(|inode| inode.attr.clone())
            .ok_or(NfsError::Stale)
    }

    pub(super) async fn setattr_id(&self, id: FileId, attrs: SetFileAttr) -> NfsResult<FileAttr> {
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

    pub(super) async fn readdir_id(&self, dir_id: FileId) -> NfsResult<Vec<DirEntry>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => {
                let mut result = Vec::with_capacity(entries.len());
                for (name, child_id) in entries {
                    if let Some(child) = inner.inodes.get(child_id) {
                        result.push(DirEntry {
                            name: name.clone(),
                            attr: child.attr.clone(),
                        });
                    }
                }
                result.sort_by(|left, right| left.name.cmp(&right.name));
                Ok(result)
            }
            InodeData::File(_) | InodeData::Symlink(_) => Err(NfsError::Notdir),
        }
    }

    pub(super) async fn read_id(
        &self,
        id: FileId,
        offset: u64,
        count: u32,
    ) -> NfsResult<(Vec<u8>, bool)> {
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
            InodeData::Directory(_) | InodeData::Symlink(_) => Err(NfsError::Inval),
        }
    }

    pub(super) async fn write_id(&self, id: FileId, offset: u64, data: &[u8]) -> NfsResult<u32> {
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
                let (sec, nsec) = Self::now();
                inode.attr.mtime_sec = sec;
                inode.attr.mtime_nsec = nsec;
                inode.attr.ctime_sec = sec;
                inode.attr.ctime_nsec = nsec;
                inode.attr.change_id = self.next_change();
                Ok(data.len() as u32)
            }
            InodeData::Directory(_) | InodeData::Symlink(_) => Err(NfsError::Inval),
        }
    }

    pub(super) async fn create_in_dir(
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
                let (sec, nsec) = Self::now();
                dir.attr.mtime_sec = sec;
                dir.attr.mtime_nsec = nsec;
            }
            InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
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

    pub(super) async fn mkdir_in_dir(
        &self,
        dir_id: FileId,
        name: &str,
        attrs: &SetFileAttr,
    ) -> NfsResult<FileId> {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (now_s, now_ns) = Self::now();
        let dir_attr = FileAttr {
            fileid: new_id,
            file_type: FileType::Directory,
            size: 4096,
            used: 4096,
            mode: attrs.mode.unwrap_or(0o755),
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
                let (sec, nsec) = Self::now();
                parent.attr.mtime_sec = sec;
                parent.attr.mtime_nsec = nsec;
            }
            InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
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

    pub(super) async fn symlink_in_dir(
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
            InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
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

    pub(super) async fn readlink_id(&self, id: FileId) -> NfsResult<String> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(&id).ok_or(NfsError::Stale)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            InodeData::File(_) | InodeData::Directory(_) => Err(NfsError::Inval),
        }
    }

    pub(super) async fn remove_from_dir(&self, dir_id: FileId, name: &str) -> NfsResult<()> {
        let mut inner = self.inner.write().await;
        let child_id = {
            let dir = inner.inodes.get(&dir_id).ok_or(NfsError::Stale)?;
            match &dir.data {
                InodeData::Directory(entries) => *entries.get(name).ok_or(NfsError::Noent)?,
                InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
            }
        };

        if let Some(child) = inner.inodes.get(&child_id)
            && let InodeData::Directory(entries) = &child.data
            && !entries.is_empty()
        {
            return Err(NfsError::Notempty);
        }

        let dir = inner.inodes.get_mut(&dir_id).ok_or(NfsError::Stale)?;
        if let InodeData::Directory(entries) = &mut dir.data {
            entries.remove(name);
        }
        dir.attr.change_id = self.next_change();
        let (sec, nsec) = Self::now();
        dir.attr.mtime_sec = sec;
        dir.attr.mtime_nsec = nsec;

        inner.inodes.remove(&child_id);
        Ok(())
    }

    pub(super) async fn rename_in_dirs(
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
                InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
            }
        };

        {
            let dir = inner.inodes.get_mut(&from_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &mut dir.data {
                entries.remove(from_name);
            }
            dir.attr.change_id = self.next_change();
        }

        {
            let tgt_dir = inner.inodes.get(&to_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &tgt_dir.data
                && let Some(&old_id) = entries.get(to_name)
            {
                inner.inodes.remove(&old_id);
            }
        }

        {
            let tgt_dir = inner.inodes.get_mut(&to_dir).ok_or(NfsError::Stale)?;
            if let InodeData::Directory(entries) = &mut tgt_dir.data {
                entries.insert(to_name.to_string(), child_id);
            }
            tgt_dir.attr.change_id = self.next_change();
        }

        Ok(())
    }

    pub(super) async fn commit_id(&self, _id: FileId) -> NfsResult<()> {
        Ok(())
    }
}

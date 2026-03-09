//! In-memory reference backend for the filesystem API.

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use crate::fs::*;

/// In-memory filesystem implementation used by tests and examples.
pub struct MemFs {
    inner: RwLock<MemFsInner>,
    next_id: AtomicU64,
    next_change: AtomicU64,
}

struct MemFsInner {
    inodes: HashMap<u64, Inode>,
}

struct Inode {
    attrs: Attrs,
    parent: Option<u64>,
    data: InodeData,
    xattrs: HashMap<String, Bytes>,
}

enum InodeData {
    File(Vec<u8>),
    Directory(HashMap<String, u64>),
    Symlink(String),
}

impl MemFs {
    /// Creates a new empty in-memory filesystem.
    pub fn new() -> Self {
        let mut inodes = HashMap::new();
        let mut root_attrs = Attrs::new(ObjectType::Directory, 1);
        root_attrs.mode = 0o777;
        inodes.insert(
            1,
            Inode {
                attrs: root_attrs,
                parent: None,
                data: InodeData::Directory(HashMap::new()),
                xattrs: HashMap::new(),
            },
        );

        Self {
            inner: RwLock::new(MemFsInner { inodes }),
            next_id: AtomicU64::new(2),
            next_change: AtomicU64::new(2),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_change(&self) -> u64 {
        self.next_change.fetch_add(1, Ordering::Relaxed)
    }

    fn touch_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.ctime = now;
    }

    fn touch_data_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.mtime = now;
        attrs.ctime = now;
    }

    fn apply_set_time(field: &mut Timestamp, value: SetTime) {
        *field = match value {
            SetTime::ServerNow => Timestamp::now(),
            SetTime::Client(ts) => ts,
        };
    }

    fn apply_create_owner(attrs: &mut Attrs, ctx: &RequestContext) {
        if let AuthContext::Sys { uid, gid, .. } = &ctx.auth {
            attrs.uid = *uid;
            attrs.gid = *gid;
        }
    }

    fn apply_setattrs(&self, inode: &mut Inode, attrs: &SetAttrs) -> FsResult<()> {
        let mut changed = false;

        if let Some(size) = attrs.size {
            match &mut inode.data {
                InodeData::File(data) => {
                    data.resize(size as usize, 0);
                    inode.attrs.size = size;
                    inode.attrs.space_used = size;
                    changed = true;
                }
                _ => return Err(FsError::InvalidInput),
            }
        }
        if let Some(mode) = attrs.mode {
            inode.attrs.mode = mode & 0o7777;
            changed = true;
        }
        if let Some(uid) = attrs.uid {
            inode.attrs.uid = uid;
            changed = true;
        }
        if let Some(gid) = attrs.gid {
            inode.attrs.gid = gid;
            changed = true;
        }
        if let Some(archive) = attrs.archive {
            inode.attrs.archive = archive;
            changed = true;
        }
        if let Some(hidden) = attrs.hidden {
            inode.attrs.hidden = hidden;
            changed = true;
        }
        if let Some(system) = attrs.system {
            inode.attrs.system = system;
            changed = true;
        }
        if let Some(atime) = attrs.atime {
            Self::apply_set_time(&mut inode.attrs.atime, atime);
            changed = true;
        }
        if let Some(mtime) = attrs.mtime {
            Self::apply_set_time(&mut inode.attrs.mtime, mtime);
            changed = true;
        }
        if let Some(birthtime) = attrs.birthtime {
            Self::apply_set_time(&mut inode.attrs.birthtime, birthtime);
            changed = true;
        }

        if changed {
            self.touch_change(&mut inode.attrs);
        }

        Ok(())
    }

    fn recompute_link_counts(inner: &mut MemFsInner) {
        for inode in inner.inodes.values_mut() {
            inode.attrs.link_count = match inode.attrs.object_type {
                ObjectType::Directory => 2,
                _ => 0,
            };
        }

        let directory_ids: Vec<u64> = inner
            .inodes
            .iter()
            .filter_map(|(id, inode)| match inode.data {
                InodeData::Directory(_) => Some(*id),
                _ => None,
            })
            .collect();

        for dir_id in directory_ids {
            let entries = match &inner.inodes.get(&dir_id).unwrap().data {
                InodeData::Directory(entries) => entries.clone(),
                _ => continue,
            };
            for child_id in entries.values() {
                if let Some(child) = inner.inodes.get_mut(child_id) {
                    match child.attrs.object_type {
                        ObjectType::Directory => {
                            if let Some(parent) = inner.inodes.get_mut(&dir_id) {
                                parent.attrs.link_count += 1;
                            }
                        }
                        _ => child.attrs.link_count += 1,
                    }
                }
            }
        }
    }

    fn remove_if_unlinked(inner: &mut MemFsInner, inode_id: u64) {
        let should_remove = match inner.inodes.get(&inode_id) {
            Some(inode) => match inode.attrs.object_type {
                ObjectType::Directory => true,
                _ => !inner
                    .inodes
                    .values()
                    .any(|candidate| match &candidate.data {
                        InodeData::Directory(entries) => entries.values().any(|id| *id == inode_id),
                        _ => false,
                    }),
            },
            None => false,
        };

        if should_remove {
            inner.inodes.remove(&inode_id);
        }
    }

    fn update_has_named_attrs(inode: &mut Inode) {
        inode.attrs.has_named_attrs = !inode.xattrs.is_empty();
    }

    fn allowed_mode_bits(attrs: &Attrs, auth: &AuthContext) -> u32 {
        match auth {
            AuthContext::Sys {
                uid,
                gid,
                supplemental_gids,
            } => {
                if *uid == 0 {
                    return 0o7;
                }
                if *uid == attrs.uid {
                    return (attrs.mode >> 6) & 0o7;
                }
                if *gid == attrs.gid || supplemental_gids.contains(&attrs.gid) {
                    return (attrs.mode >> 3) & 0o7;
                }
                attrs.mode & 0o7
            }
            AuthContext::None | AuthContext::Unknown { .. } => attrs.mode & 0o7,
        }
    }

    fn access_mask_for(attrs: &Attrs, auth: &AuthContext, requested: AccessMask) -> AccessMask {
        let perms = Self::allowed_mode_bits(attrs, auth);
        let mut allowed = AccessMask::NONE;

        if requested.intersects(AccessMask::READ) && (perms & 0o4) != 0 {
            allowed |= AccessMask::READ;
        }
        if requested.intersects(AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE)
            && (perms & 0o2) != 0
        {
            if requested.intersects(AccessMask::MODIFY) {
                allowed |= AccessMask::MODIFY;
            }
            if requested.intersects(AccessMask::EXTEND) {
                allowed |= AccessMask::EXTEND;
            }
            if requested.intersects(AccessMask::DELETE) {
                allowed |= AccessMask::DELETE;
            }
        }
        if requested.intersects(AccessMask::EXECUTE) && (perms & 0o1) != 0 {
            allowed |= AccessMask::EXECUTE;
        }
        if attrs.object_type == ObjectType::Directory
            && requested.intersects(AccessMask::LOOKUP)
            && (perms & 0o1) != 0
        {
            allowed |= AccessMask::LOOKUP;
        }

        allowed
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FileSystem for MemFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle {
        1
    }

    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities {
            symlinks: true,
            hard_links: true,
            xattrs: true,
            explicit_sync: true,
            case_sensitive: true,
            case_preserving: true,
        }
    }

    async fn statfs(&self, _ctx: &RequestContext) -> FsResult<FsStats> {
        let inner = self.inner.read().await;
        let used_bytes: u64 = inner
            .inodes
            .values()
            .map(|inode| inode.attrs.space_used)
            .sum();
        let total_files = 1 << 20;
        let used_files = inner.inodes.len() as u64;

        Ok(FsStats {
            total_bytes: 1 << 30,
            free_bytes: (1 << 30) - used_bytes,
            avail_bytes: (1 << 30) - used_bytes,
            total_files,
            free_files: total_files - used_files,
            avail_files: total_files - used_files,
        })
    }

    async fn getattr(&self, _ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        Ok(inode.attrs.clone())
    }

    async fn access(
        &self,
        ctx: &RequestContext,
        handle: &Self::Handle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        Ok(Self::access_mask_for(&inode.attrs, &ctx.auth, requested) & requested)
    }

    async fn lookup(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<Self::Handle> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::Directory(entries) => entries.get(name).copied().ok_or(FsError::NotFound),
            _ => Err(FsError::NotDirectory),
        }
    }

    async fn parent(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
    ) -> FsResult<Option<Self::Handle>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(dir).ok_or(FsError::Stale)?;
        if inode.attrs.object_type != ObjectType::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(inode.parent)
    }

    async fn readdir(
        &self,
        _ctx: &RequestContext,
        dir: &Self::Handle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<Self::Handle>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(dir).ok_or(FsError::Stale)?;
        let entries = match &inode.data {
            InodeData::Directory(entries) => entries,
            _ => return Err(FsError::NotDirectory),
        };

        let mut names: Vec<_> = entries.iter().collect();
        names.sort_by(|a, b| a.0.cmp(b.0));

        let start = if cookie == 0 {
            0
        } else {
            cookie.saturating_sub(2) as usize
        };
        let limit = if max_entries == 0 {
            usize::MAX
        } else {
            max_entries as usize
        };

        let mut page = Vec::with_capacity(limit.min(names.len().saturating_sub(start)));
        for (idx, (name, child)) in names.into_iter().skip(start).take(limit).enumerate() {
            let child_inode = inner.inodes.get(child).ok_or(FsError::Stale)?;
            page.push(DirEntry {
                name: name.clone(),
                handle: *child,
                cookie: (start + idx + 3) as u64,
                attrs: with_attrs.then(|| child_inode.attrs.clone()),
            });
        }

        Ok(DirPage {
            eof: start + page.len() >= entries.len(),
            entries: page,
        })
    }

    async fn read(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::File(data) => {
                let offset = offset as usize;
                if offset >= data.len() {
                    return Ok(ReadResult {
                        data: Bytes::new(),
                        eof: true,
                    });
                }
                let end = (offset + count as usize).min(data.len());
                Ok(ReadResult {
                    data: Bytes::copy_from_slice(&data[offset..end]),
                    eof: end == data.len(),
                })
            }
            _ => Err(FsError::InvalidInput),
        }
    }

    async fn write(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        offset: u64,
        data: Bytes,
    ) -> FsResult<WriteResult> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        match &mut inode.data {
            InodeData::File(file) => {
                let offset = offset as usize;
                let end = offset + data.len();
                if end > file.len() {
                    file.resize(end, 0);
                }
                file[offset..end].copy_from_slice(&data);
                inode.attrs.size = file.len() as u64;
                inode.attrs.space_used = inode.attrs.size;
                self.touch_data_change(&mut inode.attrs);
                Ok(WriteResult {
                    written: data.len() as u32,
                    stability: WriteStability::FileSync,
                })
            }
            _ => Err(FsError::InvalidInput),
        }
    }

    async fn create(
        &self,
        ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<Self::Handle>> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            if parent_inode.attrs.object_type != ObjectType::Directory {
                return Err(FsError::NotDirectory);
            }
            if let InodeData::Directory(entries) = &parent_inode.data
                && entries.contains_key(name)
            {
                return Err(FsError::AlreadyExists);
            }
        }

        let mut inode = Inode {
            attrs: Attrs::new(
                match req.kind {
                    CreateKind::File => ObjectType::File,
                    CreateKind::Directory => ObjectType::Directory,
                },
                new_id,
            ),
            parent: Some(*parent),
            data: match req.kind {
                CreateKind::File => InodeData::File(Vec::new()),
                CreateKind::Directory => InodeData::Directory(HashMap::new()),
            },
            xattrs: HashMap::new(),
        };
        Self::apply_create_owner(&mut inode.attrs, ctx);
        self.apply_setattrs(&mut inode, &req.attrs)?;

        if let InodeData::Directory(entries) = &mut inner.inodes.get_mut(parent).unwrap().data {
            entries.insert(name.to_string(), new_id);
        }
        if let Some(parent_inode) = inner.inodes.get_mut(parent) {
            self.touch_change(&mut parent_inode.attrs);
            parent_inode.attrs.mtime = Timestamp::now();
        }
        inner.inodes.insert(new_id, inode);
        Self::recompute_link_counts(&mut inner);

        let attrs = inner.inodes.get(&new_id).unwrap().attrs.clone();
        Ok(CreateResult {
            handle: new_id,
            attrs,
        })
    }

    async fn remove(
        &self,
        _ctx: &RequestContext,
        parent: &Self::Handle,
        name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let child_id = {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            match &parent_inode.data {
                InodeData::Directory(entries) => *entries.get(name).ok_or(FsError::NotFound)?,
                _ => return Err(FsError::NotDirectory),
            }
        };

        if let Some(child) = inner.inodes.get(&child_id)
            && let InodeData::Directory(entries) = &child.data
            && !entries.is_empty()
        {
            return Err(FsError::NotEmpty);
        }

        if let Some(parent_inode) = inner.inodes.get_mut(parent) {
            if let InodeData::Directory(entries) = &mut parent_inode.data {
                entries.remove(name);
            }
            self.touch_change(&mut parent_inode.attrs);
            parent_inode.attrs.mtime = Timestamp::now();
        }

        Self::remove_if_unlinked(&mut inner, child_id);
        Self::recompute_link_counts(&mut inner);
        Ok(())
    }

    async fn rename(
        &self,
        _ctx: &RequestContext,
        from_dir: &Self::Handle,
        from_name: &str,
        to_dir: &Self::Handle,
        to_name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;

        let child_id = {
            let from_inode = inner.inodes.get(from_dir).ok_or(FsError::Stale)?;
            match &from_inode.data {
                InodeData::Directory(entries) => {
                    *entries.get(from_name).ok_or(FsError::NotFound)?
                }
                _ => return Err(FsError::NotDirectory),
            }
        };

        let replaced = {
            let target_inode = inner.inodes.get_mut(to_dir).ok_or(FsError::Stale)?;
            match &mut target_inode.data {
                InodeData::Directory(entries) => entries.insert(to_name.to_string(), child_id),
                _ => return Err(FsError::NotDirectory),
            }
        };

        if let Some(replaced_id) = replaced
            && let Some(replaced_inode) = inner.inodes.get(&replaced_id)
            && let InodeData::Directory(entries) = &replaced_inode.data
            && !entries.is_empty()
        {
            return Err(FsError::NotEmpty);
        }

        if let Some(from_inode) = inner.inodes.get_mut(from_dir) {
            if let InodeData::Directory(entries) = &mut from_inode.data {
                entries.remove(from_name);
            }
            self.touch_change(&mut from_inode.attrs);
            from_inode.attrs.mtime = Timestamp::now();
        }
        if let Some(to_inode) = inner.inodes.get_mut(to_dir) {
            self.touch_change(&mut to_inode.attrs);
            to_inode.attrs.mtime = Timestamp::now();
        }
        if let Some(child_inode) = inner.inodes.get_mut(&child_id)
            && child_inode.attrs.object_type == ObjectType::Directory
        {
            child_inode.parent = Some(*to_dir);
        }
        if let Some(replaced_id) = replaced {
            Self::remove_if_unlinked(&mut inner, replaced_id);
        }

        Self::recompute_link_counts(&mut inner);
        Ok(())
    }

    async fn setattr(
        &self,
        _ctx: &RequestContext,
        handle: &Self::Handle,
        attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        self.apply_setattrs(inode, attrs)?;
        Ok(inode.attrs.clone())
    }

    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> {
        Some(self)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> {
        Some(self)
    }

    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> {
        Some(self)
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> {
        Some(self)
    }
}

#[async_trait]
impl Xattrs<u64> for MemFs {
    async fn list_xattrs(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<Vec<String>> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        let mut names: Vec<String> = inode.xattrs.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    async fn get_xattr(&self, _ctx: &RequestContext, handle: &u64, name: &str) -> FsResult<Bytes> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        inode.xattrs.get(name).cloned().ok_or(FsError::NotFound)
    }

    async fn set_xattr(
        &self,
        _ctx: &RequestContext,
        handle: &u64,
        name: &str,
        value: Bytes,
        mode: XattrSetMode,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        let exists = inode.xattrs.contains_key(name);
        match mode {
            XattrSetMode::CreateOrReplace => {}
            XattrSetMode::CreateOnly if exists => return Err(FsError::AlreadyExists),
            XattrSetMode::ReplaceOnly if !exists => return Err(FsError::NotFound),
            XattrSetMode::CreateOnly | XattrSetMode::ReplaceOnly => {}
        }
        inode.xattrs.insert(name.to_string(), value);
        Self::update_has_named_attrs(inode);
        self.touch_data_change(&mut inode.attrs);
        Ok(())
    }

    async fn remove_xattr(&self, _ctx: &RequestContext, handle: &u64, name: &str) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let inode = inner.inodes.get_mut(handle).ok_or(FsError::Stale)?;
        if inode.xattrs.remove(name).is_none() {
            return Err(FsError::NotFound);
        }
        Self::update_has_named_attrs(inode);
        self.touch_change(&mut inode.attrs);
        Ok(())
    }
}

#[async_trait]
impl Symlinks<u64> for MemFs {
    async fn create_symlink(
        &self,
        ctx: &RequestContext,
        parent: &u64,
        name: &str,
        target: &str,
        attrs: &SetAttrs,
    ) -> FsResult<CreateResult<u64>> {
        let new_id = self.next_id();
        let mut inner = self.inner.write().await;

        {
            let parent_inode = inner.inodes.get(parent).ok_or(FsError::Stale)?;
            match &parent_inode.data {
                InodeData::Directory(entries) => {
                    if entries.contains_key(name) {
                        return Err(FsError::AlreadyExists);
                    }
                }
                _ => return Err(FsError::NotDirectory),
            }
        }

        let mut inode = Inode {
            attrs: Attrs::new(ObjectType::Symlink, new_id),
            parent: Some(*parent),
            data: InodeData::Symlink(target.to_string()),
            xattrs: HashMap::new(),
        };
        Self::apply_create_owner(&mut inode.attrs, ctx);
        inode.attrs.size = target.len() as u64;
        inode.attrs.space_used = inode.attrs.size;
        self.apply_setattrs(&mut inode, attrs)?;
        inode.attrs.size = target.len() as u64;
        inode.attrs.space_used = inode.attrs.size;

        if let InodeData::Directory(entries) = &mut inner.inodes.get_mut(parent).unwrap().data {
            entries.insert(name.to_string(), new_id);
        }
        if let Some(parent_inode) = inner.inodes.get_mut(parent) {
            self.touch_change(&mut parent_inode.attrs);
            parent_inode.attrs.mtime = Timestamp::now();
        }
        inner.inodes.insert(new_id, inode);
        Self::recompute_link_counts(&mut inner);

        Ok(CreateResult {
            handle: new_id,
            attrs: inner.inodes.get(&new_id).unwrap().attrs.clone(),
        })
    }

    async fn readlink(&self, _ctx: &RequestContext, handle: &u64) -> FsResult<String> {
        let inner = self.inner.read().await;
        let inode = inner.inodes.get(handle).ok_or(FsError::Stale)?;
        match &inode.data {
            InodeData::Symlink(target) => Ok(target.clone()),
            _ => Err(FsError::InvalidInput),
        }
    }
}

#[async_trait]
impl HardLinks<u64> for MemFs {
    async fn link(
        &self,
        _ctx: &RequestContext,
        source: &u64,
        parent: &u64,
        name: &str,
    ) -> FsResult<()> {
        let mut inner = self.inner.write().await;
        let source_inode = inner.inodes.get(source).ok_or(FsError::Stale)?;
        if source_inode.attrs.object_type == ObjectType::Directory {
            return Err(FsError::IsDirectory);
        }

        let parent_inode = inner.inodes.get_mut(parent).ok_or(FsError::Stale)?;
        match &mut parent_inode.data {
            InodeData::Directory(entries) => {
                if entries.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                entries.insert(name.to_string(), *source);
            }
            _ => return Err(FsError::NotDirectory),
        }
        self.touch_change(&mut parent_inode.attrs);
        parent_inode.attrs.mtime = Timestamp::now();
        Self::recompute_link_counts(&mut inner);
        Ok(())
    }
}

#[async_trait]
impl CommitSupport<u64> for MemFs {
    async fn commit(
        &self,
        _ctx: &RequestContext,
        handle: &u64,
        _offset: u64,
        _count: u32,
    ) -> FsResult<()> {
        let inner = self.inner.read().await;
        if inner.inodes.contains_key(handle) {
            Ok(())
        } else {
            Err(FsError::Stale)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_write_read_round_trip() {
        let fs = MemFs::new();
        let ctx = RequestContext::anonymous();
        let created = fs
            .create(
                &ctx,
                &1,
                "hello.txt",
                CreateRequest {
                    kind: CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap();

        let written = fs
            .write(&ctx, &created.handle, 0, Bytes::from_static(b"hello world"))
            .await
            .unwrap();
        assert_eq!(written.written, 11);

        let read = fs.read(&ctx, &created.handle, 0, 1024).await.unwrap();
        assert_eq!(read.data, Bytes::from_static(b"hello world"));
        assert!(read.eof);
    }

    #[tokio::test]
    async fn readdir_returns_inline_attrs_when_requested() {
        let fs = MemFs::new();
        let ctx = RequestContext::anonymous();
        fs.create(
            &ctx,
            &1,
            "dir",
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

        let page = fs.readdir(&ctx, &1, 0, 16, true).await.unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].name, "dir");
        assert_eq!(
            page.entries[0].attrs.as_ref().unwrap().object_type,
            ObjectType::Directory
        );
    }

    #[tokio::test]
    async fn xattrs_update_exported_attrs() {
        let fs = MemFs::new();
        let ctx = RequestContext::anonymous();
        let created = fs
            .create(
                &ctx,
                &1,
                "data",
                CreateRequest {
                    kind: CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap();

        fs.set_xattr(
            &ctx,
            &created.handle,
            "com.apple.test",
            Bytes::from_static(b"value"),
            XattrSetMode::CreateOnly,
        )
        .await
        .unwrap();

        let attrs = fs.getattr(&ctx, &created.handle).await.unwrap();
        assert!(attrs.has_named_attrs);
    }

    #[tokio::test]
    async fn root_is_writable_for_non_owner_auth_sys_callers() {
        let fs = MemFs::new();
        let ctx = RequestContext {
            auth: AuthContext::Sys {
                uid: 501,
                gid: 20,
                supplemental_gids: vec![],
            },
        };

        let granted = fs
            .access(
                &ctx,
                &1,
                AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE | AccessMask::LOOKUP,
            )
            .await
            .unwrap();

        assert!(granted.contains(AccessMask::MODIFY));
        assert!(granted.contains(AccessMask::EXTEND));
        assert!(granted.contains(AccessMask::DELETE));
        assert!(granted.contains(AccessMask::LOOKUP));
    }

    #[tokio::test]
    async fn create_stamps_auth_sys_owner_by_default() {
        let fs = MemFs::new();
        let ctx = RequestContext {
            auth: AuthContext::Sys {
                uid: 501,
                gid: 20,
                supplemental_gids: vec![12],
            },
        };

        let created = fs
            .create(
                &ctx,
                &1,
                "owned.txt",
                CreateRequest {
                    kind: CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap();

        let attrs = fs.getattr(&ctx, &created.handle).await.unwrap();
        assert_eq!(attrs.uid, 501);
        assert_eq!(attrs.gid, 20);
        assert_eq!(attrs.mode, 0o644);
    }
}

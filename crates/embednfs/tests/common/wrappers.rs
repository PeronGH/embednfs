use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::Notify;

use embednfs::{
    AccessMask, Attrs, CommitSupport, CreateRequest, CreateResult, DirPage, FileSystem, FsError,
    FsResult, FsStats, HardLinks, MemFs, ReadResult, RequestContext, SetAttrs, Symlinks,
    WriteResult, XattrSetMode, Xattrs,
};

pub struct BlockingRemoveFs {
    pub inner: MemFs,
    pub entered: Arc<Notify>,
    pub release: Arc<Notify>,
}

pub struct CountingNamedAttrFs {
    pub inner: MemFs,
    pub list_count: Arc<AtomicUsize>,
}

pub struct FailPostMutationRootStatFs {
    pub inner: MemFs,
    pub root_stat_limit: usize,
    pub root_stat_calls: AtomicUsize,
}

pub struct FailFirstRootStatFs {
    pub inner: MemFs,
    pub root_stat_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl FileSystem for BlockingRemoveFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle { self.inner.root() }
    fn capabilities(&self) -> embednfs::FsCapabilities { self.inner.capabilities() }
    fn limits(&self) -> embednfs::FsLimits { self.inner.limits() }
    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> { self.inner.statfs(ctx).await }
    async fn getattr(&self, ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> { self.inner.getattr(ctx, handle).await }
    async fn access(&self, ctx: &RequestContext, handle: &Self::Handle, requested: AccessMask) -> FsResult<AccessMask> { self.inner.access(ctx, handle, requested).await }
    async fn lookup(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<Self::Handle> { self.inner.lookup(ctx, parent, name).await }
    async fn parent(&self, ctx: &RequestContext, dir: &Self::Handle) -> FsResult<Option<Self::Handle>> { self.inner.parent(ctx, dir).await }
    async fn readdir(&self, ctx: &RequestContext, dir: &Self::Handle, cookie: u64, max_entries: u32, with_attrs: bool) -> FsResult<DirPage<Self::Handle>> { self.inner.readdir(ctx, dir, cookie, max_entries, with_attrs).await }
    async fn read(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, count: u32) -> FsResult<ReadResult> { self.inner.read(ctx, handle, offset, count).await }
    async fn write(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, data: Bytes) -> FsResult<WriteResult> { self.inner.write(ctx, handle, offset, data).await }
    async fn create(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str, req: CreateRequest) -> FsResult<CreateResult<Self::Handle>> { self.inner.create(ctx, parent, name, req).await }
    async fn remove(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<()> {
        self.entered.notify_waiters();
        self.release.notified().await;
        self.inner.remove(ctx, parent, name).await
    }
    async fn rename(&self, ctx: &RequestContext, from_dir: &Self::Handle, from_name: &str, to_dir: &Self::Handle, to_name: &str) -> FsResult<()> { self.inner.rename(ctx, from_dir, from_name, to_dir, to_name).await }
    async fn setattr(&self, ctx: &RequestContext, handle: &Self::Handle, attrs: &SetAttrs) -> FsResult<Attrs> { self.inner.setattr(ctx, handle, attrs).await }
    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> { self.inner.symlinks() }
    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> { self.inner.hard_links() }
    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> { self.inner.xattrs() }
    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> { self.inner.commit_support() }
}

#[async_trait::async_trait]
impl FileSystem for CountingNamedAttrFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle { self.inner.root() }
    fn capabilities(&self) -> embednfs::FsCapabilities { self.inner.capabilities() }
    fn limits(&self) -> embednfs::FsLimits { self.inner.limits() }
    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> { self.inner.statfs(ctx).await }
    async fn getattr(&self, ctx: &RequestContext, handle: &Self::Handle) -> FsResult<Attrs> { self.inner.getattr(ctx, handle).await }
    async fn access(&self, ctx: &RequestContext, handle: &Self::Handle, requested: AccessMask) -> FsResult<AccessMask> { self.inner.access(ctx, handle, requested).await }
    async fn lookup(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<Self::Handle> { self.inner.lookup(ctx, parent, name).await }
    async fn parent(&self, ctx: &RequestContext, dir: &Self::Handle) -> FsResult<Option<Self::Handle>> { self.inner.parent(ctx, dir).await }
    async fn readdir(&self, ctx: &RequestContext, dir: &Self::Handle, cookie: u64, max_entries: u32, with_attrs: bool) -> FsResult<DirPage<Self::Handle>> { self.inner.readdir(ctx, dir, cookie, max_entries, with_attrs).await }
    async fn read(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, count: u32) -> FsResult<ReadResult> { self.inner.read(ctx, handle, offset, count).await }
    async fn write(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, data: Bytes) -> FsResult<WriteResult> { self.inner.write(ctx, handle, offset, data).await }
    async fn create(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str, req: CreateRequest) -> FsResult<CreateResult<Self::Handle>> { self.inner.create(ctx, parent, name, req).await }
    async fn remove(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<()> { self.inner.remove(ctx, parent, name).await }
    async fn rename(&self, ctx: &RequestContext, from_dir: &Self::Handle, from_name: &str, to_dir: &Self::Handle, to_name: &str) -> FsResult<()> { self.inner.rename(ctx, from_dir, from_name, to_dir, to_name).await }
    async fn setattr(&self, ctx: &RequestContext, handle: &Self::Handle, attrs: &SetAttrs) -> FsResult<Attrs> { self.inner.setattr(ctx, handle, attrs).await }
    fn symlinks(&self) -> Option<&dyn Symlinks<Self::Handle>> { self.inner.symlinks() }
    fn hard_links(&self) -> Option<&dyn HardLinks<Self::Handle>> { self.inner.hard_links() }
    fn xattrs(&self) -> Option<&dyn Xattrs<Self::Handle>> { Some(self) }
    fn commit_support(&self) -> Option<&dyn CommitSupport<Self::Handle>> { self.inner.commit_support() }
}

#[async_trait::async_trait]
impl Xattrs<u64> for CountingNamedAttrFs {
    async fn list_xattrs(&self, ctx: &RequestContext, id: &u64) -> FsResult<Vec<String>> {
        self.list_count.fetch_add(1, Ordering::Relaxed);
        self.inner.list_xattrs(ctx, id).await
    }
    async fn get_xattr(&self, ctx: &RequestContext, id: &u64, name: &str) -> FsResult<Bytes> { self.inner.get_xattr(ctx, id, name).await }
    async fn set_xattr(&self, ctx: &RequestContext, id: &u64, name: &str, value: Bytes, mode: XattrSetMode) -> FsResult<()> { self.inner.set_xattr(ctx, id, name, value, mode).await }
    async fn remove_xattr(&self, ctx: &RequestContext, id: &u64, name: &str) -> FsResult<()> { self.inner.remove_xattr(ctx, id, name).await }
}

#[async_trait::async_trait]
impl FileSystem for FailPostMutationRootStatFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle { self.inner.root() }
    fn capabilities(&self) -> embednfs::FsCapabilities { self.inner.capabilities() }
    fn limits(&self) -> embednfs::FsLimits { self.inner.limits() }
    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> { self.inner.statfs(ctx).await }
    async fn getattr(&self, ctx: &RequestContext, id: &u64) -> FsResult<Attrs> {
        if *id == self.inner.root() {
            let call = self.root_stat_calls.fetch_add(1, Ordering::Relaxed);
            if call >= self.root_stat_limit {
                return Err(FsError::Io);
            }
        }
        self.inner.getattr(ctx, id).await
    }
    async fn access(&self, ctx: &RequestContext, handle: &Self::Handle, requested: AccessMask) -> FsResult<AccessMask> { self.inner.access(ctx, handle, requested).await }
    async fn lookup(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<Self::Handle> { self.inner.lookup(ctx, parent, name).await }
    async fn parent(&self, ctx: &RequestContext, dir: &Self::Handle) -> FsResult<Option<Self::Handle>> { self.inner.parent(ctx, dir).await }
    async fn readdir(&self, ctx: &RequestContext, dir: &Self::Handle, cookie: u64, max_entries: u32, with_attrs: bool) -> FsResult<DirPage<Self::Handle>> { self.inner.readdir(ctx, dir, cookie, max_entries, with_attrs).await }
    async fn read(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, count: u32) -> FsResult<ReadResult> { self.inner.read(ctx, handle, offset, count).await }
    async fn write(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, data: Bytes) -> FsResult<WriteResult> { self.inner.write(ctx, handle, offset, data).await }
    async fn create(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str, req: CreateRequest) -> FsResult<CreateResult<Self::Handle>> { self.inner.create(ctx, parent, name, req).await }
    async fn remove(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<()> { self.inner.remove(ctx, parent, name).await }
    async fn rename(&self, ctx: &RequestContext, from_dir: &Self::Handle, from_name: &str, to_dir: &Self::Handle, to_name: &str) -> FsResult<()> { self.inner.rename(ctx, from_dir, from_name, to_dir, to_name).await }
    async fn setattr(&self, ctx: &RequestContext, handle: &Self::Handle, attrs: &SetAttrs) -> FsResult<Attrs> { self.inner.setattr(ctx, handle, attrs).await }
}

#[async_trait::async_trait]
impl FileSystem for FailFirstRootStatFs {
    type Handle = u64;

    fn root(&self) -> Self::Handle { self.inner.root() }
    fn capabilities(&self) -> embednfs::FsCapabilities { self.inner.capabilities() }
    fn limits(&self) -> embednfs::FsLimits { self.inner.limits() }
    async fn statfs(&self, ctx: &RequestContext) -> FsResult<FsStats> { self.inner.statfs(ctx).await }
    async fn getattr(&self, ctx: &RequestContext, id: &u64) -> FsResult<Attrs> {
        if *id == self.inner.root() && self.root_stat_calls.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(FsError::Io);
        }
        self.inner.getattr(ctx, id).await
    }
    async fn access(&self, ctx: &RequestContext, handle: &Self::Handle, requested: AccessMask) -> FsResult<AccessMask> { self.inner.access(ctx, handle, requested).await }
    async fn lookup(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<Self::Handle> { self.inner.lookup(ctx, parent, name).await }
    async fn parent(&self, ctx: &RequestContext, dir: &Self::Handle) -> FsResult<Option<Self::Handle>> { self.inner.parent(ctx, dir).await }
    async fn readdir(&self, ctx: &RequestContext, dir: &Self::Handle, cookie: u64, max_entries: u32, with_attrs: bool) -> FsResult<DirPage<Self::Handle>> { self.inner.readdir(ctx, dir, cookie, max_entries, with_attrs).await }
    async fn read(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, count: u32) -> FsResult<ReadResult> { self.inner.read(ctx, handle, offset, count).await }
    async fn write(&self, ctx: &RequestContext, handle: &Self::Handle, offset: u64, data: Bytes) -> FsResult<WriteResult> { self.inner.write(ctx, handle, offset, data).await }
    async fn create(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str, req: CreateRequest) -> FsResult<CreateResult<Self::Handle>> { self.inner.create(ctx, parent, name, req).await }
    async fn remove(&self, ctx: &RequestContext, parent: &Self::Handle, name: &str) -> FsResult<()> { self.inner.remove(ctx, parent, name).await }
    async fn rename(&self, ctx: &RequestContext, from_dir: &Self::Handle, from_name: &str, to_dir: &Self::Handle, to_name: &str) -> FsResult<()> { self.inner.rename(ctx, from_dir, from_name, to_dir, to_name).await }
    async fn setattr(&self, ctx: &RequestContext, handle: &Self::Handle, attrs: &SetAttrs) -> FsResult<Attrs> { self.inner.setattr(ctx, handle, attrs).await }
}

use std::path::Path;

use async_trait::async_trait;
use tokio::fs;

use crate::fs::{
    DirEntry, FileSystem, FsCapabilities, FsError, FsResult, Metadata, NfsError, PathDirEntry,
    SetFileAttr,
};

use super::MemFs;

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
        let entries: Vec<DirEntry> = self.readdir_id(dir_id).await?;
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

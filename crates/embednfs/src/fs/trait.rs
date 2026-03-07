use async_trait::async_trait;
use std::path::Path;

use super::{FsCapabilities, FsError, FsResult, Metadata, PathDirEntry};

/// A simple, path-based filesystem API.
#[async_trait]
pub trait FileSystem: Send + Sync + 'static {
    /// Filesystem capabilities and synthetic POSIX defaults.
    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities::default()
    }

    /// Fetch metadata for an absolute path.
    async fn metadata(&self, path: &str) -> FsResult<Metadata>;

    /// List all immediate children of a directory.
    async fn list(&self, path: &str) -> FsResult<Vec<PathDirEntry>>;

    /// Read file data from the given offset.
    async fn read(&self, path: &str, offset: u64, count: u32) -> FsResult<Vec<u8>>;

    /// Create an empty regular file.
    async fn create_file(&self, path: &str) -> FsResult<()>;

    /// Create a directory.
    async fn create_dir(&self, path: &str) -> FsResult<()>;

    /// Create a symbolic link.
    async fn create_symlink(&self, path: &str, target: &str) -> FsResult<()>;

    /// Read a symbolic link target.
    async fn read_symlink(&self, path: &str) -> FsResult<String>;

    /// Remove a file or empty directory.
    async fn remove(&self, path: &str, expected_revision: Option<&str>) -> FsResult<()>;

    /// Rename or move an entry.
    async fn rename(&self, from: &str, to: &str, expected_revision: Option<&str>) -> FsResult<()>;

    /// Replace a file with the given full contents.
    async fn replace_file(
        &self,
        _path: &str,
        _local_path: &Path,
        _expected_revision: Option<&str>,
    ) -> FsResult<()> {
        Err(FsError::Notsupp)
    }

    /// Write bytes directly to a file at the given offset.
    async fn write_file(&self, _path: &str, _offset: u64, _data: &[u8]) -> FsResult<u32> {
        Err(FsError::Notsupp)
    }

    /// Adjust a file's length.
    async fn set_len(&self, _path: &str, _size: u64) -> FsResult<()> {
        Err(FsError::Notsupp)
    }

    /// Flush file contents to stable storage when supported.
    async fn sync(&self, _path: &str) -> FsResult<()> {
        Ok(())
    }
}

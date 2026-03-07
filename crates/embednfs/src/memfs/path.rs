use crate::fs::{FileId, NfsError, NfsResult};

use super::{InodeData, MemFs};

impl MemFs {
    pub(super) fn split_components(path: &str) -> NfsResult<Vec<&str>> {
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

    pub(super) fn split_parent(path: &str) -> NfsResult<(String, String)> {
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

    pub(super) async fn resolve_path(&self, path: &str) -> NfsResult<FileId> {
        let components = Self::split_components(path)?;
        let inner = self.inner.read().await;
        let mut current = 1;
        for component in components {
            let inode = inner.inodes.get(&current).ok_or(NfsError::Stale)?;
            match &inode.data {
                InodeData::Directory(entries) => {
                    current = *entries.get(component).ok_or(NfsError::Noent)?;
                }
                InodeData::File(_) | InodeData::Symlink(_) => return Err(NfsError::Notdir),
            }
        }
        Ok(current)
    }
}

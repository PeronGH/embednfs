use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::fs::{FileSystem, FsError};

use super::{NfsServer, StagedFile};

impl<F: FileSystem> NfsServer<F> {
    pub(super) async fn stage_entry(&self, path: &str) -> Option<StagedFile> {
        self.staging.lock().await.get(path).cloned()
    }

    pub(super) async fn ensure_stage(
        &self,
        path: &str,
        hydrate: bool,
    ) -> Result<PathBuf, FsError> {
        if let Some(entry) = self.stage_entry(path).await {
            return Ok(entry.local_path);
        }

        fs::create_dir_all(&self.stage_root)
            .await
            .map_err(|_| FsError::Io)?;
        let stage_id = self.next_stage_id.fetch_add(1, Ordering::Relaxed);
        let local_path = self.stage_root.join(format!("{stage_id}.stage"));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&local_path)
            .await
            .map_err(|_| FsError::Io)?;

        if hydrate {
            let chunk = self.fs.capabilities().fs_info.max_read.max(8192);
            let mut offset = 0u64;
            loop {
                let data = self.fs.read(path, offset, chunk).await?;
                if data.is_empty() {
                    break;
                }
                file.write_all(&data).await.map_err(|_| FsError::Io)?;
                offset = offset.saturating_add(data.len() as u64);
                if data.len() < chunk as usize {
                    break;
                }
            }
            file.flush().await.map_err(|_| FsError::Io)?;
        }

        self.staging.lock().await.insert(
            path.to_string(),
            StagedFile {
                local_path: local_path.clone(),
                dirty: false,
            },
        );
        Ok(local_path)
    }

    pub(super) async fn read_from_stage(
        &self,
        path: &str,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, FsError> {
        let entry = self.stage_entry(path).await.ok_or(FsError::Stale)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&entry.local_path)
            .await
            .map_err(|_| FsError::Io)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| FsError::Io)?;

        let mut buf = vec![0u8; count as usize];
        let read = file.read(&mut buf).await.map_err(|_| FsError::Io)?;
        buf.truncate(read);
        Ok(buf)
    }

    pub(super) async fn stage_len(&self, path: &str) -> Option<u64> {
        let entry = self.stage_entry(path).await?;
        let metadata = fs::metadata(&entry.local_path).await.ok()?;
        Some(metadata.len())
    }

    pub(super) async fn mark_stage_dirty(&self, path: &str, dirty: bool) -> Result<(), FsError> {
        let mut staging = self.staging.lock().await;
        let entry = staging.get_mut(path).ok_or(FsError::Stale)?;
        entry.dirty = dirty;
        Ok(())
    }

    pub(super) async fn stage_write(
        &self,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, FsError> {
        let local_path = self.ensure_stage(path, true).await?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&local_path)
            .await
            .map_err(|_| FsError::Io)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|_| FsError::Io)?;
        file.write_all(data).await.map_err(|_| FsError::Io)?;
        file.flush().await.map_err(|_| FsError::Io)?;
        self.mark_stage_dirty(path, true).await?;
        Ok(data.len() as u32)
    }

    pub(super) async fn stage_set_len(&self, path: &str, size: u64) -> Result<(), FsError> {
        let local_path = self.ensure_stage(path, size != 0).await?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&local_path)
            .await
            .map_err(|_| FsError::Io)?;
        file.set_len(size).await.map_err(|_| FsError::Io)?;
        self.mark_stage_dirty(path, true).await
    }

    pub(super) async fn commit_stage(&self, path: &str) -> Result<bool, FsError> {
        let entry = match self.stage_entry(path).await {
            Some(entry) => entry,
            None => return Ok(false),
        };
        if !entry.dirty {
            return Ok(false);
        }

        self.fs.replace_file(path, &entry.local_path, None).await?;
        self.mark_stage_dirty(path, false).await?;
        Ok(true)
    }

    pub(super) async fn drop_stage(&self, path: &str) {
        let entry = self.staging.lock().await.remove(path);
        if let Some(entry) = entry {
            let _ = fs::remove_file(entry.local_path).await;
        }
    }

    pub(super) async fn rename_stage(&self, from: &str, to: &str) {
        let mut staging = self.staging.lock().await;
        if let Some(entry) = staging.remove(from) {
            staging.insert(to.to_string(), entry);
        }
    }
}

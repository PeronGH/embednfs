use std::collections::HashMap;

use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileAttr, FileSystem, FsError};

use super::NfsServer;

/// Maps opaque filehandle tokens to paths and back.
///
/// Filehandles are 8-byte big-endian u64 IDs. The registry tracks
/// the current path for each handle, updating on rename/remove.
pub(super) struct HandleRegistry {
    fh_to_path: HashMap<u64, String>,
    path_to_fh: HashMap<String, u64>,
    next_id: u64,
}

impl HandleRegistry {
    pub fn new() -> Self {
        let mut registry = HandleRegistry {
            fh_to_path: HashMap::new(),
            path_to_fh: HashMap::new(),
            next_id: 2, // 1 is reserved for root
        };
        registry.fh_to_path.insert(1, "/".into());
        registry.path_to_fh.insert("/".into(), 1);
        registry
    }

    /// Get or create an opaque filehandle for the given path.
    pub fn get_or_create(&mut self, path: &str) -> NfsFh4 {
        let id = if let Some(&id) = self.path_to_fh.get(path) {
            id
        } else {
            let id = self.next_id;
            self.next_id += 1;
            self.fh_to_path.insert(id, path.to_string());
            self.path_to_fh.insert(path.to_string(), id);
            id
        };
        NfsFh4(id.to_be_bytes().to_vec())
    }

    /// Resolve an opaque filehandle to its current path.
    pub fn resolve(&self, fh: &NfsFh4) -> Result<String, NfsStat4> {
        let id = self.fh_to_id(fh)?;
        self.fh_to_path
            .get(&id)
            .cloned()
            .ok_or(NfsStat4::Stale)
    }

    /// Get the stable handle ID for use as fileid.
    pub fn fileid(&self, fh: &NfsFh4) -> Result<u64, NfsStat4> {
        self.fh_to_id(fh)
    }

    /// Update mappings when a file or directory is renamed.
    pub fn rename(&mut self, old: &str, new: &str) {
        // Collect all paths that start with old prefix.
        let old_prefix = if old == "/" {
            "/".to_string()
        } else {
            format!("{old}/")
        };
        let mut renames: Vec<(String, String)> = Vec::new();

        // Direct entry.
        if let Some(&id) = self.path_to_fh.get(old) {
            renames.push((old.to_string(), new.to_string()));
            let _ = id; // will be updated below
        }

        // Children (prefix match).
        for existing_path in self.path_to_fh.keys() {
            if existing_path.starts_with(&old_prefix) {
                let suffix = &existing_path[old.len()..];
                let new_path = format!("{new}{suffix}");
                renames.push((existing_path.clone(), new_path));
            }
        }

        for (old_path, new_path) in renames {
            if let Some(id) = self.path_to_fh.remove(&old_path) {
                self.fh_to_path.insert(id, new_path.clone());
                self.path_to_fh.insert(new_path, id);
            }
        }
    }

    /// Remove mappings when a file or directory is deleted.
    pub fn remove(&mut self, path: &str) {
        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };

        // Remove direct entry.
        if let Some(id) = self.path_to_fh.remove(path) {
            self.fh_to_path.remove(&id);
        }

        // Remove children.
        let children: Vec<String> = self
            .path_to_fh
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .cloned()
            .collect();
        for child_path in children {
            if let Some(id) = self.path_to_fh.remove(&child_path) {
                self.fh_to_path.remove(&id);
            }
        }
    }

    fn fh_to_id(&self, fh: &NfsFh4) -> Result<u64, NfsStat4> {
        if fh.0.len() != 8 {
            return Err(NfsStat4::Badhandle);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&fh.0);
        Ok(u64::from_be_bytes(buf))
    }
}

impl<F: FileSystem> NfsServer<F> {
    pub(super) fn resolve_fh(&self, fh: &Option<NfsFh4>) -> Result<String, NfsStat4> {
        let fh = fh.as_ref().ok_or(NfsStat4::Nofilehandle)?;
        self.handles.lock().unwrap().resolve(fh)
    }

    pub(super) fn fileid_for_fh(&self, fh: &NfsFh4) -> u64 {
        self.handles.lock().unwrap().fileid(fh).unwrap_or(0)
    }

    pub(super) async fn attr_for_path(&self, path: &str) -> Result<FileAttr, FsError> {
        let metadata = self.fs.metadata(path).await?;
        let fileid = {
            let handles = self.handles.lock().unwrap();
            handles.path_to_fh.get(path).copied()
        };
        Ok(attrs::synthesize_file_attr(
            path,
            &metadata,
            &self.fs.capabilities(),
            fileid,
        ))
    }
}

pub(super) fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }

    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => "/".into(),
        Some((parent, _)) => parent.to_string(),
    }
}

pub(super) fn join_path(dir: &str, name: &str) -> Result<String, NfsStat4> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(NfsStat4::Inval);
    }

    if dir == "/" {
        Ok(format!("/{name}"))
    } else {
        Ok(format!("{dir}/{name}"))
    }
}

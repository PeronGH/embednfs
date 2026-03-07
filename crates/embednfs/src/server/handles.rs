use embednfs_proto::*;

use crate::attrs;
use crate::fs::{FileAttr, FileSystem, FsError};

use super::NfsServer;

impl<F: FileSystem> NfsServer<F> {
    pub(super) fn resolve_fh(&self, fh: &Option<NfsFh4>) -> Result<String, NfsStat4> {
        let fh = fh.as_ref().ok_or(NfsStat4::Nofilehandle)?;
        fh_to_path(fh).ok_or(NfsStat4::Stale)
    }

    pub(super) async fn attr_for_path(&self, path: &str) -> Result<FileAttr, FsError> {
        let metadata = self.fs.metadata(path).await?;
        Ok(attrs::synthesize_file_attr(
            path,
            &metadata,
            &self.fs.capabilities(),
        ))
    }
}

pub(super) fn path_to_fh(path: &str) -> NfsFh4 {
    NfsFh4(path.as_bytes().to_vec())
}

fn fh_to_path(fh: &NfsFh4) -> Option<String> {
    let path = String::from_utf8(fh.0.clone()).ok()?;
    if !path.starts_with('/') {
        return None;
    }
    Some(path)
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

pub(super) fn synthetic_fileid(path: &str) -> u64 {
    if path == "/" {
        return 1;
    }

    let mut hash = 0xcbf29ce484222325u64;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 { 1 } else { hash }
}

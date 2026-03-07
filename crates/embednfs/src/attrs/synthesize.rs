use crate::fs::{FileAttr, FileType, FsCapabilities, Metadata};

/// Synthesize NFS-facing attributes from the high-level metadata model.
///
/// If `handle_fileid` is provided, it is used as the stable fileid.
/// Otherwise, a hash of the path is used as a fallback.
pub(crate) fn synthesize_file_attr(
    path: &str,
    metadata: &Metadata,
    caps: &FsCapabilities,
    handle_fileid: Option<u64>,
) -> FileAttr {
    let defaults = &caps.posix;
    let base_mode = match metadata.file_type {
        FileType::Regular => defaults.file_mode,
        FileType::Directory => defaults.dir_mode,
        FileType::Symlink => defaults.symlink_mode,
    };

    let mode = if metadata.file_type == FileType::Symlink {
        base_mode
    } else {
        let readonly_mode = if metadata.readonly {
            base_mode & !0o222
        } else {
            base_mode
        };
        if metadata.executable {
            readonly_mode | 0o111
        } else {
            readonly_mode & !0o111
        }
    };

    let (mtime_sec, mtime_nsec) = (
        metadata.mtime_sec.unwrap_or(0),
        metadata.mtime_nsec.unwrap_or(0),
    );
    let (ctime_sec, ctime_nsec) = (
        metadata.ctime_sec.unwrap_or(mtime_sec),
        metadata.ctime_nsec.unwrap_or(mtime_nsec),
    );
    let (crtime_sec, crtime_nsec) = (
        metadata.crtime_sec.unwrap_or(ctime_sec),
        metadata.crtime_nsec.unwrap_or(ctime_nsec),
    );

    let fileid = handle_fileid.unwrap_or_else(|| stable_path_id(path));
    let change_id = metadata
        .revision
        .as_deref()
        .and_then(|revision| revision.parse::<u64>().ok())
        .unwrap_or_else(|| {
            let mut seed = String::from(path);
            if let Some(revision) = metadata.revision.as_deref() {
                seed.push('\0');
                seed.push_str(revision);
            }
            stable_hash(seed.as_bytes())
        });

    FileAttr {
        fileid,
        file_type: metadata.file_type,
        size: metadata.size,
        used: metadata.size,
        mode,
        nlink: if metadata.file_type == FileType::Directory {
            2
        } else {
            1
        },
        uid: defaults.uid,
        gid: defaults.gid,
        owner: defaults.owner.clone(),
        owner_group: defaults.owner_group.clone(),
        atime_sec: mtime_sec,
        atime_nsec: mtime_nsec,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        crtime_sec,
        crtime_nsec,
        change_id,
        rdev_major: 0,
        rdev_minor: 0,
        archive: false,
        hidden: false,
        system: false,
    }
}

fn stable_path_id(path: &str) -> u64 {
    if path == "/" {
        1
    } else {
        stable_hash(path.as_bytes())
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 { 1 } else { hash }
}

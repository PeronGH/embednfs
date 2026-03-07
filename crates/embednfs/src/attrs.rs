use crate::fs::{FileAttr, FileType, FsInfo, SetFileAttr, SetTime};
/// NFSv4.1 file attribute encoding and decoding.
///
/// Handles the bitmap-driven attribute encoding used by GETATTR/SETATTR.
use bytes::BytesMut;
use embednfs_proto::xdr::*;
use embednfs_proto::*;

/// Encode file attributes according to the requested bitmap.
pub fn encode_fattr4(attr: &FileAttr, request: &Bitmap4, fh: &NfsFh4, fs_info: &FsInfo) -> Fattr4 {
    let mut result_bitmap = Bitmap4::new();
    let mut vals = BytesMut::with_capacity(256);

    // Word 0 attributes (bits 0-31)

    // FATTR4_SUPPORTED_ATTRS (0) - mandatory
    if request.is_set(FATTR4_SUPPORTED_ATTRS) {
        result_bitmap.set(FATTR4_SUPPORTED_ATTRS);
        let mut supported = Bitmap4::new();
        for bit in &[
            FATTR4_SUPPORTED_ATTRS,
            FATTR4_TYPE,
            FATTR4_FH_EXPIRE_TYPE,
            FATTR4_CHANGE,
            FATTR4_SIZE,
            FATTR4_LINK_SUPPORT,
            FATTR4_SYMLINK_SUPPORT,
            FATTR4_NAMED_ATTR,
            FATTR4_FSID,
            FATTR4_UNIQUE_HANDLES,
            FATTR4_LEASE_TIME,
            FATTR4_RDATTR_ERROR,
            FATTR4_FILEHANDLE,
            FATTR4_ACLSUPPORT,
            FATTR4_ARCHIVE,
            FATTR4_CANSETTIME,
            FATTR4_CASE_INSENSITIVE,
            FATTR4_CASE_PRESERVING,
            FATTR4_CHOWN_RESTRICTED,
            FATTR4_FILEID,
            FATTR4_FILES_AVAIL,
            FATTR4_FILES_FREE,
            FATTR4_FILES_TOTAL,
            FATTR4_HIDDEN,
            FATTR4_HOMOGENEOUS,
            FATTR4_MAXFILESIZE,
            FATTR4_MAXLINK,
            FATTR4_MAXNAME,
            FATTR4_MAXREAD,
            FATTR4_MAXWRITE,
            FATTR4_MODE,
            FATTR4_NO_TRUNC,
            FATTR4_NUMLINKS,
            FATTR4_OWNER,
            FATTR4_OWNER_GROUP,
            FATTR4_RAWDEV,
            FATTR4_SPACE_AVAIL,
            FATTR4_SPACE_FREE,
            FATTR4_SPACE_TOTAL,
            FATTR4_SPACE_USED,
            FATTR4_SYSTEM,
            FATTR4_TIME_ACCESS,
            FATTR4_TIME_ACCESS_SET,
            FATTR4_TIME_BACKUP,
            FATTR4_TIME_CREATE,
            FATTR4_TIME_DELTA,
            FATTR4_TIME_METADATA,
            FATTR4_TIME_MODIFY,
            FATTR4_TIME_MODIFY_SET,
            FATTR4_MOUNTED_ON_FILEID,
            FATTR4_SUPPATTR_EXCLCREAT,
        ] {
            supported.set(*bit);
        }
        supported.encode(&mut vals);
    }

    // FATTR4_TYPE (1) - mandatory
    if request.is_set(FATTR4_TYPE) {
        result_bitmap.set(FATTR4_TYPE);
        let nfs_type = match attr.file_type {
            FileType::Regular => NfsFtype4::Reg,
            FileType::Directory => NfsFtype4::Dir,
            FileType::Symlink => NfsFtype4::Lnk,
            FileType::BlockDevice => NfsFtype4::Blk,
            FileType::CharDevice => NfsFtype4::Chr,
            FileType::Socket => NfsFtype4::Sock,
            FileType::Fifo => NfsFtype4::Fifo,
        };
        nfs_type.encode(&mut vals);
    }

    // FATTR4_FH_EXPIRE_TYPE (2) - mandatory
    if request.is_set(FATTR4_FH_EXPIRE_TYPE) {
        result_bitmap.set(FATTR4_FH_EXPIRE_TYPE);
        // FH4_PERSISTENT = 0x00
        0u32.encode(&mut vals);
    }

    // FATTR4_CHANGE (3) - mandatory
    if request.is_set(FATTR4_CHANGE) {
        result_bitmap.set(FATTR4_CHANGE);
        attr.change_id.encode(&mut vals);
    }

    // FATTR4_SIZE (4) - mandatory
    if request.is_set(FATTR4_SIZE) {
        result_bitmap.set(FATTR4_SIZE);
        attr.size.encode(&mut vals);
    }

    // FATTR4_LINK_SUPPORT (5)
    if request.is_set(FATTR4_LINK_SUPPORT) {
        result_bitmap.set(FATTR4_LINK_SUPPORT);
        true.encode(&mut vals);
    }

    // FATTR4_SYMLINK_SUPPORT (6)
    if request.is_set(FATTR4_SYMLINK_SUPPORT) {
        result_bitmap.set(FATTR4_SYMLINK_SUPPORT);
        true.encode(&mut vals);
    }

    // FATTR4_NAMED_ATTR (7)
    if request.is_set(FATTR4_NAMED_ATTR) {
        result_bitmap.set(FATTR4_NAMED_ATTR);
        false.encode(&mut vals);
    }

    // FATTR4_FSID (8) - mandatory
    if request.is_set(FATTR4_FSID) {
        result_bitmap.set(FATTR4_FSID);
        // Use a non-zero fsid; macOS uses this to identify the filesystem
        let fsid = Fsid4 { major: 1, minor: 1 };
        fsid.encode(&mut vals);
    }

    // FATTR4_UNIQUE_HANDLES (9)
    if request.is_set(FATTR4_UNIQUE_HANDLES) {
        result_bitmap.set(FATTR4_UNIQUE_HANDLES);
        true.encode(&mut vals);
    }

    // FATTR4_LEASE_TIME (10) - mandatory
    if request.is_set(FATTR4_LEASE_TIME) {
        result_bitmap.set(FATTR4_LEASE_TIME);
        90u32.encode(&mut vals); // 90 second lease
    }

    // FATTR4_RDATTR_ERROR (11) - mandatory
    if request.is_set(FATTR4_RDATTR_ERROR) {
        result_bitmap.set(FATTR4_RDATTR_ERROR);
        (NfsStat4::Ok as u32).encode(&mut vals);
    }

    // FATTR4_ACL (12) - skip
    // FATTR4_ACLSUPPORT (13)
    if request.is_set(FATTR4_ACLSUPPORT) {
        result_bitmap.set(FATTR4_ACLSUPPORT);
        0u32.encode(&mut vals); // no ACL support
    }

    // FATTR4_ARCHIVE (14) - macOS SF_ARCHIVED flag
    if request.is_set(FATTR4_ARCHIVE) {
        result_bitmap.set(FATTR4_ARCHIVE);
        attr.archive.encode(&mut vals);
    }

    // FATTR4_CANSETTIME (15)
    if request.is_set(FATTR4_CANSETTIME) {
        result_bitmap.set(FATTR4_CANSETTIME);
        true.encode(&mut vals);
    }

    // FATTR4_CASE_INSENSITIVE (16)
    if request.is_set(FATTR4_CASE_INSENSITIVE) {
        result_bitmap.set(FATTR4_CASE_INSENSITIVE);
        false.encode(&mut vals);
    }

    // FATTR4_CASE_PRESERVING (17)
    if request.is_set(FATTR4_CASE_PRESERVING) {
        result_bitmap.set(FATTR4_CASE_PRESERVING);
        true.encode(&mut vals);
    }

    // FATTR4_CHOWN_RESTRICTED (18)
    if request.is_set(FATTR4_CHOWN_RESTRICTED) {
        result_bitmap.set(FATTR4_CHOWN_RESTRICTED);
        true.encode(&mut vals);
    }

    // FATTR4_FILEHANDLE (19)
    if request.is_set(FATTR4_FILEHANDLE) {
        result_bitmap.set(FATTR4_FILEHANDLE);
        fh.encode(&mut vals);
    }

    // FATTR4_FILEID (20)
    if request.is_set(FATTR4_FILEID) {
        result_bitmap.set(FATTR4_FILEID);
        attr.fileid.encode(&mut vals);
    }

    // FATTR4_FILES_AVAIL (21)
    if request.is_set(FATTR4_FILES_AVAIL) {
        result_bitmap.set(FATTR4_FILES_AVAIL);
        fs_info.avail_files.encode(&mut vals);
    }

    // FATTR4_FILES_FREE (22)
    if request.is_set(FATTR4_FILES_FREE) {
        result_bitmap.set(FATTR4_FILES_FREE);
        fs_info.free_files.encode(&mut vals);
    }

    // FATTR4_FILES_TOTAL (23)
    if request.is_set(FATTR4_FILES_TOTAL) {
        result_bitmap.set(FATTR4_FILES_TOTAL);
        fs_info.total_files.encode(&mut vals);
    }

    // FATTR4_HIDDEN (25) - macOS UF_HIDDEN flag
    if request.is_set(FATTR4_HIDDEN) {
        result_bitmap.set(FATTR4_HIDDEN);
        attr.hidden.encode(&mut vals);
    }

    // FATTR4_HOMOGENEOUS (26)
    if request.is_set(FATTR4_HOMOGENEOUS) {
        result_bitmap.set(FATTR4_HOMOGENEOUS);
        true.encode(&mut vals);
    }

    // FATTR4_MAXFILESIZE (27)
    if request.is_set(FATTR4_MAXFILESIZE) {
        result_bitmap.set(FATTR4_MAXFILESIZE);
        fs_info.max_file_size.encode(&mut vals);
    }

    // FATTR4_MAXLINK (28)
    if request.is_set(FATTR4_MAXLINK) {
        result_bitmap.set(FATTR4_MAXLINK);
        255u32.encode(&mut vals);
    }

    // FATTR4_MAXNAME (29)
    if request.is_set(FATTR4_MAXNAME) {
        result_bitmap.set(FATTR4_MAXNAME);
        fs_info.max_name.encode(&mut vals);
    }

    // FATTR4_MAXREAD (30)
    if request.is_set(FATTR4_MAXREAD) {
        result_bitmap.set(FATTR4_MAXREAD);
        (fs_info.max_read as u64).encode(&mut vals);
    }

    // FATTR4_MAXWRITE (31)
    if request.is_set(FATTR4_MAXWRITE) {
        result_bitmap.set(FATTR4_MAXWRITE);
        (fs_info.max_write as u64).encode(&mut vals);
    }

    // Word 1 attributes (bits 32-63)

    // FATTR4_MODE (33)
    if request.is_set(FATTR4_MODE) {
        result_bitmap.set(FATTR4_MODE);
        attr.mode.encode(&mut vals);
    }

    // FATTR4_NO_TRUNC (34)
    if request.is_set(FATTR4_NO_TRUNC) {
        result_bitmap.set(FATTR4_NO_TRUNC);
        true.encode(&mut vals);
    }

    // FATTR4_NUMLINKS (35)
    if request.is_set(FATTR4_NUMLINKS) {
        result_bitmap.set(FATTR4_NUMLINKS);
        attr.nlink.encode(&mut vals);
    }

    // FATTR4_OWNER (36)
    if request.is_set(FATTR4_OWNER) {
        result_bitmap.set(FATTR4_OWNER);
        attr.owner.encode(&mut vals);
    }

    // FATTR4_OWNER_GROUP (37)
    if request.is_set(FATTR4_OWNER_GROUP) {
        result_bitmap.set(FATTR4_OWNER_GROUP);
        attr.owner_group.encode(&mut vals);
    }

    // FATTR4_RAWDEV (41)
    if request.is_set(FATTR4_RAWDEV) {
        result_bitmap.set(FATTR4_RAWDEV);
        let spec = Specdata4 {
            specdata1: attr.rdev_major,
            specdata2: attr.rdev_minor,
        };
        spec.encode(&mut vals);
    }

    // FATTR4_SPACE_AVAIL (42)
    if request.is_set(FATTR4_SPACE_AVAIL) {
        result_bitmap.set(FATTR4_SPACE_AVAIL);
        fs_info.avail_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_FREE (43)
    if request.is_set(FATTR4_SPACE_FREE) {
        result_bitmap.set(FATTR4_SPACE_FREE);
        fs_info.free_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_TOTAL (44)
    if request.is_set(FATTR4_SPACE_TOTAL) {
        result_bitmap.set(FATTR4_SPACE_TOTAL);
        fs_info.total_bytes.encode(&mut vals);
    }

    // FATTR4_SPACE_USED (45)
    if request.is_set(FATTR4_SPACE_USED) {
        result_bitmap.set(FATTR4_SPACE_USED);
        attr.used.encode(&mut vals);
    }

    // FATTR4_SYSTEM (46) - macOS system flag
    if request.is_set(FATTR4_SYSTEM) {
        result_bitmap.set(FATTR4_SYSTEM);
        attr.system.encode(&mut vals);
    }

    // FATTR4_TIME_ACCESS (47)
    if request.is_set(FATTR4_TIME_ACCESS) {
        result_bitmap.set(FATTR4_TIME_ACCESS);
        let t = NfsTime4 {
            seconds: attr.atime_sec,
            nseconds: attr.atime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_BACKUP (49) - same as creation time
    if request.is_set(FATTR4_TIME_BACKUP) {
        result_bitmap.set(FATTR4_TIME_BACKUP);
        let t = NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_CREATE (50) - birth/creation time (macOS uses this)
    if request.is_set(FATTR4_TIME_CREATE) {
        result_bitmap.set(FATTR4_TIME_CREATE);
        let t = NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_DELTA (51)
    if request.is_set(FATTR4_TIME_DELTA) {
        result_bitmap.set(FATTR4_TIME_DELTA);
        let t = NfsTime4 {
            seconds: 0,
            nseconds: 1000000,
        }; // 1ms
        t.encode(&mut vals);
    }

    // FATTR4_TIME_METADATA (52)
    if request.is_set(FATTR4_TIME_METADATA) {
        result_bitmap.set(FATTR4_TIME_METADATA);
        let t = NfsTime4 {
            seconds: attr.ctime_sec,
            nseconds: attr.ctime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_TIME_MODIFY (53)
    if request.is_set(FATTR4_TIME_MODIFY) {
        result_bitmap.set(FATTR4_TIME_MODIFY);
        let t = NfsTime4 {
            seconds: attr.mtime_sec,
            nseconds: attr.mtime_nsec,
        };
        t.encode(&mut vals);
    }

    // FATTR4_MOUNTED_ON_FILEID (55)
    if request.is_set(FATTR4_MOUNTED_ON_FILEID) {
        result_bitmap.set(FATTR4_MOUNTED_ON_FILEID);
        attr.fileid.encode(&mut vals);
    }

    // Word 2 attributes (bits 64-95)

    // FATTR4_SUPPATTR_EXCLCREAT (75)
    if request.is_set(FATTR4_SUPPATTR_EXCLCREAT) {
        result_bitmap.set(FATTR4_SUPPATTR_EXCLCREAT);
        // We support setting mode, size, etc. on exclusive create
        let mut excl = Bitmap4::new();
        excl.set(FATTR4_SIZE);
        excl.set(FATTR4_MODE);
        excl.encode(&mut vals);
    }

    Fattr4 {
        attrmask: result_bitmap,
        attr_vals: vals.to_vec(),
    }
}

/// Decode setattr attributes from an Fattr4.
pub fn decode_setattr(fattr: &Fattr4) -> SetFileAttr {
    let mut result = SetFileAttr::default();
    let mut src = bytes::Bytes::from(fattr.attr_vals.clone());

    // Attributes must be decoded in bitmap order
    if fattr.attrmask.is_set(FATTR4_SIZE) {
        if let Ok(size) = u64::decode(&mut src) {
            result.size = Some(size);
        }
    }

    // ARCHIVE (14) - macOS sends this; consume but store as flag
    if fattr.attrmask.is_set(FATTR4_ARCHIVE) {
        let _ = bool::decode(&mut src);
    }

    // HIDDEN (25) - macOS sends this
    if fattr.attrmask.is_set(FATTR4_HIDDEN) {
        let _ = bool::decode(&mut src);
    }

    if fattr.attrmask.is_set(FATTR4_MODE) {
        if let Ok(mode) = u32::decode(&mut src) {
            result.mode = Some(mode);
        }
    }

    if fattr.attrmask.is_set(FATTR4_OWNER) {
        if let Ok(owner_str) = String::decode(&mut src) {
            // Parse numeric uid or "uid@domain" format
            let uid_str = owner_str.split('@').next().unwrap_or(&owner_str);
            if let Ok(uid) = uid_str.parse::<u32>() {
                result.uid = Some(uid);
            }
        }
    }

    if fattr.attrmask.is_set(FATTR4_OWNER_GROUP) {
        if let Ok(group_str) = String::decode(&mut src) {
            let gid_str = group_str.split('@').next().unwrap_or(&group_str);
            if let Ok(gid) = gid_str.parse::<u32>() {
                result.gid = Some(gid);
            }
        }
    }

    // SYSTEM (46) - macOS sends this
    if fattr.attrmask.is_set(FATTR4_SYSTEM) {
        let _ = bool::decode(&mut src);
    }

    if fattr.attrmask.is_set(FATTR4_TIME_ACCESS_SET) {
        if let Ok(how) = u32::decode(&mut src) {
            match how {
                0 => result.atime = Some(SetTime::ServerTime),
                1 => {
                    if let Ok(t) = NfsTime4::decode(&mut src) {
                        result.atime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
                    }
                }
                _ => {}
            }
        }
    }

    // TIME_BACKUP (49) - macOS sends this (same format as time_create)
    if fattr.attrmask.is_set(FATTR4_TIME_BACKUP) {
        if let Ok(t) = NfsTime4::decode(&mut src) {
            result.crtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
        }
    }

    // TIME_CREATE (50) - macOS sends this as birth/creation time
    if fattr.attrmask.is_set(FATTR4_TIME_CREATE) {
        if let Ok(t) = NfsTime4::decode(&mut src) {
            result.crtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
        }
    }

    if fattr.attrmask.is_set(FATTR4_TIME_MODIFY_SET) {
        if let Ok(how) = u32::decode(&mut src) {
            match how {
                0 => result.mtime = Some(SetTime::ServerTime),
                1 => {
                    if let Ok(t) = NfsTime4::decode(&mut src) {
                        result.mtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
                    }
                }
                _ => {}
            }
        }
    }

    result
}

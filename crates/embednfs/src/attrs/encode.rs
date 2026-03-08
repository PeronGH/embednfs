use bytes::BytesMut;

use embednfs_proto::xdr::XdrEncode;
use embednfs_proto::*;

use crate::fs::{FileAttr, FileType, FsInfo};

/// Encode file attributes according to the requested bitmap.
pub(crate) fn encode_fattr4(
    attr: &FileAttr,
    request: &Bitmap4,
    fh: &NfsFh4,
    fs_info: &FsInfo,
) -> Fattr4 {
    let mut result_bitmap = Bitmap4::new();
    let mut vals = BytesMut::with_capacity(256);

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

    if request.is_set(FATTR4_TYPE) {
        result_bitmap.set(FATTR4_TYPE);
        let nfs_type = match attr.file_type {
            FileType::Regular => NfsFtype4::Reg,
            FileType::Directory => NfsFtype4::Dir,
            FileType::Symlink => NfsFtype4::Lnk,
        };
        nfs_type.encode(&mut vals);
    }

    if request.is_set(FATTR4_FH_EXPIRE_TYPE) {
        result_bitmap.set(FATTR4_FH_EXPIRE_TYPE);
        0u32.encode(&mut vals);
    }

    if request.is_set(FATTR4_CHANGE) {
        result_bitmap.set(FATTR4_CHANGE);
        attr.change_id.encode(&mut vals);
    }

    if request.is_set(FATTR4_SIZE) {
        result_bitmap.set(FATTR4_SIZE);
        attr.size.encode(&mut vals);
    }

    if request.is_set(FATTR4_LINK_SUPPORT) {
        result_bitmap.set(FATTR4_LINK_SUPPORT);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_SYMLINK_SUPPORT) {
        result_bitmap.set(FATTR4_SYMLINK_SUPPORT);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_NAMED_ATTR) {
        result_bitmap.set(FATTR4_NAMED_ATTR);
        false.encode(&mut vals);
    }

    if request.is_set(FATTR4_FSID) {
        result_bitmap.set(FATTR4_FSID);
        Fsid4 { major: 1, minor: 1 }.encode(&mut vals);
    }

    if request.is_set(FATTR4_UNIQUE_HANDLES) {
        result_bitmap.set(FATTR4_UNIQUE_HANDLES);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_LEASE_TIME) {
        result_bitmap.set(FATTR4_LEASE_TIME);
        90u32.encode(&mut vals);
    }

    if request.is_set(FATTR4_RDATTR_ERROR) {
        result_bitmap.set(FATTR4_RDATTR_ERROR);
        (NfsStat4::Ok as u32).encode(&mut vals);
    }

    if request.is_set(FATTR4_ACLSUPPORT) {
        result_bitmap.set(FATTR4_ACLSUPPORT);
        0u32.encode(&mut vals);
    }

    if request.is_set(FATTR4_ARCHIVE) {
        result_bitmap.set(FATTR4_ARCHIVE);
        attr.archive.encode(&mut vals);
    }

    if request.is_set(FATTR4_CANSETTIME) {
        result_bitmap.set(FATTR4_CANSETTIME);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_CASE_INSENSITIVE) {
        result_bitmap.set(FATTR4_CASE_INSENSITIVE);
        false.encode(&mut vals);
    }

    if request.is_set(FATTR4_CASE_PRESERVING) {
        result_bitmap.set(FATTR4_CASE_PRESERVING);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_CHOWN_RESTRICTED) {
        result_bitmap.set(FATTR4_CHOWN_RESTRICTED);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_FILEHANDLE) {
        result_bitmap.set(FATTR4_FILEHANDLE);
        fh.encode(&mut vals);
    }

    if request.is_set(FATTR4_FILEID) {
        result_bitmap.set(FATTR4_FILEID);
        attr.fileid.encode(&mut vals);
    }

    if request.is_set(FATTR4_FILES_AVAIL) {
        result_bitmap.set(FATTR4_FILES_AVAIL);
        fs_info.avail_files.encode(&mut vals);
    }

    if request.is_set(FATTR4_FILES_FREE) {
        result_bitmap.set(FATTR4_FILES_FREE);
        fs_info.free_files.encode(&mut vals);
    }

    if request.is_set(FATTR4_FILES_TOTAL) {
        result_bitmap.set(FATTR4_FILES_TOTAL);
        fs_info.total_files.encode(&mut vals);
    }

    if request.is_set(FATTR4_HIDDEN) {
        result_bitmap.set(FATTR4_HIDDEN);
        attr.hidden.encode(&mut vals);
    }

    if request.is_set(FATTR4_HOMOGENEOUS) {
        result_bitmap.set(FATTR4_HOMOGENEOUS);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_MAXFILESIZE) {
        result_bitmap.set(FATTR4_MAXFILESIZE);
        fs_info.max_file_size.encode(&mut vals);
    }

    if request.is_set(FATTR4_MAXLINK) {
        result_bitmap.set(FATTR4_MAXLINK);
        255u32.encode(&mut vals);
    }

    if request.is_set(FATTR4_MAXNAME) {
        result_bitmap.set(FATTR4_MAXNAME);
        fs_info.max_name.encode(&mut vals);
    }

    if request.is_set(FATTR4_MAXREAD) {
        result_bitmap.set(FATTR4_MAXREAD);
        (fs_info.max_read as u64).encode(&mut vals);
    }

    if request.is_set(FATTR4_MAXWRITE) {
        result_bitmap.set(FATTR4_MAXWRITE);
        (fs_info.max_write as u64).encode(&mut vals);
    }

    if request.is_set(FATTR4_MODE) {
        result_bitmap.set(FATTR4_MODE);
        (attr.mode & 0o7777).encode(&mut vals);
    }

    if request.is_set(FATTR4_NO_TRUNC) {
        result_bitmap.set(FATTR4_NO_TRUNC);
        true.encode(&mut vals);
    }

    if request.is_set(FATTR4_NUMLINKS) {
        result_bitmap.set(FATTR4_NUMLINKS);
        attr.nlink.encode(&mut vals);
    }

    if request.is_set(FATTR4_OWNER) {
        result_bitmap.set(FATTR4_OWNER);
        attr.owner.encode(&mut vals);
    }

    if request.is_set(FATTR4_OWNER_GROUP) {
        result_bitmap.set(FATTR4_OWNER_GROUP);
        attr.owner_group.encode(&mut vals);
    }

    if request.is_set(FATTR4_RAWDEV) {
        result_bitmap.set(FATTR4_RAWDEV);
        Specdata4 {
            specdata1: attr.rdev_major,
            specdata2: attr.rdev_minor,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_SPACE_AVAIL) {
        result_bitmap.set(FATTR4_SPACE_AVAIL);
        fs_info.avail_bytes.encode(&mut vals);
    }

    if request.is_set(FATTR4_SPACE_FREE) {
        result_bitmap.set(FATTR4_SPACE_FREE);
        fs_info.free_bytes.encode(&mut vals);
    }

    if request.is_set(FATTR4_SPACE_TOTAL) {
        result_bitmap.set(FATTR4_SPACE_TOTAL);
        fs_info.total_bytes.encode(&mut vals);
    }

    if request.is_set(FATTR4_SPACE_USED) {
        result_bitmap.set(FATTR4_SPACE_USED);
        attr.used.encode(&mut vals);
    }

    if request.is_set(FATTR4_SYSTEM) {
        result_bitmap.set(FATTR4_SYSTEM);
        attr.system.encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_ACCESS) {
        result_bitmap.set(FATTR4_TIME_ACCESS);
        NfsTime4 {
            seconds: attr.atime_sec,
            nseconds: attr.atime_nsec,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_BACKUP) {
        result_bitmap.set(FATTR4_TIME_BACKUP);
        NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_CREATE) {
        result_bitmap.set(FATTR4_TIME_CREATE);
        NfsTime4 {
            seconds: attr.crtime_sec,
            nseconds: attr.crtime_nsec,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_DELTA) {
        result_bitmap.set(FATTR4_TIME_DELTA);
        NfsTime4 {
            seconds: 0,
            nseconds: 1_000_000,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_METADATA) {
        result_bitmap.set(FATTR4_TIME_METADATA);
        NfsTime4 {
            seconds: attr.ctime_sec,
            nseconds: attr.ctime_nsec,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_TIME_MODIFY) {
        result_bitmap.set(FATTR4_TIME_MODIFY);
        NfsTime4 {
            seconds: attr.mtime_sec,
            nseconds: attr.mtime_nsec,
        }
        .encode(&mut vals);
    }

    if request.is_set(FATTR4_MOUNTED_ON_FILEID) {
        result_bitmap.set(FATTR4_MOUNTED_ON_FILEID);
        attr.fileid.encode(&mut vals);
    }

    if request.is_set(FATTR4_SUPPATTR_EXCLCREAT) {
        result_bitmap.set(FATTR4_SUPPATTR_EXCLCREAT);
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

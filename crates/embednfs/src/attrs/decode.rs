use bytes::Bytes;

use embednfs_proto::xdr::{XdrDecode, XdrResult};
use embednfs_proto::*;

use crate::fs::{SetFileAttr, SetTime};

/// Decode setattr attributes from an Fattr4.
pub(crate) fn decode_setattr(fattr: &Fattr4) -> XdrResult<SetFileAttr> {
    let mut result = SetFileAttr::default();
    let mut src = Bytes::from(fattr.attr_vals.clone());

    if fattr.attrmask.is_set(FATTR4_SIZE)
    {
        let size = u64::decode(&mut src)?;
        result.size = Some(size);
    }

    if fattr.attrmask.is_set(FATTR4_ARCHIVE) {
        let _ = bool::decode(&mut src)?;
    }

    if fattr.attrmask.is_set(FATTR4_HIDDEN) {
        let _ = bool::decode(&mut src)?;
    }

    if fattr.attrmask.is_set(FATTR4_MODE)
    {
        let mode = u32::decode(&mut src)?;
        result.mode = Some(mode & 0o7777);
    }

    if fattr.attrmask.is_set(FATTR4_OWNER)
    {
        let owner_str = String::decode(&mut src)?;
        let uid_str = owner_str.split('@').next().unwrap_or(&owner_str);
        if let Ok(uid) = uid_str.parse::<u32>() {
            result.uid = Some(uid);
        }
    }

    if fattr.attrmask.is_set(FATTR4_OWNER_GROUP)
    {
        let group_str = String::decode(&mut src)?;
        let gid_str = group_str.split('@').next().unwrap_or(&group_str);
        if let Ok(gid) = gid_str.parse::<u32>() {
            result.gid = Some(gid);
        }
    }

    if fattr.attrmask.is_set(FATTR4_SYSTEM) {
        let _ = bool::decode(&mut src)?;
    }

    if fattr.attrmask.is_set(FATTR4_TIME_ACCESS_SET)
    {
        let how = u32::decode(&mut src)?;
        match how {
            0 => result.atime = Some(SetTime::ServerTime),
            1 => {
                let t = NfsTime4::decode(&mut src)?;
                result.atime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
            }
            _ => {}
        }
    }

    if fattr.attrmask.is_set(FATTR4_TIME_BACKUP)
    {
        let t = NfsTime4::decode(&mut src)?;
        result.crtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
    }

    if fattr.attrmask.is_set(FATTR4_TIME_CREATE)
    {
        let t = NfsTime4::decode(&mut src)?;
        result.crtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
    }

    if fattr.attrmask.is_set(FATTR4_TIME_MODIFY_SET)
    {
        let how = u32::decode(&mut src)?;
        match how {
            0 => result.mtime = Some(SetTime::ServerTime),
            1 => {
                let t = NfsTime4::decode(&mut src)?;
                result.mtime = Some(SetTime::ClientTime(t.seconds, t.nseconds));
            }
            _ => {}
        }
    }

    Ok(result)
}

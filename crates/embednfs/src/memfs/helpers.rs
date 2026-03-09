use std::sync::atomic::Ordering;

use crate::fs::{
    AccessMask, Attrs, AuthContext, FsError, FsResult, ObjectType, RequestContext, SetAttrs,
    SetTime, Timestamp,
};

use super::MemFs;
use super::state::{Inode, InodeData, MemFsInner};

impl MemFs {
    pub(super) fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn next_change(&self) -> u64 {
        self.next_change.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn touch_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.ctime = now;
    }

    pub(super) fn touch_data_change(&self, attrs: &mut Attrs) {
        let now = Timestamp::now();
        attrs.change = self.next_change();
        attrs.mtime = now;
        attrs.ctime = now;
    }

    pub(super) fn apply_set_time(field: &mut Timestamp, value: SetTime) {
        *field = match value {
            SetTime::ServerNow => Timestamp::now(),
            SetTime::Client(ts) => ts,
        };
    }

    pub(super) fn apply_create_owner(attrs: &mut Attrs, ctx: &RequestContext) {
        if let AuthContext::Sys { uid, gid, .. } = &ctx.auth {
            attrs.uid = *uid;
            attrs.gid = *gid;
        }
    }

    pub(super) fn apply_setattrs(&self, inode: &mut Inode, attrs: &SetAttrs) -> FsResult<()> {
        let mut changed = false;

        if let Some(size) = attrs.size {
            match &mut inode.data {
                InodeData::File(data) => {
                    data.resize(size as usize, 0);
                    inode.attrs.size = size;
                    inode.attrs.space_used = size;
                    changed = true;
                }
                _ => return Err(FsError::InvalidInput),
            }
        }
        if let Some(mode) = attrs.mode {
            inode.attrs.mode = mode & 0o7777;
            changed = true;
        }
        if let Some(uid) = attrs.uid {
            inode.attrs.uid = uid;
            changed = true;
        }
        if let Some(gid) = attrs.gid {
            inode.attrs.gid = gid;
            changed = true;
        }
        if let Some(archive) = attrs.archive {
            inode.attrs.archive = archive;
            changed = true;
        }
        if let Some(hidden) = attrs.hidden {
            inode.attrs.hidden = hidden;
            changed = true;
        }
        if let Some(system) = attrs.system {
            inode.attrs.system = system;
            changed = true;
        }
        if let Some(atime) = attrs.atime {
            Self::apply_set_time(&mut inode.attrs.atime, atime);
            changed = true;
        }
        if let Some(mtime) = attrs.mtime {
            Self::apply_set_time(&mut inode.attrs.mtime, mtime);
            changed = true;
        }
        if let Some(birthtime) = attrs.birthtime {
            Self::apply_set_time(&mut inode.attrs.birthtime, birthtime);
            changed = true;
        }

        if changed {
            self.touch_change(&mut inode.attrs);
        }

        Ok(())
    }

    pub(super) fn recompute_link_counts(inner: &mut MemFsInner) {
        for inode in inner.inodes.values_mut() {
            inode.attrs.link_count = match inode.attrs.object_type {
                ObjectType::Directory => 2,
                _ => 0,
            };
        }

        let directory_ids: Vec<u64> = inner
            .inodes
            .iter()
            .filter_map(|(id, inode)| match inode.data {
                InodeData::Directory(_) => Some(*id),
                _ => None,
            })
            .collect();

        for dir_id in directory_ids {
            let entries = match &inner.inodes.get(&dir_id).unwrap().data {
                InodeData::Directory(entries) => entries.clone(),
                _ => continue,
            };
            for child_id in entries.values() {
                if let Some(child) = inner.inodes.get_mut(child_id) {
                    match child.attrs.object_type {
                        ObjectType::Directory => {
                            if let Some(parent) = inner.inodes.get_mut(&dir_id) {
                                parent.attrs.link_count += 1;
                            }
                        }
                        _ => child.attrs.link_count += 1,
                    }
                }
            }
        }
    }

    pub(super) fn remove_if_unlinked(inner: &mut MemFsInner, inode_id: u64) {
        let should_remove = match inner.inodes.get(&inode_id) {
            Some(inode) => match inode.attrs.object_type {
                ObjectType::Directory => true,
                _ => !inner
                    .inodes
                    .values()
                    .any(|candidate| match &candidate.data {
                        InodeData::Directory(entries) => entries.values().any(|id| *id == inode_id),
                        _ => false,
                    }),
            },
            None => false,
        };

        if should_remove {
            inner.inodes.remove(&inode_id);
        }
    }

    pub(super) fn update_has_named_attrs(inode: &mut Inode) {
        inode.attrs.has_named_attrs = !inode.xattrs.is_empty();
    }

    pub(super) fn allowed_mode_bits(attrs: &Attrs, auth: &AuthContext) -> u32 {
        match auth {
            AuthContext::Sys {
                uid,
                gid,
                supplemental_gids,
            } => {
                if *uid == 0 {
                    return 0o7;
                }
                if *uid == attrs.uid {
                    return (attrs.mode >> 6) & 0o7;
                }
                if *gid == attrs.gid || supplemental_gids.contains(&attrs.gid) {
                    return (attrs.mode >> 3) & 0o7;
                }
                attrs.mode & 0o7
            }
            AuthContext::None | AuthContext::Unknown { .. } => attrs.mode & 0o7,
        }
    }

    pub(super) fn access_mask_for(
        attrs: &Attrs,
        auth: &AuthContext,
        requested: AccessMask,
    ) -> AccessMask {
        let perms = Self::allowed_mode_bits(attrs, auth);
        let mut allowed = AccessMask::NONE;

        if requested.intersects(AccessMask::READ) && (perms & 0o4) != 0 {
            allowed |= AccessMask::READ;
        }
        if requested.intersects(AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE)
            && (perms & 0o2) != 0
        {
            if requested.intersects(AccessMask::MODIFY) {
                allowed |= AccessMask::MODIFY;
            }
            if requested.intersects(AccessMask::EXTEND) {
                allowed |= AccessMask::EXTEND;
            }
            if requested.intersects(AccessMask::DELETE) {
                allowed |= AccessMask::DELETE;
            }
        }
        if requested.intersects(AccessMask::EXECUTE) && (perms & 0o1) != 0 {
            allowed |= AccessMask::EXECUTE;
        }
        if attrs.object_type == ObjectType::Directory
            && requested.intersects(AccessMask::LOOKUP)
            && (perms & 0o1) != 0
        {
            allowed |= AccessMask::LOOKUP;
        }

        allowed
    }
}

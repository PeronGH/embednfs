use bytes::{Bytes, BytesMut};

use crate::xdr::*;

use super::{Changeid4, Count4};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bitmap4(pub Vec<u32>);

impl Bitmap4 {
    pub fn new() -> Self {
        Bitmap4(vec![])
    }

    pub fn is_set(&self, bit: u32) -> bool {
        let word = (bit / 32) as usize;
        let mask = 1u32 << (bit % 32);
        self.0.get(word).is_some_and(|w| w & mask != 0)
    }

    pub fn set(&mut self, bit: u32) {
        let word = (bit / 32) as usize;
        let mask = 1u32 << (bit % 32);
        while self.0.len() <= word {
            self.0.push(0);
        }
        self.0[word] |= mask;
    }
}

impl XdrEncode for Bitmap4 {
    fn encode(&self, dst: &mut BytesMut) {
        let trimmed_len = self
            .0
            .iter()
            .rposition(|word| *word != 0)
            .map_or(0, |idx| idx + 1);
        (trimmed_len as u32).encode(dst);
        for word in &self.0[..trimmed_len] {
            word.encode(dst);
        }
    }
}

impl XdrDecode for Bitmap4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let count = u32::decode(src)? as usize;
        if count > 8 {
            return Err(XdrError::OpaqueTooLong(count));
        }
        let mut words = Vec::with_capacity(count);
        for _ in 0..count {
            words.push(u32::decode(src)?);
        }
        Ok(Bitmap4(words))
    }
}

pub const FATTR4_SUPPORTED_ATTRS: u32 = 0;
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_FH_EXPIRE_TYPE: u32 = 2;
pub const FATTR4_CHANGE: u32 = 3;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_LINK_SUPPORT: u32 = 5;
pub const FATTR4_SYMLINK_SUPPORT: u32 = 6;
pub const FATTR4_NAMED_ATTR: u32 = 7;
pub const FATTR4_FSID: u32 = 8;
pub const FATTR4_UNIQUE_HANDLES: u32 = 9;
pub const FATTR4_LEASE_TIME: u32 = 10;
pub const FATTR4_RDATTR_ERROR: u32 = 11;
pub const FATTR4_ACL: u32 = 12;
pub const FATTR4_ACLSUPPORT: u32 = 13;
pub const FATTR4_ARCHIVE: u32 = 14;
pub const FATTR4_CANSETTIME: u32 = 15;
pub const FATTR4_CASE_INSENSITIVE: u32 = 16;
pub const FATTR4_CASE_PRESERVING: u32 = 17;
pub const FATTR4_CHOWN_RESTRICTED: u32 = 18;
pub const FATTR4_FILEHANDLE: u32 = 19;
pub const FATTR4_FILEID: u32 = 20;
pub const FATTR4_FILES_AVAIL: u32 = 21;
pub const FATTR4_FILES_FREE: u32 = 22;
pub const FATTR4_FILES_TOTAL: u32 = 23;
pub const FATTR4_FS_LOCATIONS: u32 = 24;
pub const FATTR4_HIDDEN: u32 = 25;
pub const FATTR4_HOMOGENEOUS: u32 = 26;
pub const FATTR4_MAXFILESIZE: u32 = 27;
pub const FATTR4_MAXLINK: u32 = 28;
pub const FATTR4_MAXNAME: u32 = 29;
pub const FATTR4_MAXREAD: u32 = 30;
pub const FATTR4_MAXWRITE: u32 = 31;
pub const FATTR4_MIMETYPE: u32 = 32;
pub const FATTR4_MODE: u32 = 33;
pub const FATTR4_NO_TRUNC: u32 = 34;
pub const FATTR4_NUMLINKS: u32 = 35;
pub const FATTR4_OWNER: u32 = 36;
pub const FATTR4_OWNER_GROUP: u32 = 37;
pub const FATTR4_QUOTA_AVAIL_HARD: u32 = 38;
pub const FATTR4_QUOTA_AVAIL_SOFT: u32 = 39;
pub const FATTR4_QUOTA_USED: u32 = 40;
pub const FATTR4_RAWDEV: u32 = 41;
pub const FATTR4_SPACE_AVAIL: u32 = 42;
pub const FATTR4_SPACE_FREE: u32 = 43;
pub const FATTR4_SPACE_TOTAL: u32 = 44;
pub const FATTR4_SPACE_USED: u32 = 45;
pub const FATTR4_SYSTEM: u32 = 46;
pub const FATTR4_TIME_ACCESS: u32 = 47;
pub const FATTR4_TIME_ACCESS_SET: u32 = 48;
pub const FATTR4_TIME_BACKUP: u32 = 49;
pub const FATTR4_TIME_CREATE: u32 = 50;
pub const FATTR4_TIME_DELTA: u32 = 51;
pub const FATTR4_TIME_METADATA: u32 = 52;
pub const FATTR4_TIME_MODIFY: u32 = 53;
pub const FATTR4_TIME_MODIFY_SET: u32 = 54;
pub const FATTR4_MOUNTED_ON_FILEID: u32 = 55;
pub const FATTR4_SUPPATTR_EXCLCREAT: u32 = 75;

#[derive(Debug, Clone, Copy, Default)]
pub struct Fsid4 {
    pub major: u64,
    pub minor: u64,
}

impl XdrEncode for Fsid4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.major.encode(dst);
        self.minor.encode(dst);
    }
}

impl XdrDecode for Fsid4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(Fsid4 {
            major: u64::decode(src)?,
            minor: u64::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Specdata4 {
    pub specdata1: u32,
    pub specdata2: u32,
}

impl XdrEncode for Specdata4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.specdata1.encode(dst);
        self.specdata2.encode(dst);
    }
}

#[derive(Debug, Clone)]
pub struct Fattr4 {
    pub attrmask: Bitmap4,
    pub attr_vals: Vec<u8>,
}

impl XdrEncode for Fattr4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.attrmask.encode(dst);
        encode_opaque(dst, &self.attr_vals);
    }
}

impl XdrDecode for Fattr4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(Fattr4 {
            attrmask: Bitmap4::decode(src)?,
            attr_vals: decode_opaque(src)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChangeInfo4 {
    pub atomic: bool,
    pub before: Changeid4,
    pub after: Changeid4,
}

impl XdrEncode for ChangeInfo4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.atomic.encode(dst);
        self.before.encode(dst);
        self.after.encode(dst);
    }
}

pub const ACCESS4_READ: u32 = 0x00000001;
pub const ACCESS4_LOOKUP: u32 = 0x00000002;
pub const ACCESS4_MODIFY: u32 = 0x00000004;
pub const ACCESS4_EXTEND: u32 = 0x00000008;
pub const ACCESS4_DELETE: u32 = 0x00000010;
pub const ACCESS4_EXECUTE: u32 = 0x00000020;

pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x00000001;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x00000002;
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 0x00000003;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x00000000;
pub const OPEN4_SHARE_DENY_READ: u32 = 0x00000001;
pub const OPEN4_SHARE_DENY_WRITE: u32 = 0x00000002;
pub const OPEN4_SHARE_DENY_BOTH: u32 = 0x00000003;
pub const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK: u32 = 0xFF00;
pub const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE: u32 = 0x0000;
pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: u32 = 0x0100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenClaimType4 {
    Null = 0,
    Previous = 1,
    DelegateCur = 2,
    DelegatePrev = 3,
    Fh = 4,
    DelegCurFh = 5,
    DelegPrevFh = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Createmode4 {
    Unchecked4 = 0,
    Guarded4 = 1,
    Exclusive4 = 2,
    Exclusive4_1 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenDelegationType4 {
    None = 0,
    Read = 1,
    Write = 2,
    NoneExt = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WhyNoDelegation4 {
    NotWanted = 0,
    Contention = 1,
    ResourceNotAvail = 2,
    NotSuppFtype = 3,
    WriteDelegNotSuppFtype = 4,
    NotSuppUpgrade = 5,
    NotSuppDowngrade = 6,
    Cancelled = 7,
    IsDir = 8,
}

pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x00000001;
pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x00000002;
pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: u32 = 0x00000100;
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x00010000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x00020000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x00040000;
pub const EXCHGID4_FLAG_MASK_PNFS: u32 = 0x00070000;
pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x40000000;
pub const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x80000000;

pub const CREATE_SESSION4_FLAG_PERSIST: u32 = 0x00000001;
pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 0x00000002;
pub const CREATE_SESSION4_FLAG_CONN_RDMA: u32 = 0x00000004;

#[derive(Debug, Clone)]
pub struct ChannelAttrs4 {
    pub headerpadsize: Count4,
    pub maxrequestsize: Count4,
    pub maxresponsesize: Count4,
    pub maxresponsesize_cached: Count4,
    pub maxoperations: Count4,
    pub maxrequests: Count4,
    pub rdma_ird: Vec<u32>,
}

impl XdrEncode for ChannelAttrs4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.headerpadsize.encode(dst);
        self.maxrequestsize.encode(dst);
        self.maxresponsesize.encode(dst);
        self.maxresponsesize_cached.encode(dst);
        self.maxoperations.encode(dst);
        self.maxrequests.encode(dst);
        (self.rdma_ird.len() as u32).encode(dst);
        for value in &self.rdma_ird {
            value.encode(dst);
        }
    }
}

impl XdrDecode for ChannelAttrs4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(ChannelAttrs4 {
            headerpadsize: u32::decode(src)?,
            maxrequestsize: u32::decode(src)?,
            maxresponsesize: u32::decode(src)?,
            maxresponsesize_cached: u32::decode(src)?,
            maxoperations: u32::decode(src)?,
            maxrequests: u32::decode(src)?,
            rdma_ird: decode_list(src)?,
        })
    }
}

impl Default for ChannelAttrs4 {
    fn default() -> Self {
        ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: 1_049_620,
            maxresponsesize: 1_049_620,
            maxresponsesize_cached: 6144,
            maxoperations: 16,
            maxrequests: 64,
            rdma_ird: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallbackSecParms4 {
    pub cb_secflavor: u32,
}

impl XdrDecode for CallbackSecParms4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let cb_secflavor = u32::decode(src)?;
        match cb_secflavor {
            0 => {}
            1 => {
                let _stamp = u32::decode(src)?;
                let _machine = String::decode(src)?;
                let _uid = u32::decode(src)?;
                let _gid = u32::decode(src)?;
                let _gids: Vec<u32> = decode_list(src)?;
            }
            _ => {}
        }
        Ok(CallbackSecParms4 { cb_secflavor })
    }
}

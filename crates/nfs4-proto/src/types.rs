/// NFSv4.1 protocol types per RFC 8881.
use bytes::{Bytes, BytesMut};
use crate::xdr::*;

// ===== Basic types =====

pub type Offset4 = u64;
pub type Count4 = u32;
pub type Length4 = u64;
pub type Changeid4 = u64;
pub type Clientid4 = u64;
pub type Seqid4 = u32;
pub type Sequenceid4 = u32;
pub type Slotid4 = u32;
pub type Sessionid4 = [u8; 16];
pub type Verifier4 = [u8; 8];

/// NFS file handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NfsFh4(pub Vec<u8>);

impl XdrEncode for NfsFh4 {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, &self.0);
    }
}

impl XdrDecode for NfsFh4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let data = decode_opaque_max(src, 128)?;
        Ok(NfsFh4(data))
    }
}

/// NFS status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsStat4 {
    Ok = 0,
    Perm = 1,
    Noent = 2,
    Io = 5,
    Nxio = 6,
    Access = 13,
    Exist = 17,
    Xdev = 18,
    Notdir = 20,
    Isdir = 21,
    Inval = 22,
    Fbig = 27,
    Nospc = 28,
    Rofs = 30,
    Mlink = 31,
    Nametoolong = 63,
    Notempty = 66,
    Dquot = 69,
    Stale = 70,
    Badhandle = 10001,
    BadCookie = 10003,
    Notsupp = 10004,
    Toosmall = 10005,
    Serverfault = 10006,
    Badtype = 10007,
    Delay = 10008,
    Same = 10009,
    Denied = 10010,
    Expired = 10011,
    Locked = 10012,
    Grace = 10013,
    Fhexpired = 10014,
    ShareDenied = 10015,
    WrongSec = 10016,
    ClidInuse = 10017,
    Moved = 10019,
    Nofilehandle = 10020,
    MinorVersMismatch = 10021,
    StaleClientid = 10022,
    StaleStateid = 10023,
    OldStateid = 10024,
    BadStateid = 10025,
    BadSeqid = 10026,
    NotSame = 10027,
    LockRange = 10028,
    Symlink = 10029,
    Restorefh = 10030,
    LeaseMoved = 10031,
    AttrNotsupp = 10032,
    NoGrace = 10033,
    ReclaimBad = 10034,
    ReclaimConflict = 10035,
    BadXdr = 10036,
    LocksHeld = 10037,
    Openmode = 10038,
    BadOwner = 10039,
    Badchar = 10040,
    Badname = 10041,
    BadRange = 10042,
    LockNotsupp = 10043,
    OpIllegal = 10044,
    Deadlock = 10045,
    FileOpen = 10046,
    AdminRevoked = 10047,
    CbPathDown = 10048,
    BadIomode = 10049,
    BadLayout = 10050,
    BadSessionDigest = 10051,
    BadSession = 10052,
    BadSlot = 10053,
    CompleteAlready = 10054,
    ConnNotBoundToSession = 10055,
    DelegAlreadyWanted = 10056,
    BackChanBusy = 10057,
    LayoutTrylater = 10058,
    LayoutUnavailable = 10059,
    NomatchingLayout = 10060,
    RecallConflict = 10061,
    UnknownLayouttype = 10062,
    SeqMisordered = 10063,
    SeqFalseRetry = 10064,
    RetryUncachedRep = 10065,
    BadHighSlot = 10066,
    DeadSession = 10067,
    EncrAlgUnsupp = 10068,
    PnfsNoLayout = 10069,
    NotOnlyOp = 10070,
    WrongCred = 10071,
    WrongType = 10072,
    DirDelegUnavail = 10073,
    RejectDeleg = 10074,
    ReturnConflict = 10075,
    DelegRevoked = 10076,
    PartnerNotsupp = 10077,
    PartnerNoAuth = 10078,
    UnionNotsupp = 10079,
    ReplayMe = 10080,
    TooManyOps = 10081,
}

impl NfsStat4 {
    pub fn from_u32(v: u32) -> Self {
        // Safety: we handle all known values, default to Serverfault
        match v {
            0 => NfsStat4::Ok,
            1 => NfsStat4::Perm,
            2 => NfsStat4::Noent,
            5 => NfsStat4::Io,
            6 => NfsStat4::Nxio,
            13 => NfsStat4::Access,
            17 => NfsStat4::Exist,
            18 => NfsStat4::Xdev,
            20 => NfsStat4::Notdir,
            21 => NfsStat4::Isdir,
            22 => NfsStat4::Inval,
            27 => NfsStat4::Fbig,
            28 => NfsStat4::Nospc,
            30 => NfsStat4::Rofs,
            31 => NfsStat4::Mlink,
            63 => NfsStat4::Nametoolong,
            66 => NfsStat4::Notempty,
            69 => NfsStat4::Dquot,
            70 => NfsStat4::Stale,
            10001 => NfsStat4::Badhandle,
            10003 => NfsStat4::BadCookie,
            10004 => NfsStat4::Notsupp,
            10005 => NfsStat4::Toosmall,
            10006 => NfsStat4::Serverfault,
            10044 => NfsStat4::OpIllegal,
            10052 => NfsStat4::BadSession,
            10053 => NfsStat4::BadSlot,
            10063 => NfsStat4::SeqMisordered,
            10070 => NfsStat4::NotOnlyOp,
            _ => NfsStat4::Serverfault,
        }
    }
}

impl XdrEncode for NfsStat4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

impl XdrDecode for NfsStat4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let v = u32::decode(src)?;
        Ok(NfsStat4::from_u32(v))
    }
}

// ===== File types =====

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsFtype4 {
    Reg = 1,
    Dir = 2,
    Blk = 3,
    Chr = 4,
    Lnk = 5,
    Sock = 6,
    Fifo = 7,
    AttrDir = 8,
    NamedAttr = 9,
}

impl XdrEncode for NfsFtype4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

impl XdrDecode for NfsFtype4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        match u32::decode(src)? {
            1 => Ok(NfsFtype4::Reg),
            2 => Ok(NfsFtype4::Dir),
            3 => Ok(NfsFtype4::Blk),
            4 => Ok(NfsFtype4::Chr),
            5 => Ok(NfsFtype4::Lnk),
            6 => Ok(NfsFtype4::Sock),
            7 => Ok(NfsFtype4::Fifo),
            8 => Ok(NfsFtype4::AttrDir),
            9 => Ok(NfsFtype4::NamedAttr),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

// ===== Time =====

#[derive(Debug, Clone, Copy, Default)]
pub struct NfsTime4 {
    pub seconds: i64,
    pub nseconds: u32,
}

impl XdrEncode for NfsTime4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.seconds.encode(dst);
        self.nseconds.encode(dst);
    }
}

impl XdrDecode for NfsTime4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let seconds = i64::decode(src)?;
        let nseconds = u32::decode(src)?;
        Ok(NfsTime4 { seconds, nseconds })
    }
}

// ===== Stateid =====

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Stateid4 {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl Stateid4 {
    pub const ANONYMOUS: Stateid4 = Stateid4 { seqid: 0, other: [0; 12] };
    pub const CURRENT: Stateid4 = Stateid4 { seqid: 1, other: [0xff; 12] };
    pub const BYPASS: Stateid4 = Stateid4 { seqid: 0xffffffff, other: [0xff; 12] };
}

impl XdrEncode for Stateid4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.seqid.encode(dst);
        dst.extend_from_slice(&self.other);
    }
}

impl XdrDecode for Stateid4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let seqid = u32::decode(src)?;
        let other_data = decode_fixed_opaque(src, 12)?;
        let mut other = [0u8; 12];
        other.copy_from_slice(&other_data);
        Ok(Stateid4 { seqid, other })
    }
}

// ===== File attributes =====

/// Bitmap4 - variable length bitmap for file attributes.
#[derive(Debug, Clone, Default)]
#[derive(PartialEq, Eq)]
pub struct Bitmap4(pub Vec<u32>);

impl Bitmap4 {
    pub fn new() -> Self {
        Bitmap4(vec![0, 0, 0])
    }

    pub fn is_set(&self, bit: u32) -> bool {
        let word = (bit / 32) as usize;
        let mask = 1u32 << (bit % 32);
        self.0.get(word).map_or(false, |w| w & mask != 0)
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
        (self.0.len() as u32).encode(dst);
        for w in &self.0 {
            w.encode(dst);
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

// Attribute bit numbers
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
pub const FATTR4_FILEHANDLE: u32 = 19;
pub const FATTR4_SUPPATTR_EXCLCREAT: u32 = 75;
pub const FATTR4_ACL: u32 = 12;
pub const FATTR4_ACLSUPPORT: u32 = 13;
pub const FATTR4_ARCHIVE: u32 = 14;
pub const FATTR4_CANSETTIME: u32 = 15;
pub const FATTR4_CASE_INSENSITIVE: u32 = 16;
pub const FATTR4_CASE_PRESERVING: u32 = 17;
pub const FATTR4_CHOWN_RESTRICTED: u32 = 18;
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

/// FSID.
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
        let major = u64::decode(src)?;
        let minor = u64::decode(src)?;
        Ok(Fsid4 { major, minor })
    }
}

/// Specdata4 for device numbers.
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

/// Fattr4 - file attributes with bitmap + opaque value.
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
        let attrmask = Bitmap4::decode(src)?;
        let attr_vals = decode_opaque(src)?;
        Ok(Fattr4 { attrmask, attr_vals })
    }
}

// ===== Change info =====

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

// ===== Access bits =====
pub const ACCESS4_READ: u32 = 0x00000001;
pub const ACCESS4_LOOKUP: u32 = 0x00000002;
pub const ACCESS4_MODIFY: u32 = 0x00000004;
pub const ACCESS4_EXTEND: u32 = 0x00000008;
pub const ACCESS4_DELETE: u32 = 0x00000010;
pub const ACCESS4_EXECUTE: u32 = 0x00000020;

// ===== Open flags =====
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

// Open claim types
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

// Create mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Createmode4 {
    Unchecked4 = 0,
    Guarded4 = 1,
    Exclusive4 = 2,
    Exclusive4_1 = 3,
}

// Open delegation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenDelegationType4 {
    None = 0,
    Read = 1,
    Write = 2,
    NoneExt = 3,
}

// why_no_delegation4
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

// ===== Operation numbers =====

pub const OP_ACCESS: u32 = 3;
pub const OP_CLOSE: u32 = 4;
pub const OP_COMMIT: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_DELEGPURGE: u32 = 7;
pub const OP_DELEGRETURN: u32 = 8;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LINK: u32 = 11;
pub const OP_LOCK: u32 = 12;
pub const OP_LOCKT: u32 = 13;
pub const OP_LOCKU: u32 = 14;
pub const OP_LOOKUP: u32 = 15;
pub const OP_LOOKUPP: u32 = 16;
pub const OP_NVERIFY: u32 = 17;
pub const OP_OPEN: u32 = 18;
pub const OP_OPENATTR: u32 = 19;
pub const OP_OPEN_CONFIRM: u32 = 20; // removed in v4.1
pub const OP_OPEN_DOWNGRADE: u32 = 21;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTPUBFH: u32 = 23;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30; // removed in v4.1
pub const OP_RESTOREFH: u32 = 31;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SECINFO: u32 = 33;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35; // removed in v4.1
pub const OP_SETCLIENTID_CONFIRM: u32 = 36; // removed in v4.1
pub const OP_VERIFY: u32 = 37;
pub const OP_WRITE: u32 = 38;
pub const OP_RELEASE_LOCKOWNER: u32 = 39; // removed in v4.1
pub const OP_BACKCHANNEL_CTL: u32 = 40;
pub const OP_BIND_CONN_TO_SESSION: u32 = 41;
pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_DESTROY_SESSION: u32 = 44;
pub const OP_FREE_STATEID: u32 = 45;
pub const OP_GET_DIR_DELEGATION: u32 = 46;
pub const OP_GETDEVICEINFO: u32 = 47;
pub const OP_GETDEVICELIST: u32 = 48;
pub const OP_LAYOUTCOMMIT: u32 = 49;
pub const OP_LAYOUTGET: u32 = 50;
pub const OP_LAYOUTRETURN: u32 = 51;
pub const OP_SECINFO_NO_NAME: u32 = 52;
pub const OP_SEQUENCE: u32 = 53;
pub const OP_SET_SSV: u32 = 54;
pub const OP_TEST_STATEID: u32 = 55;
pub const OP_WANT_DELEGATION: u32 = 56;
pub const OP_DESTROY_CLIENTID: u32 = 57;
pub const OP_RECLAIM_COMPLETE: u32 = 58;
pub const OP_ILLEGAL: u32 = 10044;

// ===== EXCHANGE_ID flags =====
pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x00000001;
pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x00000002;
pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: u32 = 0x00000100;
pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x00010000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x00020000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x00040000;
pub const EXCHGID4_FLAG_MASK_PNFS: u32 = 0x00070000;
pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x40000000;
pub const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x80000000;

// ===== CREATE_SESSION flags =====
pub const CREATE_SESSION4_FLAG_PERSIST: u32 = 0x00000001;
pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 0x00000002;
pub const CREATE_SESSION4_FLAG_CONN_RDMA: u32 = 0x00000004;

/// Channel attributes for CREATE_SESSION.
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
        for v in &self.rdma_ird {
            v.encode(dst);
        }
    }
}

impl XdrDecode for ChannelAttrs4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let headerpadsize = u32::decode(src)?;
        let maxrequestsize = u32::decode(src)?;
        let maxresponsesize = u32::decode(src)?;
        let maxresponsesize_cached = u32::decode(src)?;
        let maxoperations = u32::decode(src)?;
        let maxrequests = u32::decode(src)?;
        let rdma_ird = decode_list(src)?;
        Ok(ChannelAttrs4 {
            headerpadsize,
            maxrequestsize,
            maxresponsesize,
            maxresponsesize_cached,
            maxoperations,
            maxrequests,
            rdma_ird,
        })
    }
}

impl Default for ChannelAttrs4 {
    fn default() -> Self {
        ChannelAttrs4 {
            headerpadsize: 0,
            maxrequestsize: 1049620,
            maxresponsesize: 1049620,
            maxresponsesize_cached: 6144,
            maxoperations: 16,
            maxrequests: 64,
            rdma_ird: vec![],
        }
    }
}

/// Callback security parameters.
#[derive(Debug, Clone)]
pub struct CallbackSecParms4 {
    pub cb_secflavor: u32,
    // For AUTH_NONE and AUTH_SYS, no extra fields needed
    // For RPCSEC_GSS, we'd need more fields but we don't support it
}

impl XdrDecode for CallbackSecParms4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let cb_secflavor = u32::decode(src)?;
        match cb_secflavor {
            0 => {} // AUTH_NONE - nothing to decode
            1 => {
                // AUTH_SYS - skip the params
                let _stamp = u32::decode(src)?;
                let _machine = String::decode(src)?;
                let _uid = u32::decode(src)?;
                let _gid = u32::decode(src)?;
                let _gids: Vec<u32> = decode_list(src)?;
            }
            _ => {
                // For GSS, skip; not supported
            }
        }
        Ok(CallbackSecParms4 { cb_secflavor })
    }
}

// ===== NFS operation arguments (decoded from client) =====

/// NfsArgop4 - a single operation in a COMPOUND request.
#[derive(Debug)]
pub enum NfsArgop4 {
    Access(AccessArgs4),
    Close(CloseArgs4),
    Commit(CommitArgs4),
    Create(CreateArgs4),
    Getattr(GetattrArgs4),
    Getfh,
    Link(LinkArgs4),
    Lookup(LookupArgs4),
    Lookupp,
    Open(OpenArgs4),
    OpenConfirm(OpenConfirmArgs4),
    Putfh(PutfhArgs4),
    Putpubfh,
    Putrootfh,
    Read(ReadArgs4),
    Readdir(ReaddirArgs4),
    Readlink,
    Remove(RemoveArgs4),
    Rename(RenameArgs4),
    Restorefh,
    Savefh,
    Secinfo(SecinfoArgs4),
    Setattr(SetattrArgs4),
    Write(WriteArgs4),
    ExchangeId(ExchangeIdArgs4),
    CreateSession(CreateSessionArgs4),
    DestroySession(DestroySessionArgs4),
    Sequence(SequenceArgs4),
    ReclaimComplete(ReclaimCompleteArgs4),
    DestroyClientid(DestroyClientidArgs4),
    BindConnToSession(BindConnToSessionArgs4),
    SecInfoNoName(u32),
    FreeStateid(FreeStateidArgs4),
    TestStateid(TestStateidArgs4),
    DelegReturn(DelegReturnArgs4),
    SetClientId(SetClientIdArgs4),
    SetClientIdConfirm(SetClientIdConfirmArgs4),
    Renew(Clientid4),
    Lock(LockArgs4),
    Lockt(LocktArgs4),
    Locku(LockuArgs4),
    OpenAttr(OpenAttrArgs4),
    DelegPurge,
    ReleaseLockowner,
    Verify(Fattr4),
    Nverify(Fattr4),
    OpenDowngrade(OpenDowngradeArgs4),
    LayoutGet,
    LayoutReturn,
    LayoutCommit,
    GetDirDelegation,
    WantDelegation,
    BackchannelCtl,
    GetDeviceInfo,
    GetDeviceList,
    SetSsv,
    Illegal,
}

// ===== Operation argument types =====

#[derive(Debug)]
pub struct AccessArgs4 {
    pub access: u32,
}

#[derive(Debug)]
pub struct CloseArgs4 {
    pub seqid: Seqid4,
    pub open_stateid: Stateid4,
}

#[derive(Debug)]
pub struct CommitArgs4 {
    pub offset: Offset4,
    pub count: Count4,
}

#[derive(Debug)]
pub struct CreateArgs4 {
    pub objtype: Createtype4,
    pub objname: String,
    pub createattrs: Fattr4,
}

#[derive(Debug)]
pub enum Createtype4 {
    Link(String),
    Blk(Specdata4),
    Chr(Specdata4),
    Sock,
    Fifo,
    Dir,
}

#[derive(Debug)]
pub struct GetattrArgs4 {
    pub attr_request: Bitmap4,
}

#[derive(Debug)]
pub struct LinkArgs4 {
    pub newname: String,
}

#[derive(Debug)]
pub struct LookupArgs4 {
    pub objname: String,
}

#[derive(Debug)]
pub struct OpenArgs4 {
    pub seqid: Seqid4,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: StateOwner4,
    pub openhow: Openflag4,
    pub claim: OpenClaim4,
}

#[derive(Debug, Clone)]
pub struct StateOwner4 {
    pub clientid: Clientid4,
    pub owner: Vec<u8>,
}

impl XdrDecode for StateOwner4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let clientid = u64::decode(src)?;
        let owner = decode_opaque(src)?;
        Ok(StateOwner4 { clientid, owner })
    }
}

#[derive(Debug)]
pub enum Openflag4 {
    NoCreate,
    Create(Createhow4),
}

#[derive(Debug)]
pub enum Createhow4 {
    Unchecked(Fattr4),
    Guarded(Fattr4),
    Exclusive(Verifier4),
    Exclusive4_1 { verifier: Verifier4, attrs: Fattr4 },
}

#[derive(Debug)]
pub enum OpenClaim4 {
    Null(String),
    Previous(u32),
    DelegateCur { delegate_stateid: Stateid4, file: String },
    DelegatePrev(String),
    Fh,
    DelegCurFh(Stateid4),
    DelegPrevFh,
}

#[derive(Debug)]
pub struct PutfhArgs4 {
    pub object: NfsFh4,
}

#[derive(Debug)]
pub struct ReadArgs4 {
    pub stateid: Stateid4,
    pub offset: Offset4,
    pub count: Count4,
}

#[derive(Debug)]
pub struct ReaddirArgs4 {
    pub cookie: u64,
    pub cookieverf: Verifier4,
    pub dircount: Count4,
    pub maxcount: Count4,
    pub attr_request: Bitmap4,
}

#[derive(Debug)]
pub struct RemoveArgs4 {
    pub target: String,
}

#[derive(Debug)]
pub struct RenameArgs4 {
    pub oldname: String,
    pub newname: String,
}

#[derive(Debug)]
pub struct SecinfoArgs4 {
    pub name: String,
}

#[derive(Debug)]
pub struct OpenConfirmArgs4 {
    pub open_stateid: Stateid4,
    pub seqid: Seqid4,
}

#[derive(Debug)]
pub struct SetClientIdArgs4 {
    pub client: ClientOwner4,
    pub callback: NfsClientCallback4,
    pub callback_ident: u32,
}

#[derive(Debug)]
pub struct NfsClientCallback4 {
    pub cb_program: u32,
    pub cb_location: String,
}

#[derive(Debug)]
pub struct SetClientIdConfirmArgs4 {
    pub clientid: Clientid4,
    pub verifier: Verifier4,
}

#[derive(Debug)]
pub struct OpenDowngradeArgs4 {
    pub open_stateid: Stateid4,
    pub seqid: Seqid4,
    pub share_access: u32,
    pub share_deny: u32,
}

#[derive(Debug)]
pub struct SetattrArgs4 {
    pub stateid: Stateid4,
    pub obj_attributes: Fattr4,
}

#[derive(Debug)]
pub struct WriteArgs4 {
    pub stateid: Stateid4,
    pub offset: Offset4,
    pub stable: u32, // stable_how4
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct ExchangeIdArgs4 {
    pub clientowner: ClientOwner4,
    pub flags: u32,
    pub state_protect: StateProtect4A,
    pub client_impl_id: Vec<NfsImplId4>,
}

#[derive(Debug, Clone)]
pub struct ClientOwner4 {
    pub verifier: Verifier4,
    pub ownerid: Vec<u8>,
}

impl XdrDecode for ClientOwner4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let vdata = decode_fixed_opaque(src, 8)?;
        let mut verifier = [0u8; 8];
        verifier.copy_from_slice(&vdata);
        let ownerid = decode_opaque(src)?;
        Ok(ClientOwner4 { verifier, ownerid })
    }
}

#[derive(Debug)]
pub enum StateProtect4A {
    None,
    MachCred { ops: StateProt4MachOps },
    Ssv { ssv: SsvProtInfo4 },
}

#[derive(Debug)]
pub struct StateProt4MachOps {
    pub enforce: Bitmap4,
    pub allow: Bitmap4,
}

#[derive(Debug)]
pub struct SsvProtInfo4 {
    // We don't really need this for a basic impl
    pub ops: StateProt4MachOps,
    pub hash_algs: Vec<u32>,
    pub encr_algs: Vec<u32>,
    pub window: u32,
    pub num_gss_handles: u32,
}

#[derive(Debug, Clone)]
pub struct NfsImplId4 {
    pub domain: String,
    pub name: String,
    pub date: NfsTime4,
}

impl XdrEncode for NfsImplId4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.domain.encode(dst);
        self.name.encode(dst);
        self.date.encode(dst);
    }
}

impl XdrDecode for NfsImplId4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let domain = String::decode(src)?;
        let name = String::decode(src)?;
        let date = NfsTime4::decode(src)?;
        Ok(NfsImplId4 { domain, name, date })
    }
}

#[derive(Debug)]
pub struct CreateSessionArgs4 {
    pub clientid: Clientid4,
    pub sequence: Sequenceid4,
    pub flags: u32,
    pub fore_chan_attrs: ChannelAttrs4,
    pub back_chan_attrs: ChannelAttrs4,
    pub cb_program: u32,
    pub sec_parms: Vec<CallbackSecParms4>,
}

#[derive(Debug)]
pub struct DestroySessionArgs4 {
    pub sessionid: Sessionid4,
}

#[derive(Debug)]
pub struct SequenceArgs4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub slotid: Slotid4,
    pub highest_slotid: Slotid4,
    pub cachethis: bool,
}

#[derive(Debug)]
pub struct ReclaimCompleteArgs4 {
    pub one_fs: bool,
}

#[derive(Debug)]
pub struct DestroyClientidArgs4 {
    pub clientid: Clientid4,
}

#[derive(Debug)]
pub struct BindConnToSessionArgs4 {
    pub sessionid: Sessionid4,
    pub dir: u32,
    pub use_conn_in_rdma_mode: bool,
}

#[derive(Debug)]
pub struct FreeStateidArgs4 {
    pub stateid: Stateid4,
}

#[derive(Debug)]
pub struct TestStateidArgs4 {
    pub stateids: Vec<Stateid4>,
}

#[derive(Debug)]
pub struct DelegReturnArgs4 {
    pub stateid: Stateid4,
}

// ===== Lock types =====

/// Lock type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsLockType4 {
    ReadLt = 1,
    WriteLt = 2,
    ReadwLt = 3,
    WritewLt = 4,
}

impl XdrDecode for NfsLockType4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let v = u32::decode(src)?;
        match v {
            1 => Ok(NfsLockType4::ReadLt),
            2 => Ok(NfsLockType4::WriteLt),
            3 => Ok(NfsLockType4::ReadwLt),
            4 => Ok(NfsLockType4::WritewLt),
            _ => Err(XdrError::InvalidEnum(v)),
        }
    }
}

impl XdrEncode for NfsLockType4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

/// Open-to-lock owner (new lock).
#[derive(Debug)]
pub struct OpenToLockOwner4 {
    pub open_seqid: Seqid4,
    pub open_stateid: Stateid4,
    pub lock_seqid: Seqid4,
    pub lock_owner: StateOwner4,
}

/// Existing lock owner.
#[derive(Debug)]
pub struct ExistLockOwner4 {
    pub lock_stateid: Stateid4,
    pub lock_seqid: Seqid4,
}

/// Lock owner union.
#[derive(Debug)]
pub enum Locker4 {
    NewLockOwner(OpenToLockOwner4),
    ExistingLockOwner(ExistLockOwner4),
}

/// LOCK args.
#[derive(Debug)]
pub struct LockArgs4 {
    pub locktype: NfsLockType4,
    pub reclaim: bool,
    pub offset: Offset4,
    pub length: Length4,
    pub locker: Locker4,
}

/// LOCKT args.
#[derive(Debug)]
pub struct LocktArgs4 {
    pub locktype: NfsLockType4,
    pub offset: Offset4,
    pub length: Length4,
    pub owner: StateOwner4,
}

/// LOCKU args.
#[derive(Debug)]
pub struct LockuArgs4 {
    pub locktype: NfsLockType4,
    pub seqid: Seqid4,
    pub lock_stateid: Stateid4,
    pub offset: Offset4,
    pub length: Length4,
}

/// Lock denied info.
#[derive(Debug)]
pub struct LockDenied4 {
    pub offset: Offset4,
    pub length: Length4,
    pub locktype: NfsLockType4,
    pub owner: StateOwner4,
}

/// OPENATTR args.
#[derive(Debug)]
pub struct OpenAttrArgs4 {
    pub createdir: bool,
}

// ===== Compound request/response =====

/// A COMPOUND request (NFSv4.1 procedure 1).
#[derive(Debug)]
pub struct Compound4Args {
    pub tag: String,
    pub minorversion: u32,
    pub argarray: Vec<NfsArgop4>,
}

/// A COMPOUND response.
#[derive(Debug)]
pub struct Compound4Res {
    pub status: NfsStat4,
    pub tag: String,
    pub resarray: Vec<NfsResop4>,
}

impl XdrEncode for Compound4Res {
    fn encode(&self, dst: &mut BytesMut) {
        self.status.encode(dst);
        self.tag.encode(dst);
        (self.resarray.len() as u32).encode(dst);
        for res in &self.resarray {
            res.encode(dst);
        }
    }
}

/// A single operation result.
#[derive(Debug)]
pub enum NfsResop4 {
    Access(NfsStat4, u32, u32), // status, supported, access
    Close(NfsStat4, Stateid4),
    Commit(NfsStat4, Verifier4),
    Create(NfsStat4, Option<ChangeInfo4>, Bitmap4),
    Getattr(NfsStat4, Option<Fattr4>),
    Getfh(NfsStat4, Option<NfsFh4>),
    Link(NfsStat4, Option<ChangeInfo4>),
    Lookup(NfsStat4),
    Lookupp(NfsStat4),
    Open(NfsStat4, Option<OpenRes4>),
    Putfh(NfsStat4),
    Putpubfh(NfsStat4),
    Putrootfh(NfsStat4),
    Read(NfsStat4, Option<ReadRes4>),
    Readdir(NfsStat4, Option<ReaddirRes4>),
    Readlink(NfsStat4, Option<String>),
    Remove(NfsStat4, Option<ChangeInfo4>),
    Rename(NfsStat4, Option<ChangeInfo4>, Option<ChangeInfo4>),
    Restorefh(NfsStat4),
    Savefh(NfsStat4),
    Secinfo(NfsStat4, Vec<SecinfoEntry4>),
    Setattr(NfsStat4, Bitmap4),
    Write(NfsStat4, Option<WriteRes4>),
    ExchangeId(NfsStat4, Option<ExchangeIdRes4>),
    CreateSession(NfsStat4, Option<CreateSessionRes4>),
    DestroySession(NfsStat4),
    Sequence(NfsStat4, Option<SequenceRes4>),
    ReclaimComplete(NfsStat4),
    DestroyClientid(NfsStat4),
    BindConnToSession(NfsStat4, Option<BindConnToSessionRes4>),
    SecInfoNoName(NfsStat4, Vec<SecinfoEntry4>),
    FreeStateid(NfsStat4),
    TestStateid(NfsStat4, Vec<NfsStat4>),
    DelegReturn(NfsStat4),
    Lock(NfsStat4, Option<Stateid4>, Option<LockDenied4>),
    Lockt(NfsStat4, Option<LockDenied4>),
    Locku(NfsStat4, Option<Stateid4>),
    OpenAttr(NfsStat4),
    DelegPurge(NfsStat4),
    SetClientId(NfsStat4, Option<SetClientIdRes4>),
    SetClientIdConfirm(NfsStat4),
    Renew(NfsStat4),
    OpenConfirm(NfsStat4, Option<Stateid4>),
    ReleaseLockowner(NfsStat4),
    Verify(NfsStat4),
    Nverify(NfsStat4),
    OpenDowngrade(NfsStat4, Option<Stateid4>),
    LayoutGet(NfsStat4),
    LayoutReturn(NfsStat4),
    LayoutCommit(NfsStat4),
    GetDirDelegation(NfsStat4),
    WantDelegation(NfsStat4),
    BackchannelCtl(NfsStat4),
    GetDeviceInfo(NfsStat4),
    GetDeviceList(NfsStat4),
    SetSsv(NfsStat4),
    Illegal(NfsStat4),
}

#[derive(Debug)]
pub struct SetClientIdRes4 {
    pub clientid: Clientid4,
    pub verifier: Verifier4,
}

#[derive(Debug)]
pub struct OpenRes4 {
    pub stateid: Stateid4,
    pub cinfo: ChangeInfo4,
    pub rflags: u32,
    pub attrset: Bitmap4,
    pub delegation: OpenDelegation4,
}

#[derive(Debug)]
pub enum OpenDelegation4 {
    None,
    NoneExt(WhyNoDelegation4),
    Read { stateid: Stateid4 },
    Write { stateid: Stateid4 },
}

#[derive(Debug)]
pub struct ReadRes4 {
    pub eof: bool,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct WriteRes4 {
    pub count: Count4,
    pub committed: u32, // stable_how4
    pub writeverf: Verifier4,
}

#[derive(Debug)]
pub struct ReaddirRes4 {
    pub cookieverf: Verifier4,
    pub entries: Vec<Entry4>,
    pub eof: bool,
}

#[derive(Debug)]
pub struct Entry4 {
    pub cookie: u64,
    pub name: String,
    pub attrs: Fattr4,
}

#[derive(Debug)]
pub struct ExchangeIdRes4 {
    pub clientid: Clientid4,
    pub sequenceid: Sequenceid4,
    pub flags: u32,
    pub state_protect: StateProtect4R,
    pub server_owner: ServerOwner4,
    pub server_scope: Vec<u8>,
    pub server_impl_id: Vec<NfsImplId4>,
}

#[derive(Debug)]
pub enum StateProtect4R {
    None,
}

#[derive(Debug, Clone)]
pub struct ServerOwner4 {
    pub minor_id: u64,
    pub major_id: Vec<u8>,
}

impl XdrEncode for ServerOwner4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.minor_id.encode(dst);
        encode_opaque(dst, &self.major_id);
    }
}

#[derive(Debug)]
pub struct CreateSessionRes4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub flags: u32,
    pub fore_chan_attrs: ChannelAttrs4,
    pub back_chan_attrs: ChannelAttrs4,
}

#[derive(Debug)]
pub struct SequenceRes4 {
    pub sessionid: Sessionid4,
    pub sequenceid: Sequenceid4,
    pub slotid: Slotid4,
    pub highest_slotid: Slotid4,
    pub target_highest_slotid: Slotid4,
    pub status_flags: u32,
}

#[derive(Debug)]
pub struct BindConnToSessionRes4 {
    pub sessionid: Sessionid4,
    pub dir: u32,
    pub use_conn_in_rdma_mode: bool,
}

#[derive(Debug)]
pub struct SecinfoEntry4 {
    pub flavor: u32,
    // For AUTH_SYS: nothing extra
    // For RPCSEC_GSS: oid, qop, service
}

impl XdrEncode for SecinfoEntry4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.flavor.encode(dst);
        // AUTH_NONE or AUTH_SYS: no extra data
    }
}

// ===== Open result flags =====
pub const OPEN4_RESULT_CONFIRM: u32 = 0x00000002;
pub const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x00000004;
pub const OPEN4_RESULT_PRESERVE_UNLINKED: u32 = 0x00000008;
pub const OPEN4_RESULT_MAY_NOTIFY_LOCK: u32 = 0x00000020;

// ===== Stable how =====
pub const UNSTABLE4: u32 = 0;
pub const DATA_SYNC4: u32 = 1;
pub const FILE_SYNC4: u32 = 2;

// ===== NfsResop4 encoding =====

impl XdrEncode for NfsResop4 {
    fn encode(&self, dst: &mut BytesMut) {
        match self {
            NfsResop4::Access(status, supported, access) => {
                OP_ACCESS.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    supported.encode(dst);
                    access.encode(dst);
                }
            }
            NfsResop4::Close(status, stateid) => {
                OP_CLOSE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    stateid.encode(dst);
                }
            }
            NfsResop4::Commit(status, verf) => {
                OP_COMMIT.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    dst.extend_from_slice(verf);
                }
            }
            NfsResop4::Create(status, cinfo, attrset) => {
                OP_CREATE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = cinfo {
                        ci.encode(dst);
                    }
                    attrset.encode(dst);
                }
            }
            NfsResop4::Getattr(status, attrs) => {
                OP_GETATTR.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(a) = attrs {
                        a.encode(dst);
                    }
                }
            }
            NfsResop4::Getfh(status, fh) => {
                OP_GETFH.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(f) = fh {
                        f.encode(dst);
                    }
                }
            }
            NfsResop4::Link(status, cinfo) => {
                OP_LINK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = cinfo {
                        ci.encode(dst);
                    }
                }
            }
            NfsResop4::Lookup(status) => {
                OP_LOOKUP.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Lookupp(status) => {
                OP_LOOKUPP.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Open(status, res) => {
                OP_OPEN.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        r.stateid.encode(dst);
                        r.cinfo.encode(dst);
                        r.rflags.encode(dst);
                        r.attrset.encode(dst);
                        // delegation
                        match &r.delegation {
                            OpenDelegation4::None => {
                                (OpenDelegationType4::None as u32).encode(dst);
                            }
                            OpenDelegation4::NoneExt(why) => {
                                (OpenDelegationType4::NoneExt as u32).encode(dst);
                                (*why as u32).encode(dst);
                                // Only CONTENTION and RESOURCE have a bool
                                match why {
                                    WhyNoDelegation4::Contention |
                                    WhyNoDelegation4::ResourceNotAvail => {
                                        false.encode(dst);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {
                                (OpenDelegationType4::None as u32).encode(dst);
                            }
                        }
                    }
                }
            }
            NfsResop4::Putfh(status) => {
                OP_PUTFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Putpubfh(status) => {
                OP_PUTPUBFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Putrootfh(status) => {
                OP_PUTROOTFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Read(status, res) => {
                OP_READ.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        r.eof.encode(dst);
                        encode_opaque(dst, &r.data);
                    }
                }
            }
            NfsResop4::Readdir(status, res) => {
                OP_READDIR.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        dst.extend_from_slice(&r.cookieverf);
                        // Encode directory entries as linked list
                        for entry in &r.entries {
                            true.encode(dst); // value follows
                            entry.cookie.encode(dst);
                            entry.name.encode(dst);
                            entry.attrs.encode(dst);
                        }
                        false.encode(dst); // no more entries
                        r.eof.encode(dst);
                    }
                }
            }
            NfsResop4::Readlink(status, target) => {
                OP_READLINK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(t) = target {
                        t.encode(dst);
                    }
                }
            }
            NfsResop4::Remove(status, cinfo) => {
                OP_REMOVE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = cinfo {
                        ci.encode(dst);
                    }
                }
            }
            NfsResop4::Rename(status, src_cinfo, tgt_cinfo) => {
                OP_RENAME.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(ci) = src_cinfo {
                        ci.encode(dst);
                    }
                    if let Some(ci) = tgt_cinfo {
                        ci.encode(dst);
                    }
                }
            }
            NfsResop4::Restorefh(status) => {
                OP_RESTOREFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Savefh(status) => {
                OP_SAVEFH.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Secinfo(status, entries) => {
                OP_SECINFO.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (entries.len() as u32).encode(dst);
                    for e in entries {
                        e.encode(dst);
                    }
                }
            }
            NfsResop4::Setattr(status, attrsset) => {
                OP_SETATTR.encode(dst);
                status.encode(dst);
                attrsset.encode(dst);
            }
            NfsResop4::Write(status, res) => {
                OP_WRITE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        r.count.encode(dst);
                        r.committed.encode(dst);
                        dst.extend_from_slice(&r.writeverf);
                    }
                }
            }
            NfsResop4::ExchangeId(status, res) => {
                OP_EXCHANGE_ID.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        r.clientid.encode(dst);
                        r.sequenceid.encode(dst);
                        r.flags.encode(dst);
                        // state_protect4_r: SP4_NONE = 0
                        0u32.encode(dst);
                        r.server_owner.encode(dst);
                        encode_opaque(dst, &r.server_scope);
                        // server_impl_id
                        (r.server_impl_id.len() as u32).encode(dst);
                        for id in &r.server_impl_id {
                            id.encode(dst);
                        }
                    }
                }
            }
            NfsResop4::CreateSession(status, res) => {
                OP_CREATE_SESSION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        dst.extend_from_slice(&r.sessionid);
                        r.sequenceid.encode(dst);
                        r.flags.encode(dst);
                        r.fore_chan_attrs.encode(dst);
                        r.back_chan_attrs.encode(dst);
                    }
                }
            }
            NfsResop4::DestroySession(status) => {
                OP_DESTROY_SESSION.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Sequence(status, res) => {
                OP_SEQUENCE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        dst.extend_from_slice(&r.sessionid);
                        r.sequenceid.encode(dst);
                        r.slotid.encode(dst);
                        r.highest_slotid.encode(dst);
                        r.target_highest_slotid.encode(dst);
                        r.status_flags.encode(dst);
                    }
                }
            }
            NfsResop4::ReclaimComplete(status) => {
                OP_RECLAIM_COMPLETE.encode(dst);
                status.encode(dst);
            }
            NfsResop4::DestroyClientid(status) => {
                OP_DESTROY_CLIENTID.encode(dst);
                status.encode(dst);
            }
            NfsResop4::BindConnToSession(status, res) => {
                OP_BIND_CONN_TO_SESSION.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        dst.extend_from_slice(&r.sessionid);
                        r.dir.encode(dst);
                        r.use_conn_in_rdma_mode.encode(dst);
                    }
                }
            }
            NfsResop4::SecInfoNoName(status, entries) => {
                OP_SECINFO_NO_NAME.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (entries.len() as u32).encode(dst);
                    for e in entries {
                        e.encode(dst);
                    }
                }
            }
            NfsResop4::FreeStateid(status) => {
                OP_FREE_STATEID.encode(dst);
                status.encode(dst);
            }
            NfsResop4::TestStateid(status, results) => {
                OP_TEST_STATEID.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    (results.len() as u32).encode(dst);
                    for r in results {
                        r.encode(dst);
                    }
                }
            }
            NfsResop4::DelegReturn(status) => {
                OP_DELEGRETURN.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Lock(status, stateid, denied) => {
                OP_LOCK.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(s) = stateid {
                        s.encode(dst);
                    }
                } else if *status == NfsStat4::Denied {
                    if let Some(d) = denied {
                        d.offset.encode(dst);
                        d.length.encode(dst);
                        d.locktype.encode(dst);
                        d.owner.clientid.encode(dst);
                        encode_opaque(dst, &d.owner.owner);
                    }
                }
            }
            NfsResop4::Lockt(status, denied) => {
                OP_LOCKT.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Denied {
                    if let Some(d) = denied {
                        d.offset.encode(dst);
                        d.length.encode(dst);
                        d.locktype.encode(dst);
                        d.owner.clientid.encode(dst);
                        encode_opaque(dst, &d.owner.owner);
                    }
                }
            }
            NfsResop4::Locku(status, stateid) => {
                OP_LOCKU.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(s) = stateid {
                        s.encode(dst);
                    }
                }
            }
            NfsResop4::OpenAttr(status) => {
                OP_OPENATTR.encode(dst);
                status.encode(dst);
            }
            NfsResop4::DelegPurge(status) => {
                OP_DELEGPURGE.encode(dst);
                status.encode(dst);
            }
            NfsResop4::SetClientId(status, res) => {
                OP_SETCLIENTID.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(r) = res {
                        r.clientid.encode(dst);
                        dst.extend_from_slice(&r.verifier);
                    }
                }
            }
            NfsResop4::SetClientIdConfirm(status) => {
                OP_SETCLIENTID_CONFIRM.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Renew(status) => {
                OP_RENEW.encode(dst);
                status.encode(dst);
            }
            NfsResop4::OpenConfirm(status, stateid) => {
                OP_OPEN_CONFIRM.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(s) = stateid {
                        s.encode(dst);
                    }
                }
            }
            NfsResop4::ReleaseLockowner(status) => {
                OP_RELEASE_LOCKOWNER.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Verify(status) => {
                OP_VERIFY.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Nverify(status) => {
                OP_NVERIFY.encode(dst);
                status.encode(dst);
            }
            NfsResop4::OpenDowngrade(status, stateid) => {
                OP_OPEN_DOWNGRADE.encode(dst);
                status.encode(dst);
                if *status == NfsStat4::Ok {
                    if let Some(s) = stateid {
                        s.encode(dst);
                    }
                }
            }
            NfsResop4::LayoutGet(status) => {
                OP_LAYOUTGET.encode(dst);
                status.encode(dst);
            }
            NfsResop4::LayoutReturn(status) => {
                OP_LAYOUTRETURN.encode(dst);
                status.encode(dst);
            }
            NfsResop4::LayoutCommit(status) => {
                OP_LAYOUTCOMMIT.encode(dst);
                status.encode(dst);
            }
            NfsResop4::GetDirDelegation(status) => {
                OP_GET_DIR_DELEGATION.encode(dst);
                status.encode(dst);
            }
            NfsResop4::WantDelegation(status) => {
                OP_WANT_DELEGATION.encode(dst);
                status.encode(dst);
            }
            NfsResop4::BackchannelCtl(status) => {
                OP_BACKCHANNEL_CTL.encode(dst);
                status.encode(dst);
            }
            NfsResop4::GetDeviceInfo(status) => {
                OP_GETDEVICEINFO.encode(dst);
                status.encode(dst);
            }
            NfsResop4::GetDeviceList(status) => {
                OP_GETDEVICELIST.encode(dst);
                status.encode(dst);
            }
            NfsResop4::SetSsv(status) => {
                OP_SET_SSV.encode(dst);
                status.encode(dst);
            }
            NfsResop4::Illegal(status) => {
                OP_ILLEGAL.encode(dst);
                status.encode(dst);
            }
        }
    }
}

// ===== Compound4Args decoding =====

impl Compound4Args {
    pub fn decode(src: &mut Bytes) -> XdrResult<Self> {
        let tag = String::decode(src)?;
        let minorversion = u32::decode(src)?;
        let count = u32::decode(src)? as usize;
        let mut argarray = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            argarray.push(decode_nfs_argop4(src)?);
        }
        Ok(Compound4Args { tag, minorversion, argarray })
    }
}

fn decode_nfs_argop4(src: &mut Bytes) -> XdrResult<NfsArgop4> {
    let opnum = u32::decode(src)?;
    match opnum {
        OP_ACCESS => {
            let access = u32::decode(src)?;
            Ok(NfsArgop4::Access(AccessArgs4 { access }))
        }
        OP_CLOSE => {
            let seqid = u32::decode(src)?;
            let open_stateid = Stateid4::decode(src)?;
            Ok(NfsArgop4::Close(CloseArgs4 { seqid, open_stateid }))
        }
        OP_COMMIT => {
            let offset = u64::decode(src)?;
            let count = u32::decode(src)?;
            Ok(NfsArgop4::Commit(CommitArgs4 { offset, count }))
        }
        OP_CREATE => {
            let type_val = u32::decode(src)?;
            let objtype = match type_val {
                5 => {  // NF4LNK
                    let linkdata = String::decode(src)?;
                    Createtype4::Link(linkdata)
                }
                3 => {  // NF4BLK
                    let s1 = u32::decode(src)?;
                    let s2 = u32::decode(src)?;
                    Createtype4::Blk(Specdata4 { specdata1: s1, specdata2: s2 })
                }
                4 => {  // NF4CHR
                    let s1 = u32::decode(src)?;
                    let s2 = u32::decode(src)?;
                    Createtype4::Chr(Specdata4 { specdata1: s1, specdata2: s2 })
                }
                6 => Createtype4::Sock,
                7 => Createtype4::Fifo,
                2 => Createtype4::Dir,
                _ => return Err(XdrError::InvalidEnum(type_val)),
            };
            let objname = String::decode(src)?;
            let createattrs = Fattr4::decode(src)?;
            Ok(NfsArgop4::Create(CreateArgs4 { objtype, objname, createattrs }))
        }
        OP_GETATTR => {
            let attr_request = Bitmap4::decode(src)?;
            Ok(NfsArgop4::Getattr(GetattrArgs4 { attr_request }))
        }
        OP_GETFH => Ok(NfsArgop4::Getfh),
        OP_LINK => {
            let newname = String::decode(src)?;
            Ok(NfsArgop4::Link(LinkArgs4 { newname }))
        }
        OP_LOOKUP => {
            let objname = String::decode(src)?;
            Ok(NfsArgop4::Lookup(LookupArgs4 { objname }))
        }
        OP_LOOKUPP => Ok(NfsArgop4::Lookupp),
        OP_OPEN => {
            let seqid = u32::decode(src)?;
            let share_access = u32::decode(src)?;
            let share_deny = u32::decode(src)?;
            let owner = StateOwner4::decode(src)?;
            // openflag4
            let opentype = u32::decode(src)?;
            let openhow = if opentype == 1 {
                // OPEN4_CREATE
                let createmode = u32::decode(src)?;
                let how = match createmode {
                    0 => { // UNCHECKED4
                        let attrs = Fattr4::decode(src)?;
                        Createhow4::Unchecked(attrs)
                    }
                    1 => { // GUARDED4
                        let attrs = Fattr4::decode(src)?;
                        Createhow4::Guarded(attrs)
                    }
                    2 => { // EXCLUSIVE4
                        let vdata = decode_fixed_opaque(src, 8)?;
                        let mut v = [0u8; 8];
                        v.copy_from_slice(&vdata);
                        Createhow4::Exclusive(v)
                    }
                    3 => { // EXCLUSIVE4_1
                        let vdata = decode_fixed_opaque(src, 8)?;
                        let mut v = [0u8; 8];
                        v.copy_from_slice(&vdata);
                        let attrs = Fattr4::decode(src)?;
                        Createhow4::Exclusive4_1 { verifier: v, attrs }
                    }
                    _ => return Err(XdrError::InvalidEnum(createmode)),
                };
                Openflag4::Create(how)
            } else {
                Openflag4::NoCreate
            };
            // open_claim4
            let claim_type = u32::decode(src)?;
            let claim = match claim_type {
                0 => { // CLAIM_NULL
                    let file = String::decode(src)?;
                    OpenClaim4::Null(file)
                }
                1 => { // CLAIM_PREVIOUS
                    let dt = u32::decode(src)?;
                    OpenClaim4::Previous(dt)
                }
                2 => { // CLAIM_DELEGATE_CUR
                    let ds = Stateid4::decode(src)?;
                    let file = String::decode(src)?;
                    OpenClaim4::DelegateCur { delegate_stateid: ds, file }
                }
                3 => { // CLAIM_DELEGATE_PREV
                    let file = String::decode(src)?;
                    OpenClaim4::DelegatePrev(file)
                }
                4 => OpenClaim4::Fh,
                5 => {
                    let ds = Stateid4::decode(src)?;
                    OpenClaim4::DelegCurFh(ds)
                }
                6 => OpenClaim4::DelegPrevFh,
                _ => return Err(XdrError::InvalidEnum(claim_type)),
            };
            Ok(NfsArgop4::Open(OpenArgs4 {
                seqid,
                share_access,
                share_deny,
                owner,
                openhow,
                claim,
            }))
        }
        OP_OPEN_CONFIRM => {
            let open_stateid = Stateid4::decode(src)?;
            let seqid = u32::decode(src)?;
            Ok(NfsArgop4::OpenConfirm(OpenConfirmArgs4 { open_stateid, seqid }))
        }
        OP_OPEN_DOWNGRADE => {
            let open_stateid = Stateid4::decode(src)?;
            let seqid = u32::decode(src)?;
            let share_access = u32::decode(src)?;
            let share_deny = u32::decode(src)?;
            Ok(NfsArgop4::OpenDowngrade(OpenDowngradeArgs4 { open_stateid, seqid, share_access, share_deny }))
        }
        OP_PUTFH => {
            let object = NfsFh4::decode(src)?;
            Ok(NfsArgop4::Putfh(PutfhArgs4 { object }))
        }
        OP_PUTPUBFH => Ok(NfsArgop4::Putpubfh),
        OP_PUTROOTFH => Ok(NfsArgop4::Putrootfh),
        OP_READ => {
            let stateid = Stateid4::decode(src)?;
            let offset = u64::decode(src)?;
            let count = u32::decode(src)?;
            Ok(NfsArgop4::Read(ReadArgs4 { stateid, offset, count }))
        }
        OP_READDIR => {
            let cookie = u64::decode(src)?;
            let cvdata = decode_fixed_opaque(src, 8)?;
            let mut cookieverf = [0u8; 8];
            cookieverf.copy_from_slice(&cvdata);
            let dircount = u32::decode(src)?;
            let maxcount = u32::decode(src)?;
            let attr_request = Bitmap4::decode(src)?;
            Ok(NfsArgop4::Readdir(ReaddirArgs4 {
                cookie, cookieverf, dircount, maxcount, attr_request,
            }))
        }
        OP_READLINK => Ok(NfsArgop4::Readlink),
        OP_REMOVE => {
            let target = String::decode(src)?;
            Ok(NfsArgop4::Remove(RemoveArgs4 { target }))
        }
        OP_RENAME => {
            let oldname = String::decode(src)?;
            let newname = String::decode(src)?;
            Ok(NfsArgop4::Rename(RenameArgs4 { oldname, newname }))
        }
        OP_RESTOREFH => Ok(NfsArgop4::Restorefh),
        OP_SAVEFH => Ok(NfsArgop4::Savefh),
        OP_SECINFO => {
            let name = String::decode(src)?;
            Ok(NfsArgop4::Secinfo(SecinfoArgs4 { name }))
        }
        OP_SETATTR => {
            let stateid = Stateid4::decode(src)?;
            let obj_attributes = Fattr4::decode(src)?;
            Ok(NfsArgop4::Setattr(SetattrArgs4 { stateid, obj_attributes }))
        }
        OP_WRITE => {
            let stateid = Stateid4::decode(src)?;
            let offset = u64::decode(src)?;
            let stable = u32::decode(src)?;
            let data = decode_opaque(src)?;
            Ok(NfsArgop4::Write(WriteArgs4 { stateid, offset, stable, data }))
        }
        OP_EXCHANGE_ID => {
            let clientowner = ClientOwner4::decode(src)?;
            let flags = u32::decode(src)?;
            let sp_type = u32::decode(src)?;
            let state_protect = match sp_type {
                0 => StateProtect4A::None,
                1 => {
                    let enforce = Bitmap4::decode(src)?;
                    let allow = Bitmap4::decode(src)?;
                    StateProtect4A::MachCred { ops: StateProt4MachOps { enforce, allow } }
                }
                _ => {
                    // Skip SSV and others
                    return Err(XdrError::InvalidEnum(sp_type));
                }
            };
            let client_impl_id = decode_list(src)?;
            Ok(NfsArgop4::ExchangeId(ExchangeIdArgs4 {
                clientowner, flags, state_protect, client_impl_id,
            }))
        }
        OP_CREATE_SESSION => {
            let clientid = u64::decode(src)?;
            let sequence = u32::decode(src)?;
            let flags = u32::decode(src)?;
            let fore_chan_attrs = ChannelAttrs4::decode(src)?;
            let back_chan_attrs = ChannelAttrs4::decode(src)?;
            let cb_program = u32::decode(src)?;
            let sec_parms = decode_list(src)?;
            Ok(NfsArgop4::CreateSession(CreateSessionArgs4 {
                clientid, sequence, flags, fore_chan_attrs, back_chan_attrs,
                cb_program, sec_parms,
            }))
        }
        OP_DESTROY_SESSION => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            Ok(NfsArgop4::DestroySession(DestroySessionArgs4 { sessionid }))
        }
        OP_SEQUENCE => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            let sequenceid = u32::decode(src)?;
            let slotid = u32::decode(src)?;
            let highest_slotid = u32::decode(src)?;
            let cachethis = bool::decode(src)?;
            Ok(NfsArgop4::Sequence(SequenceArgs4 {
                sessionid, sequenceid, slotid, highest_slotid, cachethis,
            }))
        }
        OP_RECLAIM_COMPLETE => {
            let one_fs = bool::decode(src)?;
            Ok(NfsArgop4::ReclaimComplete(ReclaimCompleteArgs4 { one_fs }))
        }
        OP_DESTROY_CLIENTID => {
            let clientid = u64::decode(src)?;
            Ok(NfsArgop4::DestroyClientid(DestroyClientidArgs4 { clientid }))
        }
        OP_BIND_CONN_TO_SESSION => {
            let sid = decode_fixed_opaque(src, 16)?;
            let mut sessionid = [0u8; 16];
            sessionid.copy_from_slice(&sid);
            let dir = u32::decode(src)?;
            let use_conn_in_rdma_mode = bool::decode(src)?;
            Ok(NfsArgop4::BindConnToSession(BindConnToSessionArgs4 {
                sessionid, dir, use_conn_in_rdma_mode,
            }))
        }
        OP_SECINFO_NO_NAME => {
            let style = u32::decode(src)?;
            Ok(NfsArgop4::SecInfoNoName(style))
        }
        OP_FREE_STATEID => {
            let stateid = Stateid4::decode(src)?;
            Ok(NfsArgop4::FreeStateid(FreeStateidArgs4 { stateid }))
        }
        OP_TEST_STATEID => {
            let stateids = decode_list(src)?;
            Ok(NfsArgop4::TestStateid(TestStateidArgs4 { stateids }))
        }
        OP_DELEGRETURN => {
            let stateid = Stateid4::decode(src)?;
            Ok(NfsArgop4::DelegReturn(DelegReturnArgs4 { stateid }))
        }
        OP_SETCLIENTID => {
            let vdata = decode_fixed_opaque(src, 8)?;
            let mut verifier = [0u8; 8];
            verifier.copy_from_slice(&vdata);
            let ownerid = decode_opaque(src)?;
            let client = ClientOwner4 { verifier, ownerid };
            // callback: cb_program + cb_location (netaddr4 = netid + addr)
            let cb_program = u32::decode(src)?;
            let cb_netid = String::decode(src)?;
            let cb_addr = String::decode(src)?;
            let callback = NfsClientCallback4 {
                cb_program,
                cb_location: format!("{cb_netid}://{cb_addr}"),
            };
            let callback_ident = u32::decode(src)?;
            Ok(NfsArgop4::SetClientId(SetClientIdArgs4 { client, callback, callback_ident }))
        }
        OP_SETCLIENTID_CONFIRM => {
            let clientid = u64::decode(src)?;
            let vdata = decode_fixed_opaque(src, 8)?;
            let mut verifier = [0u8; 8];
            verifier.copy_from_slice(&vdata);
            Ok(NfsArgop4::SetClientIdConfirm(SetClientIdConfirmArgs4 { clientid, verifier }))
        }
        OP_RENEW => {
            let clientid = u64::decode(src)?;
            Ok(NfsArgop4::Renew(clientid))
        }
        OP_RELEASE_LOCKOWNER => {
            // lock_owner: clientid + owner
            let _clientid = u64::decode(src)?;
            let _owner = decode_opaque(src)?;
            Ok(NfsArgop4::ReleaseLockowner)
        }
        OP_LOCK => {
            let locktype = NfsLockType4::decode(src)?;
            let reclaim = bool::decode(src)?;
            let offset = u64::decode(src)?;
            let length = u64::decode(src)?;
            let new_lock_owner = bool::decode(src)?;
            let locker = if new_lock_owner {
                let open_seqid = u32::decode(src)?;
                let open_stateid = Stateid4::decode(src)?;
                let lock_seqid = u32::decode(src)?;
                let clientid = u64::decode(src)?;
                let owner = decode_opaque(src)?;
                Locker4::NewLockOwner(OpenToLockOwner4 {
                    open_seqid,
                    open_stateid,
                    lock_seqid,
                    lock_owner: StateOwner4 { clientid, owner },
                })
            } else {
                let lock_stateid = Stateid4::decode(src)?;
                let lock_seqid = u32::decode(src)?;
                Locker4::ExistingLockOwner(ExistLockOwner4 {
                    lock_stateid,
                    lock_seqid,
                })
            };
            Ok(NfsArgop4::Lock(LockArgs4 { locktype, reclaim, offset, length, locker }))
        }
        OP_LOCKT => {
            let locktype = NfsLockType4::decode(src)?;
            let offset = u64::decode(src)?;
            let length = u64::decode(src)?;
            let clientid = u64::decode(src)?;
            let owner = decode_opaque(src)?;
            Ok(NfsArgop4::Lockt(LocktArgs4 {
                locktype, offset, length,
                owner: StateOwner4 { clientid, owner },
            }))
        }
        OP_LOCKU => {
            let locktype = NfsLockType4::decode(src)?;
            let seqid = u32::decode(src)?;
            let lock_stateid = Stateid4::decode(src)?;
            let offset = u64::decode(src)?;
            let length = u64::decode(src)?;
            Ok(NfsArgop4::Locku(LockuArgs4 { locktype, seqid, lock_stateid, offset, length }))
        }
        OP_OPENATTR => {
            let createdir = bool::decode(src)?;
            Ok(NfsArgop4::OpenAttr(OpenAttrArgs4 { createdir }))
        }
        OP_DELEGPURGE => {
            let _clientid = u64::decode(src)?;
            Ok(NfsArgop4::DelegPurge)
        }
        OP_VERIFY => {
            let attrs = Fattr4::decode(src)?;
            Ok(NfsArgop4::Verify(attrs))
        }
        OP_NVERIFY => {
            let attrs = Fattr4::decode(src)?;
            Ok(NfsArgop4::Nverify(attrs))
        }
        OP_BACKCHANNEL_CTL => {
            // cb_program(u32) + sec_parms(list of callback_sec_parms4)
            let _cb_program = u32::decode(src)?;
            let count = u32::decode(src)?;
            for _ in 0..count {
                let flavor = u32::decode(src)?;
                match flavor {
                    0 => {} // AUTH_NONE
                    1 => {  // AUTH_SYS
                        let _stamp = u32::decode(src)?;
                        let _name = String::decode(src)?;
                        let _uid = u32::decode(src)?;
                        let _gid = u32::decode(src)?;
                        let _gids = decode_list::<u32>(src)?;
                    }
                    6 => { // RPCSEC_GSS
                        let _gcbp_service = u32::decode(src)?;
                        let _gss_handle = decode_opaque(src)?;
                        let _gcbp_handle_from_server = decode_opaque(src)?;
                        let _gcbp_handle_from_client = decode_opaque(src)?;
                    }
                    _ => {}
                }
            }
            Ok(NfsArgop4::BackchannelCtl)
        }
        OP_GET_DIR_DELEGATION => {
            // Signal deleg_avail; just skip the args
            let _signal = bool::decode(src)?;
            let _notif_types = Bitmap4::decode(src)?;
            let _child_attr_delay = u64::decode(src)?; // nfstime4
            let _ = u32::decode(src)?;
            let _dir_attr_delay = u64::decode(src)?;
            let _ = u32::decode(src)?;
            let _child_attrs = Bitmap4::decode(src)?;
            let _dir_attrs = Bitmap4::decode(src)?;
            Ok(NfsArgop4::GetDirDelegation)
        }
        OP_GETDEVICEINFO => {
            let _deviceid = decode_fixed_opaque(src, 16)?;
            let _layout_type = u32::decode(src)?;
            let _maxcount = u32::decode(src)?;
            let _notif_types = Bitmap4::decode(src)?;
            Ok(NfsArgop4::GetDeviceInfo)
        }
        OP_GETDEVICELIST => {
            let _layout_type = u32::decode(src)?;
            let _maxdevices = u32::decode(src)?;
            let _cookie = u64::decode(src)?;
            let _vdata = decode_fixed_opaque(src, 8)?;
            Ok(NfsArgop4::GetDeviceList)
        }
        OP_LAYOUTCOMMIT => {
            let _offset = u64::decode(src)?;
            let _length = u64::decode(src)?;
            let _reclaim = bool::decode(src)?;
            let _stateid = Stateid4::decode(src)?;
            let _new_offset = bool::decode(src)?;
            if _new_offset {
                let _last_byte = u64::decode(src)?;
            }
            let _time_modify = bool::decode(src)?;
            if _time_modify {
                let _t = NfsTime4::decode(src)?;
            }
            let _layout_type = u32::decode(src)?;
            let _layoutupdate = decode_opaque(src)?;
            Ok(NfsArgop4::LayoutCommit)
        }
        OP_LAYOUTGET => {
            let _signal = bool::decode(src)?;
            let _layout_type = u32::decode(src)?;
            let _iomode = u32::decode(src)?;
            let _offset = u64::decode(src)?;
            let _length = u64::decode(src)?;
            let _minlength = u64::decode(src)?;
            let _stateid = Stateid4::decode(src)?;
            let _maxcount = u32::decode(src)?;
            Ok(NfsArgop4::LayoutGet)
        }
        OP_LAYOUTRETURN => {
            let _reclaim = bool::decode(src)?;
            let _layout_type = u32::decode(src)?;
            let _iomode = u32::decode(src)?;
            let _return_type = u32::decode(src)?;
            match _return_type {
                1 => { // LAYOUTRETURN4_FILE
                    let _offset = u64::decode(src)?;
                    let _length = u64::decode(src)?;
                    let _stateid = Stateid4::decode(src)?;
                    let _body = decode_opaque(src)?;
                }
                2 | 3 => {} // LAYOUTRETURN4_FSID / LAYOUTRETURN4_ALL
                _ => {}
            }
            Ok(NfsArgop4::LayoutReturn)
        }
        OP_SET_SSV => {
            let _ssv = decode_opaque(src)?;
            let _digest = decode_opaque(src)?;
            Ok(NfsArgop4::SetSsv)
        }
        OP_WANT_DELEGATION => {
            let _want = u32::decode(src)?;
            // want_signal_deleg_avail: union on want
            let _claim_type = u32::decode(src)?;
            match _claim_type {
                0 => {} // CLAIM_NULL
                3 => { // CLAIM_DELEGATE_PREV
                    let _file = String::decode(src)?;
                }
                _ => {}
            }
            Ok(NfsArgop4::WantDelegation)
        }
        _ => {
            // Unknown op - return Illegal
            Ok(NfsArgop4::Illegal)
        }
    }
}

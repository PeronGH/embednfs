use bytes::{Bytes, BytesMut};

use crate::xdr::*;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NfsFh4(pub Vec<u8>);

impl XdrEncode for NfsFh4 {
    fn encode(&self, dst: &mut BytesMut) {
        encode_opaque(dst, &self.0);
    }
}

impl XdrDecode for NfsFh4 {
    fn decode(src: &mut Bytes) -> XdrResult<Self> {
        Ok(NfsFh4(decode_opaque_max(src, 128)?))
    }
}

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
    SequencePos = 10064,
    ReqTooBig = 10065,
    RepTooBig = 10066,
    RepTooBigToCache = 10067,
    RetryUncachedRep = 10068,
    UnsafeCompound = 10069,
    TooManyOps = 10070,
    OpNotInSession = 10071,
    HashAlgUnsupp = 10072,
    ClientidBusy = 10074,
    PnfsIoHole = 10075,
    SeqFalseRetry = 10076,
    BadHighSlot = 10077,
    DeadSession = 10078,
    EncrAlgUnsupp = 10079,
    PnfsNoLayout = 10080,
    NotOnlyOp = 10081,
    WrongCred = 10082,
    WrongType = 10083,
    DirDelegUnavail = 10084,
    RejectDeleg = 10085,
    ReturnConflict = 10086,
    DelegRevoked = 10087,
}

impl NfsStat4 {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::Noent,
            5 => Self::Io,
            6 => Self::Nxio,
            13 => Self::Access,
            17 => Self::Exist,
            18 => Self::Xdev,
            20 => Self::Notdir,
            21 => Self::Isdir,
            22 => Self::Inval,
            27 => Self::Fbig,
            28 => Self::Nospc,
            30 => Self::Rofs,
            31 => Self::Mlink,
            63 => Self::Nametoolong,
            66 => Self::Notempty,
            69 => Self::Dquot,
            70 => Self::Stale,
            10001 => Self::Badhandle,
            10003 => Self::BadCookie,
            10004 => Self::Notsupp,
            10005 => Self::Toosmall,
            10006 => Self::Serverfault,
            10007 => Self::Badtype,
            10008 => Self::Delay,
            10009 => Self::Same,
            10010 => Self::Denied,
            10011 => Self::Expired,
            10012 => Self::Locked,
            10013 => Self::Grace,
            10014 => Self::Fhexpired,
            10015 => Self::ShareDenied,
            10016 => Self::WrongSec,
            10017 => Self::ClidInuse,
            10019 => Self::Moved,
            10020 => Self::Nofilehandle,
            10021 => Self::MinorVersMismatch,
            10022 => Self::StaleClientid,
            10023 => Self::StaleStateid,
            10024 => Self::OldStateid,
            10025 => Self::BadStateid,
            10026 => Self::BadSeqid,
            10027 => Self::NotSame,
            10028 => Self::LockRange,
            10029 => Self::Symlink,
            10030 => Self::Restorefh,
            10031 => Self::LeaseMoved,
            10032 => Self::AttrNotsupp,
            10033 => Self::NoGrace,
            10034 => Self::ReclaimBad,
            10035 => Self::ReclaimConflict,
            10036 => Self::BadXdr,
            10037 => Self::LocksHeld,
            10038 => Self::Openmode,
            10039 => Self::BadOwner,
            10040 => Self::Badchar,
            10041 => Self::Badname,
            10042 => Self::BadRange,
            10043 => Self::LockNotsupp,
            10044 => Self::OpIllegal,
            10045 => Self::Deadlock,
            10046 => Self::FileOpen,
            10047 => Self::AdminRevoked,
            10048 => Self::CbPathDown,
            10049 => Self::BadIomode,
            10050 => Self::BadLayout,
            10051 => Self::BadSessionDigest,
            10052 => Self::BadSession,
            10053 => Self::BadSlot,
            10054 => Self::CompleteAlready,
            10055 => Self::ConnNotBoundToSession,
            10056 => Self::DelegAlreadyWanted,
            10057 => Self::BackChanBusy,
            10058 => Self::LayoutTrylater,
            10059 => Self::LayoutUnavailable,
            10060 => Self::NomatchingLayout,
            10061 => Self::RecallConflict,
            10062 => Self::UnknownLayouttype,
            10063 => Self::SeqMisordered,
            10064 => Self::SequencePos,
            10065 => Self::ReqTooBig,
            10066 => Self::RepTooBig,
            10067 => Self::RepTooBigToCache,
            10068 => Self::RetryUncachedRep,
            10069 => Self::UnsafeCompound,
            10070 => Self::TooManyOps,
            10071 => Self::OpNotInSession,
            10072 => Self::HashAlgUnsupp,
            10074 => Self::ClientidBusy,
            10075 => Self::PnfsIoHole,
            10076 => Self::SeqFalseRetry,
            10077 => Self::BadHighSlot,
            10078 => Self::DeadSession,
            10079 => Self::EncrAlgUnsupp,
            10080 => Self::PnfsNoLayout,
            10081 => Self::NotOnlyOp,
            10082 => Self::WrongCred,
            10083 => Self::WrongType,
            10084 => Self::DirDelegUnavail,
            10085 => Self::RejectDeleg,
            10086 => Self::ReturnConflict,
            10087 => Self::DelegRevoked,
            _ => Self::Serverfault,
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
        Ok(Self::from_u32(u32::decode(src)?))
    }
}

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
            1 => Ok(Self::Reg),
            2 => Ok(Self::Dir),
            3 => Ok(Self::Blk),
            4 => Ok(Self::Chr),
            5 => Ok(Self::Lnk),
            6 => Ok(Self::Sock),
            7 => Ok(Self::Fifo),
            8 => Ok(Self::AttrDir),
            9 => Ok(Self::NamedAttr),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

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
        Ok(NfsTime4 {
            seconds: i64::decode(src)?,
            nseconds: u32::decode(src)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Stateid4 {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl Stateid4 {
    pub const ANONYMOUS: Stateid4 = Stateid4 {
        seqid: 0,
        other: [0; 12],
    };
    pub const CURRENT: Stateid4 = Stateid4 {
        seqid: 1,
        other: [0xff; 12],
    };
    pub const BYPASS: Stateid4 = Stateid4 {
        seqid: 0xffff_ffff,
        other: [0xff; 12],
    };
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

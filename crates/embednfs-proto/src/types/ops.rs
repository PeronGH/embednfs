use bytes::{Bytes, BytesMut};

use crate::xdr::*;

use super::*;

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
pub const OP_OPEN_CONFIRM: u32 = 20;
pub const OP_OPEN_DOWNGRADE: u32 = 21;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTPUBFH: u32 = 23;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30;
pub const OP_RESTOREFH: u32 = 31;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SECINFO: u32 = 33;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35;
pub const OP_SETCLIENTID_CONFIRM: u32 = 36;
pub const OP_VERIFY: u32 = 37;
pub const OP_WRITE: u32 = 38;
pub const OP_RELEASE_LOCKOWNER: u32 = 39;
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
    OpenConfirm(OpenConfirmArgs4),
    Renew(RenewArgs4),
    ReleaseLockowner(ReleaseLockOwnerArgs4),
    Lock(LockArgs4),
    Lockt(LocktArgs4),
    Locku(LockuArgs4),
    OpenAttr(OpenAttrArgs4),
    DelegPurge,
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

#[derive(Debug)]
pub struct SetClientIdArgs4 {
    pub client: ClientOwner4,
    pub callback: CbClient4,
    pub callback_ident: u32,
}

#[derive(Debug)]
pub struct CbClient4 {
    pub cb_program: u32,
    pub cb_location: Netaddr4,
}

#[derive(Debug)]
pub struct Netaddr4 {
    pub netid: String,
    pub addr: String,
}

#[derive(Debug)]
pub struct SetClientIdConfirmArgs4 {
    pub clientid: Clientid4,
    pub setclientid_confirm: Verifier4,
}

#[derive(Debug)]
pub struct OpenConfirmArgs4 {
    pub open_stateid: Stateid4,
    pub seqid: Seqid4,
}

#[derive(Debug)]
pub struct RenewArgs4 {
    pub clientid: Clientid4,
}

#[derive(Debug)]
pub struct ReleaseLockOwnerArgs4 {
    pub lock_owner: StateOwner4,
}

#[derive(Debug)]
pub struct SetClientIdRes4 {
    pub clientid: Clientid4,
    pub setclientid_confirm: Verifier4,
}

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
        Ok(StateOwner4 {
            clientid: u64::decode(src)?,
            owner: decode_opaque(src)?,
        })
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
    pub stable: u32,
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
        Ok(ClientOwner4 {
            verifier,
            ownerid: decode_opaque(src)?,
        })
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
        Ok(NfsImplId4 {
            domain: String::decode(src)?,
            name: String::decode(src)?,
            date: NfsTime4::decode(src)?,
        })
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
        match u32::decode(src)? {
            1 => Ok(Self::ReadLt),
            2 => Ok(Self::WriteLt),
            3 => Ok(Self::ReadwLt),
            4 => Ok(Self::WritewLt),
            v => Err(XdrError::InvalidEnum(v)),
        }
    }
}

impl XdrEncode for NfsLockType4 {
    fn encode(&self, dst: &mut BytesMut) {
        (*self as u32).encode(dst);
    }
}

#[derive(Debug)]
pub struct OpenToLockOwner4 {
    pub open_seqid: Seqid4,
    pub open_stateid: Stateid4,
    pub lock_seqid: Seqid4,
    pub lock_owner: StateOwner4,
}

#[derive(Debug)]
pub struct ExistLockOwner4 {
    pub lock_stateid: Stateid4,
    pub lock_seqid: Seqid4,
}

#[derive(Debug)]
pub enum Locker4 {
    NewLockOwner(OpenToLockOwner4),
    ExistingLockOwner(ExistLockOwner4),
}

#[derive(Debug)]
pub struct LockArgs4 {
    pub locktype: NfsLockType4,
    pub reclaim: bool,
    pub offset: Offset4,
    pub length: Length4,
    pub locker: Locker4,
}

#[derive(Debug)]
pub struct LocktArgs4 {
    pub locktype: NfsLockType4,
    pub offset: Offset4,
    pub length: Length4,
    pub owner: StateOwner4,
}

#[derive(Debug)]
pub struct LockuArgs4 {
    pub locktype: NfsLockType4,
    pub seqid: Seqid4,
    pub lock_stateid: Stateid4,
    pub offset: Offset4,
    pub length: Length4,
}

#[derive(Debug)]
pub struct LockDenied4 {
    pub offset: Offset4,
    pub length: Length4,
    pub locktype: NfsLockType4,
    pub owner: StateOwner4,
}

#[derive(Debug)]
pub struct OpenAttrArgs4 {
    pub createdir: bool,
}

#[derive(Debug)]
pub struct Compound4Args {
    pub tag: String,
    pub minorversion: u32,
    pub argarray: Vec<NfsArgop4>,
}

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

#[derive(Debug)]
pub enum NfsResop4 {
    Access(NfsStat4, u32, u32),
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
    SetClientId(NfsStat4, Option<SetClientIdRes4>),
    SetClientIdConfirm(NfsStat4),
    OpenConfirm(NfsStat4, Option<Stateid4>),
    Renew(NfsStat4),
    ReleaseLockowner(NfsStat4),
    Lock(NfsStat4, Option<Stateid4>, Option<LockDenied4>),
    Lockt(NfsStat4, Option<LockDenied4>),
    Locku(NfsStat4, Option<Stateid4>),
    OpenAttr(NfsStat4),
    DelegPurge(NfsStat4),
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
    pub committed: u32,
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

#[derive(Debug, Clone)]
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
}

impl XdrEncode for SecinfoEntry4 {
    fn encode(&self, dst: &mut BytesMut) {
        self.flavor.encode(dst);
    }
}

pub const OPEN4_RESULT_CONFIRM: u32 = 0x00000002;
pub const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x00000004;
pub const OPEN4_RESULT_PRESERVE_UNLINKED: u32 = 0x00000008;
pub const OPEN4_RESULT_MAY_NOTIFY_LOCK: u32 = 0x00000020;

pub const UNSTABLE4: u32 = 0;
pub const DATA_SYNC4: u32 = 1;
pub const FILE_SYNC4: u32 = 2;

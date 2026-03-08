use embednfs_proto::xdr::xdr_pad;
use embednfs_proto::*;

pub(super) fn xdr_opaque_len(len: usize) -> usize {
    4 + len + xdr_pad(len)
}

pub(super) fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn xdr_bitmap4_len(bitmap: &Bitmap4) -> usize {
    4 + (bitmap.0.len() * 4)
}

fn xdr_fattr4_len(fattr: &Fattr4) -> usize {
    xdr_bitmap4_len(&fattr.attrmask) + xdr_opaque_len(fattr.attr_vals.len())
}

pub(super) fn readdir_dir_info_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len())
}

pub(super) fn readdir_entry_len(entry: &Entry4) -> usize {
    8 + xdr_opaque_len(entry.name.len()) + xdr_fattr4_len(&entry.attrs)
}

pub(super) fn readdir_entry_list_item_len(entry: &Entry4) -> usize {
    4 + readdir_entry_len(entry)
}

pub(super) fn readdir_resok_len(entries: &[Entry4], _eof: bool) -> usize {
    8 + entries.iter().map(readdir_entry_list_item_len).sum::<usize>() + 4 + 4
}

pub(super) fn allows_compound_without_sequence(op: &NfsArgop4) -> bool {
    matches!(
        op,
        NfsArgop4::ExchangeId(_)
            | NfsArgop4::CreateSession(_)
            | NfsArgop4::DestroySession(_)
            | NfsArgop4::DestroyClientid(_)
            | NfsArgop4::BindConnToSession(_)
    )
}

pub(super) fn error_res_for_op(op: &NfsArgop4, status: NfsStat4) -> NfsResop4 {
    match op {
        NfsArgop4::Access(_) => NfsResop4::Access(status, 0, 0),
        NfsArgop4::Close(_) => NfsResop4::Close(status, Stateid4::default()),
        NfsArgop4::Commit(_) => NfsResop4::Commit(status, [0u8; 8]),
        NfsArgop4::Create(_) => NfsResop4::Create(status, None, Bitmap4::new()),
        NfsArgop4::Getattr(_) => NfsResop4::Getattr(status, None),
        NfsArgop4::Getfh => NfsResop4::Getfh(status, None),
        NfsArgop4::Link(_) => NfsResop4::Link(status, None),
        NfsArgop4::Lookup(_) => NfsResop4::Lookup(status),
        NfsArgop4::Lookupp => NfsResop4::Lookupp(status),
        NfsArgop4::Open(_) => NfsResop4::Open(status, None),
        NfsArgop4::Putfh(_) => NfsResop4::Putfh(status),
        NfsArgop4::Putpubfh => NfsResop4::Putpubfh(status),
        NfsArgop4::Putrootfh => NfsResop4::Putrootfh(status),
        NfsArgop4::Read(_) => NfsResop4::Read(status, None),
        NfsArgop4::Readdir(_) => NfsResop4::Readdir(status, None),
        NfsArgop4::Readlink => NfsResop4::Readlink(status, None),
        NfsArgop4::Remove(_) => NfsResop4::Remove(status, None),
        NfsArgop4::Rename(_) => NfsResop4::Rename(status, None, None),
        NfsArgop4::Restorefh => NfsResop4::Restorefh(status),
        NfsArgop4::Savefh => NfsResop4::Savefh(status),
        NfsArgop4::Secinfo(_) => NfsResop4::Secinfo(status, vec![]),
        NfsArgop4::Setattr(_) => NfsResop4::Setattr(status, Bitmap4::new()),
        NfsArgop4::Write(_) => NfsResop4::Write(status, None),
        NfsArgop4::ExchangeId(_) => NfsResop4::ExchangeId(status, None),
        NfsArgop4::CreateSession(_) => NfsResop4::CreateSession(status, None),
        NfsArgop4::DestroySession(_) => NfsResop4::DestroySession(status),
        NfsArgop4::Sequence(_) => NfsResop4::Sequence(status, None),
        NfsArgop4::ReclaimComplete(_) => NfsResop4::ReclaimComplete(status),
        NfsArgop4::DestroyClientid(_) => NfsResop4::DestroyClientid(status),
        NfsArgop4::BindConnToSession(_) => NfsResop4::BindConnToSession(status, None),
        NfsArgop4::SecInfoNoName(_) => NfsResop4::SecInfoNoName(status, vec![]),
        NfsArgop4::FreeStateid(_) => NfsResop4::FreeStateid(status),
        NfsArgop4::TestStateid(_) => NfsResop4::TestStateid(status, vec![]),
        NfsArgop4::DelegReturn(_) => NfsResop4::DelegReturn(status),
        NfsArgop4::MustNotImplement(op) => NfsResop4::MustNotImplement(*op, status),
        NfsArgop4::Lock(_) => NfsResop4::Lock(status, None, None),
        NfsArgop4::Lockt(_) => NfsResop4::Lockt(status, None),
        NfsArgop4::Locku(_) => NfsResop4::Locku(status, None),
        NfsArgop4::OpenAttr(_) => NfsResop4::OpenAttr(status),
        NfsArgop4::DelegPurge => NfsResop4::DelegPurge(status),
        NfsArgop4::Verify(_) => NfsResop4::Verify(status),
        NfsArgop4::Nverify(_) => NfsResop4::Nverify(status),
        NfsArgop4::OpenDowngrade(_) => NfsResop4::OpenDowngrade(status, None),
        NfsArgop4::LayoutGet => NfsResop4::LayoutGet(status),
        NfsArgop4::LayoutReturn => NfsResop4::LayoutReturn(status),
        NfsArgop4::LayoutCommit => NfsResop4::LayoutCommit(status),
        NfsArgop4::GetDirDelegation => NfsResop4::GetDirDelegation(status),
        NfsArgop4::WantDelegation => NfsResop4::WantDelegation(status),
        NfsArgop4::BackchannelCtl => NfsResop4::BackchannelCtl(status),
        NfsArgop4::GetDeviceInfo => NfsResop4::GetDeviceInfo(status),
        NfsArgop4::GetDeviceList => NfsResop4::GetDeviceList(status),
        NfsArgop4::SetSsv => NfsResop4::SetSsv(status),
        NfsArgop4::Illegal => NfsResop4::Illegal(status),
    }
}

pub(super) fn argop_name(op: &NfsArgop4) -> &'static str {
    match op {
        NfsArgop4::Access(_) => "ACCESS",
        NfsArgop4::Close(_) => "CLOSE",
        NfsArgop4::Commit(_) => "COMMIT",
        NfsArgop4::Create(_) => "CREATE",
        NfsArgop4::Getattr(_) => "GETATTR",
        NfsArgop4::Getfh => "GETFH",
        NfsArgop4::Link(_) => "LINK",
        NfsArgop4::Lookup(_) => "LOOKUP",
        NfsArgop4::Lookupp => "LOOKUPP",
        NfsArgop4::Open(_) => "OPEN",
        NfsArgop4::Putfh(_) => "PUTFH",
        NfsArgop4::Putpubfh => "PUTPUBFH",
        NfsArgop4::Putrootfh => "PUTROOTFH",
        NfsArgop4::Read(_) => "READ",
        NfsArgop4::Readdir(_) => "READDIR",
        NfsArgop4::Readlink => "READLINK",
        NfsArgop4::Remove(_) => "REMOVE",
        NfsArgop4::Rename(_) => "RENAME",
        NfsArgop4::Restorefh => "RESTOREFH",
        NfsArgop4::Savefh => "SAVEFH",
        NfsArgop4::Secinfo(_) => "SECINFO",
        NfsArgop4::Setattr(_) => "SETATTR",
        NfsArgop4::Write(_) => "WRITE",
        NfsArgop4::ExchangeId(_) => "EXCHANGE_ID",
        NfsArgop4::CreateSession(_) => "CREATE_SESSION",
        NfsArgop4::DestroySession(_) => "DESTROY_SESSION",
        NfsArgop4::Sequence(_) => "SEQUENCE",
        NfsArgop4::ReclaimComplete(_) => "RECLAIM_COMPLETE",
        NfsArgop4::DestroyClientid(_) => "DESTROY_CLIENTID",
        NfsArgop4::BindConnToSession(_) => "BIND_CONN_TO_SESSION",
        NfsArgop4::SecInfoNoName(_) => "SECINFO_NO_NAME",
        NfsArgop4::FreeStateid(_) => "FREE_STATEID",
        NfsArgop4::TestStateid(_) => "TEST_STATEID",
        NfsArgop4::DelegReturn(_) => "DELEGRETURN",
        NfsArgop4::MustNotImplement(_) => "MUST_NOT_IMPLEMENT",
        NfsArgop4::Lock(_) => "LOCK",
        NfsArgop4::Lockt(_) => "LOCKT",
        NfsArgop4::Locku(_) => "LOCKU",
        NfsArgop4::OpenAttr(_) => "OPENATTR",
        NfsArgop4::DelegPurge => "DELEGPURGE",
        NfsArgop4::Verify(_) => "VERIFY",
        NfsArgop4::Nverify(_) => "NVERIFY",
        NfsArgop4::OpenDowngrade(_) => "OPEN_DOWNGRADE",
        NfsArgop4::LayoutGet => "LAYOUTGET",
        NfsArgop4::LayoutReturn => "LAYOUTRETURN",
        NfsArgop4::LayoutCommit => "LAYOUTCOMMIT",
        NfsArgop4::GetDirDelegation => "GET_DIR_DELEGATION",
        NfsArgop4::WantDelegation => "WANT_DELEGATION",
        NfsArgop4::BackchannelCtl => "BACKCHANNEL_CTL",
        NfsArgop4::GetDeviceInfo => "GETDEVICEINFO",
        NfsArgop4::GetDeviceList => "GETDEVICELIST",
        NfsArgop4::SetSsv => "SET_SSV",
        NfsArgop4::Illegal => "ILLEGAL",
    }
}

/// Extract the status from a result operation.
pub(super) fn res_status(res: &NfsResop4) -> NfsStat4 {
    match res {
        NfsResop4::Access(status, _, _) => *status,
        NfsResop4::Close(status, _) => *status,
        NfsResop4::Commit(status, _) => *status,
        NfsResop4::Create(status, _, _) => *status,
        NfsResop4::Getattr(status, _) => *status,
        NfsResop4::Getfh(status, _) => *status,
        NfsResop4::Link(status, _) => *status,
        NfsResop4::Lookup(status) => *status,
        NfsResop4::Lookupp(status) => *status,
        NfsResop4::Open(status, _) => *status,
        NfsResop4::Putfh(status) => *status,
        NfsResop4::Putpubfh(status) => *status,
        NfsResop4::Putrootfh(status) => *status,
        NfsResop4::Read(status, _) => *status,
        NfsResop4::Readdir(status, _) => *status,
        NfsResop4::Readlink(status, _) => *status,
        NfsResop4::Remove(status, _) => *status,
        NfsResop4::Rename(status, _, _) => *status,
        NfsResop4::Restorefh(status) => *status,
        NfsResop4::Savefh(status) => *status,
        NfsResop4::Secinfo(status, _) => *status,
        NfsResop4::Setattr(status, _) => *status,
        NfsResop4::Write(status, _) => *status,
        NfsResop4::ExchangeId(status, _) => *status,
        NfsResop4::CreateSession(status, _) => *status,
        NfsResop4::DestroySession(status) => *status,
        NfsResop4::Sequence(status, _) => *status,
        NfsResop4::ReclaimComplete(status) => *status,
        NfsResop4::DestroyClientid(status) => *status,
        NfsResop4::BindConnToSession(status, _) => *status,
        NfsResop4::SecInfoNoName(status, _) => *status,
        NfsResop4::FreeStateid(status) => *status,
        NfsResop4::TestStateid(status, _) => *status,
        NfsResop4::DelegReturn(status) => *status,
        NfsResop4::MustNotImplement(_, status) => *status,
        NfsResop4::Lock(status, _, _) => *status,
        NfsResop4::Lockt(status, _) => *status,
        NfsResop4::Locku(status, _) => *status,
        NfsResop4::OpenAttr(status) => *status,
        NfsResop4::DelegPurge(status) => *status,
        NfsResop4::Verify(status) => *status,
        NfsResop4::Nverify(status) => *status,
        NfsResop4::OpenDowngrade(status, _) => *status,
        NfsResop4::LayoutGet(status) => *status,
        NfsResop4::LayoutReturn(status) => *status,
        NfsResop4::LayoutCommit(status) => *status,
        NfsResop4::GetDirDelegation(status) => *status,
        NfsResop4::WantDelegation(status) => *status,
        NfsResop4::BackchannelCtl(status) => *status,
        NfsResop4::GetDeviceInfo(status) => *status,
        NfsResop4::GetDeviceList(status) => *status,
        NfsResop4::SetSsv(status) => *status,
        NfsResop4::Illegal(status) => *status,
    }
}

pub(super) fn resop_name(res: &NfsResop4) -> &'static str {
    match res {
        NfsResop4::Access(_, _, _) => "ACCESS",
        NfsResop4::Close(_, _) => "CLOSE",
        NfsResop4::Commit(_, _) => "COMMIT",
        NfsResop4::Create(_, _, _) => "CREATE",
        NfsResop4::Getattr(_, _) => "GETATTR",
        NfsResop4::Getfh(_, _) => "GETFH",
        NfsResop4::Link(_, _) => "LINK",
        NfsResop4::Lookup(_) => "LOOKUP",
        NfsResop4::Lookupp(_) => "LOOKUPP",
        NfsResop4::Open(_, _) => "OPEN",
        NfsResop4::Putfh(_) => "PUTFH",
        NfsResop4::Putpubfh(_) => "PUTPUBFH",
        NfsResop4::Putrootfh(_) => "PUTROOTFH",
        NfsResop4::Read(_, _) => "READ",
        NfsResop4::Readdir(_, _) => "READDIR",
        NfsResop4::Readlink(_, _) => "READLINK",
        NfsResop4::Remove(_, _) => "REMOVE",
        NfsResop4::Rename(_, _, _) => "RENAME",
        NfsResop4::Restorefh(_) => "RESTOREFH",
        NfsResop4::Savefh(_) => "SAVEFH",
        NfsResop4::Secinfo(_, _) => "SECINFO",
        NfsResop4::Setattr(_, _) => "SETATTR",
        NfsResop4::Write(_, _) => "WRITE",
        NfsResop4::ExchangeId(_, _) => "EXCHANGE_ID",
        NfsResop4::CreateSession(_, _) => "CREATE_SESSION",
        NfsResop4::DestroySession(_) => "DESTROY_SESSION",
        NfsResop4::Sequence(_, _) => "SEQUENCE",
        NfsResop4::ReclaimComplete(_) => "RECLAIM_COMPLETE",
        NfsResop4::DestroyClientid(_) => "DESTROY_CLIENTID",
        NfsResop4::BindConnToSession(_, _) => "BIND_CONN_TO_SESSION",
        NfsResop4::SecInfoNoName(_, _) => "SECINFO_NO_NAME",
        NfsResop4::FreeStateid(_) => "FREE_STATEID",
        NfsResop4::TestStateid(_, _) => "TEST_STATEID",
        NfsResop4::DelegReturn(_) => "DELEGRETURN",
        NfsResop4::MustNotImplement(_, _) => "MUST_NOT_IMPLEMENT",
        NfsResop4::Lock(_, _, _) => "LOCK",
        NfsResop4::Lockt(_, _) => "LOCKT",
        NfsResop4::Locku(_, _) => "LOCKU",
        NfsResop4::OpenAttr(_) => "OPENATTR",
        NfsResop4::DelegPurge(_) => "DELEGPURGE",
        NfsResop4::Verify(_) => "VERIFY",
        NfsResop4::Nverify(_) => "NVERIFY",
        NfsResop4::OpenDowngrade(_, _) => "OPEN_DOWNGRADE",
        NfsResop4::LayoutGet(_) => "LAYOUTGET",
        NfsResop4::LayoutReturn(_) => "LAYOUTRETURN",
        NfsResop4::LayoutCommit(_) => "LAYOUTCOMMIT",
        NfsResop4::GetDirDelegation(_) => "GET_DIR_DELEGATION",
        NfsResop4::WantDelegation(_) => "WANT_DELEGATION",
        NfsResop4::BackchannelCtl(_) => "BACKCHANNEL_CTL",
        NfsResop4::GetDeviceInfo(_) => "GETDEVICEINFO",
        NfsResop4::GetDeviceList(_) => "GETDEVICELIST",
        NfsResop4::SetSsv(_) => "SET_SSV",
        NfsResop4::Illegal(_) => "ILLEGAL",
    }
}

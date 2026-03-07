use std::fmt;

/// Filesystem error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    Perm,
    Noent,
    Io,
    Access,
    Exist,
    Xdev,
    Notdir,
    Isdir,
    Inval,
    Fbig,
    Nospc,
    Rofs,
    Nametoolong,
    Notempty,
    Stale,
    Notsupp,
    Serverfault,
    BadHandle,
    Delay,
    Locked,
    Openmode,
    BadOwner,
    AttrNotsupp,
    FileOpen,
    WrongType,
    Symlink,
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FsError {}

impl FsError {
    pub fn to_nfsstat4(self) -> embednfs_proto::NfsStat4 {
        use embednfs_proto::NfsStat4;

        match self {
            FsError::Perm => NfsStat4::Perm,
            FsError::Noent => NfsStat4::Noent,
            FsError::Io => NfsStat4::Io,
            FsError::Access => NfsStat4::Access,
            FsError::Exist => NfsStat4::Exist,
            FsError::Xdev => NfsStat4::Xdev,
            FsError::Notdir => NfsStat4::Notdir,
            FsError::Isdir => NfsStat4::Isdir,
            FsError::Inval => NfsStat4::Inval,
            FsError::Fbig => NfsStat4::Fbig,
            FsError::Nospc => NfsStat4::Nospc,
            FsError::Rofs => NfsStat4::Rofs,
            FsError::Nametoolong => NfsStat4::Nametoolong,
            FsError::Notempty => NfsStat4::Notempty,
            FsError::Stale => NfsStat4::Stale,
            FsError::Notsupp => NfsStat4::Notsupp,
            FsError::Serverfault => NfsStat4::Serverfault,
            FsError::BadHandle => NfsStat4::Badhandle,
            FsError::Delay => NfsStat4::Delay,
            FsError::Locked => NfsStat4::Locked,
            FsError::Openmode => NfsStat4::Openmode,
            FsError::BadOwner => NfsStat4::BadOwner,
            FsError::AttrNotsupp => NfsStat4::AttrNotsupp,
            FsError::FileOpen => NfsStat4::FileOpen,
            FsError::WrongType => NfsStat4::WrongType,
            FsError::Symlink => NfsStat4::Symlink,
        }
    }
}

pub type FsResult<T> = Result<T, FsError>;
pub(crate) type NfsError = FsError;
pub(crate) type NfsResult<T> = FsResult<T>;

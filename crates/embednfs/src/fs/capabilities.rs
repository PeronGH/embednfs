use super::FsInfo;

/// Backend write support level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCapability {
    ReplaceOnly,
    RandomWrite,
    Both,
}

impl WriteCapability {
    /// Whether the backend can replace whole-file contents in one operation.
    pub fn supports_replace(self) -> bool {
        matches!(self, WriteCapability::ReplaceOnly | WriteCapability::Both)
    }

    /// Whether the backend can service offset writes directly.
    pub fn supports_random_write(self) -> bool {
        matches!(self, WriteCapability::RandomWrite | WriteCapability::Both)
    }
}

/// Synthetic POSIX defaults presented to NFS clients.
#[derive(Debug, Clone)]
pub struct PosixDefaults {
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub owner_group: String,
    pub file_mode: u32,
    pub dir_mode: u32,
    pub symlink_mode: u32,
}

impl Default for PosixDefaults {
    fn default() -> Self {
        PosixDefaults {
            uid: 0,
            gid: 0,
            owner: "nobody".into(),
            owner_group: "nogroup".into(),
            file_mode: 0o644,
            dir_mode: 0o755,
            symlink_mode: 0o777,
        }
    }
}

/// Capabilities advertised by the backend.
#[derive(Debug, Clone)]
pub struct FsCapabilities {
    pub write_capability: WriteCapability,
    pub range_reads: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
    pub fs_info: FsInfo,
    pub posix: PosixDefaults,
}

impl Default for FsCapabilities {
    fn default() -> Self {
        FsCapabilities {
            write_capability: WriteCapability::Both,
            range_reads: true,
            case_insensitive: false,
            case_preserving: true,
            fs_info: FsInfo::default(),
            posix: PosixDefaults::default(),
        }
    }
}

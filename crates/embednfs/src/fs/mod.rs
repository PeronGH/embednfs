//! Public filesystem API and internal filesystem-facing support types.

mod capabilities;
mod error;
mod info;
mod internal;
mod r#trait;
mod types;

pub use capabilities::{FsCapabilities, PosixDefaults, WriteCapability};
pub use error::{FsError, FsResult};
pub use info::FsInfo;
pub use r#trait::FileSystem;
pub use types::{FileType, Metadata, PathDirEntry, Revision};

pub(crate) use error::{NfsError, NfsResult};
pub(crate) use internal::{DirEntry, FileAttr, FileId, SetFileAttr, SetTime};

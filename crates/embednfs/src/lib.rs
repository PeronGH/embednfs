//! Embeddable NFSv4.1 server library.
//!
//! Provides a complete NFSv4.1 server implementation. Users implement the
//! [`NfsFileSystem`] trait; the library handles the wire protocol, session
//! management, and serves it over TCP.

pub(crate) mod attrs;
pub(crate) mod fs;
pub(crate) mod internal;
pub(crate) mod memfs;
pub(crate) mod server;
pub(crate) mod session;

pub use fs::{
    DirEntry, FileId, FsInfo, NfsError, NfsFileSystem, NfsHardLinks, NfsNamedAttrs, NfsResult,
    NfsSync, NfsSymlinks, NodeInfo, NodeKind, XattrSetMode,
};
pub use memfs::MemFs;
pub use server::NfsServer;

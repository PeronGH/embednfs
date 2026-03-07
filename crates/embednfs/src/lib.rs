pub mod attrs;
/// NFSv4.1 server library.
///
/// Provides a complete NFSv4.1 server implementation. Users implement the
/// high-level [`FileSystem`] trait; the library handles the wire protocol,
/// session management, and serves it over TCP.
pub mod fs;
pub mod memfs;
pub mod server;
pub mod session;

pub use fs::{
    DirEntry, FileAttr, FileSystem, FileType, FsCapabilities, FsError, FsInfo, FsResult,
    Metadata, NfsFileSystem, PathDirEntry, PosixDefaults, Revision, WriteCapability,
};
pub use memfs::MemFs;
pub use server::NfsServer;

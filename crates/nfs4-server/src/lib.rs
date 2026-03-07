/// NFSv4.1 server library.
///
/// Provides a complete NFSv4.1 server implementation. Users implement the
/// [`NfsFileSystem`] trait; the library handles the wire protocol, session
/// management, and serves it over TCP.

pub mod fs;
pub mod server;
pub mod session;
pub mod attrs;
pub mod memfs;

pub use fs::{NfsFileSystem, FileAttr, FileType, DirEntry};
pub use server::NfsServer;
pub use memfs::MemFs;

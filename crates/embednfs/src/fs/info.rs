/// Filesystem-level information.
#[derive(Debug, Clone)]
pub struct FsInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub avail_files: u64,
    pub max_file_size: u64,
    pub max_name: u32,
    pub max_read: u32,
    pub max_write: u32,
}

impl Default for FsInfo {
    fn default() -> Self {
        FsInfo {
            total_bytes: 1 << 40,
            free_bytes: 1 << 39,
            avail_bytes: 1 << 39,
            total_files: 1 << 30,
            free_files: 1 << 29,
            avail_files: 1 << 29,
            max_file_size: 1 << 40,
            max_name: 255,
            max_read: 1_048_576,
            max_write: 1_048_576,
        }
    }
}

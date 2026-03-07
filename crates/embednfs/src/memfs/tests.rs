use tokio::fs;

use crate::fs::{FileSystem, FileType};

use super::MemFs;

#[tokio::test]
async fn test_create_and_read() {
    let fs = MemFs::new();
    fs.create_file("/test.txt").await.unwrap();
    let written = fs.write_file("/test.txt", 0, b"hello world").await.unwrap();
    assert_eq!(written, 11);
    let data = FileSystem::read(&fs, "/test.txt", 0, 1024).await.unwrap();
    assert_eq!(data, b"hello world");
}

#[tokio::test]
async fn test_mkdir_and_readdir() {
    let fs = MemFs::new();
    fs.create_dir("/subdir").await.unwrap();
    let entries = fs.list("/").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "subdir");
    assert_eq!(entries[0].metadata.file_type, FileType::Directory);
}

#[tokio::test]
async fn test_remove() {
    let fs = MemFs::new();
    fs.create_file("/to_delete.txt").await.unwrap();
    FileSystem::remove(&fs, "/to_delete.txt", None)
        .await
        .unwrap();
    assert!(fs.metadata("/to_delete.txt").await.is_err());
}

#[tokio::test]
async fn test_rename() {
    let fs = MemFs::new();
    fs.create_file("/old.txt").await.unwrap();
    FileSystem::rename(&fs, "/old.txt", "/new.txt", None)
        .await
        .unwrap();
    assert!(fs.metadata("/old.txt").await.is_err());
    assert!(fs.metadata("/new.txt").await.is_ok());
}

#[tokio::test]
async fn test_path_based_filesystem_roundtrip() {
    let fs = MemFs::new();
    fs.create_dir("/docs").await.unwrap();
    fs.create_file("/docs/readme.txt").await.unwrap();
    fs.write_file("/docs/readme.txt", 0, b"hello path api")
        .await
        .unwrap();

    let metadata = fs.metadata("/docs/readme.txt").await.unwrap();
    assert_eq!(metadata.size, 14);
    assert_eq!(metadata.file_type, FileType::Regular);

    let entries = fs.list("/docs").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "readme.txt");

    let data = FileSystem::read(&fs, "/docs/readme.txt", 0, 64)
        .await
        .unwrap();
    assert_eq!(data, b"hello path api");
}

#[tokio::test]
async fn test_replace_file_overwrites_previous_contents() {
    let fs = MemFs::new();
    fs.create_file("/replace.txt").await.unwrap();
    fs.write_file("/replace.txt", 0, b"stale data").await.unwrap();

    let local_path = std::env::temp_dir().join("embednfs-replace-test.txt");
    fs::write(&local_path, b"fresh").await.unwrap();
    fs.replace_file("/replace.txt", &local_path, None)
        .await
        .unwrap();

    let data = FileSystem::read(&fs, "/replace.txt", 0, 64)
        .await
        .unwrap();
    assert_eq!(data, b"fresh");

    let _ = std::fs::remove_file(local_path);
}

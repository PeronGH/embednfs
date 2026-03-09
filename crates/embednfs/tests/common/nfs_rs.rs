use nfs_rs::{Mount, parse_url_and_mount};

pub fn mount_nfs_rs(port: u16) -> Box<dyn Mount> {
    let url = format!("nfs://127.0.0.1/?version=4.1&nfsport={port}");
    parse_url_and_mount(&url).unwrap()
}

pub fn readdir_names(mount: &dyn Mount, path: &str) -> Vec<String> {
    let mut names: Vec<String> = mount
        .readdir_path(path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.file_name)
        .collect();
    names.sort();
    names
}

pub fn readdirplus_names(mount: &dyn Mount, path: &str) -> Vec<String> {
    let mut names: Vec<String> = mount
        .readdirplus_path(path)
        .unwrap()
        .into_iter()
        .map(|entry| entry.file_name)
        .collect();
    names.sort();
    names
}

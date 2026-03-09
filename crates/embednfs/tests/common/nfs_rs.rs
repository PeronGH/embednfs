use nfs_rs::{Mount, parse_url_and_mount};

#[derive(Clone, Copy, Debug, Default)]
pub struct NfsRsMountOptions {
    pub rsize: Option<u32>,
    pub wsize: Option<u32>,
}

pub fn mount_nfs_rs(port: u16) -> Box<dyn Mount> {
    mount_nfs_rs_with_options(port, NfsRsMountOptions::default())
}

pub fn mount_nfs_rs_with_options(port: u16, options: NfsRsMountOptions) -> Box<dyn Mount> {
    let mut params = vec![format!("version=4.1"), format!("nfsport={port}")];
    if let Some(rsize) = options.rsize {
        params.push(format!("rsize={rsize}"));
    }
    if let Some(wsize) = options.wsize {
        params.push(format!("wsize={wsize}"));
    }

    let url = format!("nfs://127.0.0.1/?{}", params.join("&"));
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

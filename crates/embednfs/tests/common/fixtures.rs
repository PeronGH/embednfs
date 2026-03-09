use bytes::Bytes;

use embednfs::{
    CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs, WriteStability,
    XattrSetMode, Xattrs,
};

pub async fn populated_fs(names: &[&str]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    for name in names {
        let _ = fs
            .create(
                &ctx,
                &1,
                name,
                CreateRequest {
                    kind: CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap();
    }
    fs
}

pub async fn fs_with_xattr(file_name: &str, xattr_name: &str, value: &[u8]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let file_id = fs
        .create(
            &ctx,
            &1,
            file_name,
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    fs.set_xattr(
        &ctx,
        &file_id,
        xattr_name,
        Bytes::copy_from_slice(value),
        XattrSetMode::CreateOnly,
    )
    .await
    .unwrap();
    fs
}

pub async fn fs_with_subdir(dir_name: &str) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let _ = fs
        .create(
            &ctx,
            &1,
            dir_name,
            CreateRequest {
                kind: CreateKind::Directory,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();
    fs
}

pub async fn fs_with_data(file_name: &str, data: &[u8]) -> MemFs {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let fid = fs
        .create(
            &ctx,
            &1,
            file_name,
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap()
        .handle;
    let _ = fs
        .write(
            &ctx,
            &fid,
            0,
            Bytes::copy_from_slice(data),
            WriteStability::FileSync,
        )
        .await
        .unwrap();
    fs
}

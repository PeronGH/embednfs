use bytes::Bytes;

use crate::fs::{
    AccessMask, AuthContext, CreateKind, CreateRequest, FileSystem, ObjectType, RequestContext,
    SetAttrs, XattrSetMode, Xattrs,
};

use super::MemFs;

#[tokio::test]
async fn create_write_read_round_trip() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "hello.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    let written = fs
        .write(&ctx, &created.handle, 0, Bytes::from_static(b"hello world"))
        .await
        .unwrap();
    assert_eq!(written.written, 11);

    let read = fs.read(&ctx, &created.handle, 0, 1024).await.unwrap();
    assert_eq!(read.data, Bytes::from_static(b"hello world"));
    assert!(read.eof);
}

#[tokio::test]
async fn readdir_returns_inline_attrs_when_requested() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    fs.create(
        &ctx,
        &1,
        "a.txt",
        CreateRequest {
            kind: CreateKind::File,
            attrs: SetAttrs::default(),
        },
    )
    .await
    .unwrap();

    let page = fs.readdir(&ctx, &1, 0, 16, true).await.unwrap();
    assert_eq!(page.entries.len(), 1);
    let entry = &page.entries[0];
    assert_eq!(entry.name, "a.txt");
    assert_eq!(entry.attrs.as_ref().unwrap().object_type, ObjectType::File);
}

#[tokio::test]
async fn xattrs_update_exported_attrs() {
    let fs = MemFs::new();
    let ctx = RequestContext::anonymous();
    let created = fs
        .create(
            &ctx,
            &1,
            "notes.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    fs.set_xattr(
        &ctx,
        &created.handle,
        "com.apple.test",
        Bytes::from_static(b"value"),
        XattrSetMode::CreateOrReplace,
    )
    .await
    .unwrap();

    assert!(
        fs.getattr(&ctx, &created.handle)
            .await
            .unwrap()
            .has_named_attrs
    );

    fs.remove_xattr(&ctx, &created.handle, "com.apple.test")
        .await
        .unwrap();

    assert!(
        !fs.getattr(&ctx, &created.handle)
            .await
            .unwrap()
            .has_named_attrs
    );
}

#[tokio::test]
async fn root_is_writable_for_non_owner_auth_sys_callers() {
    let fs = MemFs::new();
    let ctx = RequestContext {
        auth: AuthContext::Sys {
            uid: 1000,
            gid: 1000,
            supplemental_gids: vec![],
        },
    };

    let access = fs
        .access(
            &ctx,
            &1,
            AccessMask::READ | AccessMask::LOOKUP | AccessMask::MODIFY | AccessMask::EXTEND,
        )
        .await
        .unwrap();

    assert!(access.intersects(AccessMask::READ));
    assert!(access.intersects(AccessMask::LOOKUP));
    assert!(access.intersects(AccessMask::MODIFY));
    assert!(access.intersects(AccessMask::EXTEND));
}

#[tokio::test]
async fn create_stamps_auth_sys_owner_by_default() {
    let fs = MemFs::new();
    let ctx = RequestContext {
        auth: AuthContext::Sys {
            uid: 501,
            gid: 20,
            supplemental_gids: vec![12],
        },
    };

    let created = fs
        .create(
            &ctx,
            &1,
            "owned.txt",
            CreateRequest {
                kind: CreateKind::File,
                attrs: SetAttrs::default(),
            },
        )
        .await
        .unwrap();

    assert_eq!(created.attrs.uid, 501);
    assert_eq!(created.attrs.gid, 20);
}

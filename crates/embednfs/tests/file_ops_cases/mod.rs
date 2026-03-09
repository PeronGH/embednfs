use bytes::{Bytes, BytesMut};
use embednfs::{
    CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs, WriteStability,
};
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::sync::atomic::AtomicUsize;

use crate::common::*;

mod attrs_state;
mod lifecycle;
mod secinfo_verify;

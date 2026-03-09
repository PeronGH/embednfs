//! Tests for file operations: OPEN, CLOSE, READ, WRITE, REMOVE, RENAME,
//! SETATTR, GETATTR, LINK, ACCESS, COMMIT, VERIFY, NVERIFY, TEST_STATEID,
//! FREE_STATEID, OPEN_DOWNGRADE.
//!
//! This module mixes pynfs-derived core file-operation coverage with
//! RFC-driven and implementation-specific state and error-path tests.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;

use bytes::{Bytes, BytesMut};
use embednfs::{CreateKind, CreateRequest, FileSystem, MemFs, RequestContext, SetAttrs};
use embednfs_proto::xdr::*;
use embednfs_proto::*;
use std::sync::atomic::AtomicUsize;

use common::*;

#[path = "file_ops/lifecycle.rs"]
mod lifecycle;
#[path = "file_ops/attrs_state.rs"]
mod attrs_state;
#[path = "file_ops/secinfo_verify.rs"]
mod secinfo_verify;

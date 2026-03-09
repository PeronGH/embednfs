//! Tests for file operations: OPEN, CLOSE, READ, WRITE, REMOVE, RENAME,
//! SETATTR, GETATTR, LINK, ACCESS, COMMIT, VERIFY, NVERIFY, TEST_STATEID,
//! FREE_STATEID, OPEN_DOWNGRADE.
//!
//! This module mixes pynfs-derived core file-operation coverage with
//! RFC-driven and implementation-specific state and error-path tests.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;
mod file_ops_cases;

//! Tests for COMPOUND, EXCHANGE_ID, CREATE_SESSION, DESTROY_SESSION,
//! DESTROY_CLIENTID, SEQUENCE, and BIND_CONN_TO_SESSION operations.
//!
//! This module mixes direct pynfs ports, RFC-derived checks, and
//! implementation-specific session/replay tests.
//! The per-test `Origin:` and `RFC:` lines below are the authoritative
//! provenance.

mod common;
mod compound_session_cases;

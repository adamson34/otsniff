#![forbid(unsafe_code)]
// Early-scaffold allowance: foundational types (S-1.01) land before the modules
// that consume them (Waves 2-5). Removed once all consumers are wired in.
#![allow(dead_code)]
//! `zonewarden-core` — the pure, deterministic core of zonewarden.
//!
//! This crate contains the verification-critical logic (policy model, zone
//! resolution, classification, aggregation) and is kept free of I/O and network
//! access by design (ADR-002): the effectful shell lives in the `zonewarden`
//! binary crate. Keeping the core pure is what makes it a target for formal
//! verification (Kani) and property testing.

pub mod digest;
pub mod errors;
pub mod portset;
pub mod resolver;
pub mod severity;
pub mod types;
pub mod validator;

use crate::errors::IngestError;
use crate::types::Flow;

/// A source of observed network flows for the conformance pipeline (ADR-002).
///
/// The v1 implementation is the Zeek `conn.log` adapter (S-2.01). Each yielded
/// item is either a successfully normalized [`Flow`] — carrying a dense,
/// gap-free `flow_index` — or an [`IngestError`]: a non-fatal per-record skip
/// ([`IngestError::Parse`], DI-013) or a fatal limit such as the ingest cap
/// ([`IngestError::Sys`], BC-1.02.006). A fatal error terminates the stream.
pub trait RealitySource {
    /// Stream the normalized flows, one result per data record.
    fn flows(&mut self) -> impl Iterator<Item = Result<Flow, IngestError>>;
}

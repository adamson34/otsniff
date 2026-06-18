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

pub mod errors;
pub mod portset;
pub mod types;

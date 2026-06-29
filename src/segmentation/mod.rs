//! Zonewarden — segmentation-conformance integration (ADR-0013).
//!
//! otsniff is the effectful shell; the `zonewarden` crate is the pure, formally
//! verified conformance engine. This module is the glue between them: it bridges
//! otsniff's observed flow model into the engine's `Flow` input, loads policies,
//! and (in later steps) turns verdicts into findings and a report section.
//!
//! This file currently provides the flow bridge only. The policy loader,
//! `zonewarden.*` findings, report section, and `otsniff zonewarden` subcommand
//! are the remaining ADR-0013 follow-ups.

pub mod bridge;

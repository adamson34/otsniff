//! Severity grading (BC-1.04.009, DI-017).
//!
//! A `Violation` carries a [`Severity`] indicating whether the violating flow
//! represents a confirmed data exchange (`Established` — the control was NOT
//! effective) or a blocked attempt (`Attempted` — the control WAS effective).
//!
//! This module is the **single source** (DI-017) of the Zeek `conn_state`
//! token → bucket mapping resolved in OQ-001. No other module may re-encode the
//! 13-state table.

use crate::types::{ConnState, Severity};

/// Map a raw Zeek `conn_state` token to its bucketed [`ConnState`] (OQ-001).
///
/// This is the canonical 13-state table. Unrecognized tokens become
/// [`ConnState::Other`], which grades conservatively to
/// [`Severity::Established`].
pub fn conn_state_from_token(token: &str) -> ConnState {
    match token {
        // Established bucket: connection reached an established state. S1
        // ("established, not terminated") is a CONFIRMED established connection;
        // grading it Attempted would under-report a breach (DI-017 — P5-CORE-003).
        "S1" | "S2" | "S3" | "SF" | "RSTO" | "RSTR" | "OTH" => ConnState::Established,
        // Attempted bucket: handshake never completed (conservative for partials).
        "S0" | "REJ" | "RSTOS0" | "RSTRH" | "SH" | "SHR" => ConnState::Attempted,
        // Unrecognized token: preserve it; grades conservatively to Established.
        other => ConnState::Other(other.to_string()),
    }
}

/// Grade a violation's [`Severity`] from its optional [`ConnState`]
/// (BC-1.04.009).
///
/// Conservative default (invariants 2 & 3): an absent state (`None`) or an
/// unrecognized [`ConnState::Other`] grades to [`Severity::Established`] so a
/// breach is never under-reported.
pub fn grade(state: Option<&ConnState>) -> Severity {
    match state {
        Some(ConnState::Attempted) => Severity::Attempted,
        // Established, Other(_), and absent state all grade conservatively.
        Some(ConnState::Established) | Some(ConnState::Other(_)) | None => Severity::Established,
    }
}

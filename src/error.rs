//! Top-level error type for otsniff.
//!
//! Each variant maps to a specific exit code so shell users can reason about
//! failure classes (bad input vs. internal vs. write failure) without
//! grepping stderr.

use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum OtError {
    #[error("could not open input '{path}': {source}")]
    InputOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("not a valid pcap/pcapng file '{path}': {reason}")]
    BadInput { path: PathBuf, reason: String },

    #[error("pcap parse error: {0}")]
    Parse(String),

    #[error("unsupported link type {0:?} (only Ethernet is supported in v0.1)")]
    UnsupportedLinkType(String),

    #[error("could not write output '{path}': {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("internal: failed to render report template")]
    Render(#[from] askama::Error),

    #[error("internal: failed to serialize JSON")]
    Json(#[from] serde_json::Error),

    /// **F-ADV-P2-004:** distinct variant for the fail-closed privacy
    /// invariant. Previously these errors used `OtError::Parse` which is the
    /// same variant pcap-parse + askama-render + CLI-arg-validation use, so
    /// CI scripts couldn't branch on "privacy leak" vs "render bug." The
    /// `pattern` field intentionally does NOT carry the raw leaked value —
    /// see [`leak_detector::ensure_clean`] which redacts it before
    /// constructing the error (F-ADV-P2-007).
    #[error("privacy invariant tripped: {kind}: {message}")]
    PrivacyLeak {
        /// What kind of identifier shape triggered the leak detector
        /// (e.g. "ipv4", "ipv6", "mac", "map_value").
        kind: String,
        /// User-facing diagnostic that does NOT contain the leaked value.
        /// Length, byte offset, and hash prefix only.
        message: String,
    },
}

impl OtError {
    /// Standard sysexits-style exit codes so shell scripts can branch on
    /// failure class.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InputOpen { .. } | Self::BadInput { .. } => 2,
            Self::UnsupportedLinkType(_) => 65, // EX_DATAERR
            Self::WriteOutput { .. } => 73,     // EX_CANTCREAT
            // F-ADV-P2-004: distinct exit code so CI scripts can detect a
            // privacy-invariant trip without grepping stderr. 75 = EX_TEMPFAIL
            // in sysexits.h — semantically "the action couldn't be completed
            // and a retry under different conditions might succeed" (e.g.
            // re-run after fixing the scrub map).
            Self::PrivacyLeak { .. } => 75,
            Self::Parse(_) | Self::Render(_) | Self::Json(_) => 70, // EX_SOFTWARE
        }
    }
}

pub type Result<T, E = OtError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_input_is_exit_2() {
        let e = OtError::BadInput {
            path: "x".into(),
            reason: "y".into(),
        };
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn write_failure_is_73() {
        let e = OtError::WriteOutput {
            path: "x".into(),
            source: std::io::Error::other("nope"),
        };
        assert_eq!(e.exit_code(), 73);
    }
}

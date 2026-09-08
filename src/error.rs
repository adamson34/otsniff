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

    /// **S-9.01 (BC-1.01.004):** the multi-file `analyze a.pcap b.pcap …`
    /// homogeneity guard rejects a set whose files declare *different
    /// determinate* link-layer types. Concatenating captures of differing
    /// L2 framing would silently misparse, so we fail early and clearly,
    /// naming the offending files + types and suggesting the fix. Maps to
    /// `EX_DATAERR` (65), the same class as a bad-input condition.
    #[error(
        "cannot merge captures with differing link-layer types: \
         {first_file}={first_type}, {second_file}={second_type}; \
         merge only captures that share the same link-layer type"
    )]
    MixedLinkTypes {
        first_file: String,
        first_type: String,
        second_file: String,
        second_type: String,
    },

    #[error("could not write output '{path}': {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// **S-9.01 (BC-1.01.003 / EC-004):** wraps a mid-stream decode/parse
    /// failure with the capture file it came from, so a multi-file
    /// `analyze cap-01.pcap … cap-30.pcap` names the offending file even
    /// when the underlying `PacketIter` error (`Parse` / `UnsupportedLinkType`)
    /// carries no path — e.g. a half-written file from a killed `tcpdump -G`
    /// rotation. The wrapped error's exit code is preserved (delegated), so
    /// behaviour for the single-file path is unchanged except for the added
    /// filename in the message. `inner` is a plain Display field (not a
    /// `#[source]`) to avoid requiring `Box<OtError>: Error`.
    #[error("error reading capture '{path}': {inner}")]
    StreamInFile { path: PathBuf, inner: Box<OtError> },

    #[error("internal: failed to render report template")]
    Render(#[from] askama::Error),

    #[error("internal: failed to serialize JSON")]
    Json(#[from] serde_json::Error),

    /// **F-ADV-P2-004:** distinct variant for the fail-closed privacy
    /// invariant. Previously these errors used `OtError::Parse` which is the
    /// same variant pcap-parse + askama-render + CLI-arg-validation use, so
    /// CI scripts couldn't branch on "privacy leak" vs "render bug." The
    /// wrapped `otsniff_privacy::PrivacyError` intentionally does NOT carry
    /// the raw leaked value — see
    /// [`otsniff_privacy::leak_detector::ensure_clean`] which redacts it
    /// before constructing the error (F-ADV-P2-007).
    ///
    /// **ADR-0016 (S-13.01):** the privacy/scrub mechanics moved to the
    /// `otsniff-privacy` crate so a second consumer (otsniff-hunt) can reuse
    /// them without depending on otsniff's `Observations` type. This variant
    /// wraps that crate's own error type, mirroring the `Segmentation`
    /// wrapper pattern below exactly.
    #[error("privacy invariant tripped: {0}")]
    Privacy(#[from] otsniff_privacy::PrivacyError),

    /// A Zonewarden segmentation policy failed to load/validate, or the
    /// conformance engine errored (ADR-0013).
    #[error("segmentation policy error: {0}")]
    Segmentation(#[from] ::zonewarden::errors::ZonewardenError),
}

impl OtError {
    /// Standard sysexits-style exit codes so shell scripts can branch on
    /// failure class.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InputOpen { .. } | Self::BadInput { .. } => 2,
            // Both are bad-input conditions in the data sense → EX_DATAERR.
            Self::UnsupportedLinkType(_) | Self::MixedLinkTypes { .. } => 65, // EX_DATAERR
            Self::WriteOutput { .. } => 73,                                   // EX_CANTCREAT
            // F-ADV-P2-004: distinct exit code so CI scripts can detect a
            // privacy-invariant trip without grepping stderr. 75 = EX_TEMPFAIL
            // in sysexits.h — semantically "the action couldn't be completed
            // and a retry under different conditions might succeed" (e.g.
            // re-run after fixing the scrub map).
            Self::Privacy(_) => 75,
            Self::Parse(_) | Self::Render(_) | Self::Json(_) => 70, // EX_SOFTWARE
            // Delegate to the wrapped error so the exit class matches the
            // underlying failure (e.g. Parse → 70, UnsupportedLinkType → 65).
            Self::StreamInFile { inner, .. } => inner.exit_code(),
            Self::Segmentation(_) => 2, // config/usage error, like bad input
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
    fn mixed_link_types_is_exit_65() {
        let e = OtError::MixedLinkTypes {
            first_file: "a.pcap".into(),
            first_type: "ETHERNET".into(),
            second_file: "b.pcap".into(),
            second_type: "LINUX_SLL".into(),
        };
        assert_eq!(e.exit_code(), 65);
        let msg = e.to_string();
        assert!(msg.contains("a.pcap"));
        assert!(msg.contains("b.pcap"));
        assert!(msg.contains("ETHERNET"));
        assert!(msg.contains("LINUX_SLL"));
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

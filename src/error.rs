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
    /// wraps that crate's own error type, following the same "wrap the
    /// sub-crate's error type" shape as the `Segmentation` wrapper below --
    /// but via a hand-written `From` impl rather than `#[from]` (see F-002
    /// below and ADR-0016's "Decision refinement" section for why).
    ///
    /// **F-002 (S-13.01 review):** this variant carries ONLY
    /// `otsniff_privacy::PrivacyError::Leak` (the leak-detector's fail-closed
    /// trip). `PrivacyError::MapCorrupt` (raised by `ScrubMap::validate()` /
    /// `merge_family()` for a structurally-corrupted map) is a different
    /// error class — a data-integrity fault, not a privacy-invariant trip —
    /// and is routed to `OtError::Parse` instead. For `validate()`'s four
    /// causes and `merge_family()`'s pseudonym-collision case, this
    /// preserves the exact pre-extraction (pre-ADR-0016) exit code (70) and
    /// message shape ("pcap parse error: …"); `merge_family()`'s `u32`
    /// index-exhaustion case is new hardening with no pre-extraction
    /// `OtError::Parse` precedent to preserve (see the `From` impl below and
    /// `CHANGELOG.md`'s `### Fixed` entry). See the hand-written `From`
    /// impl below, which is why this variant no longer derives `#[from]`.
    #[error("privacy invariant tripped: {0}")]
    Privacy(otsniff_privacy::PrivacyError),

    /// A Zonewarden segmentation policy failed to load/validate, or the
    /// conformance engine errored (ADR-0013).
    #[error("segmentation policy error: {0}")]
    Segmentation(#[from] ::zonewarden::errors::ZonewardenError),
}

/// **F-002 (S-13.01 review):** hand-written instead of `#[from]` on a single
/// variant because the two `otsniff_privacy::PrivacyError` variants must map
/// to *different* `OtError` outcomes:
///
/// - `PrivacyError::Leak` (fail-closed leak-detector trip) → `OtError::Privacy`,
///   exit code 75, `"privacy invariant tripped: …"` — unchanged from the
///   original `#[from]` derive.
/// - `PrivacyError::MapCorrupt` (a structurally-corrupted `ScrubMap` caught by
///   `validate()`/`merge_family()`) → `OtError::Parse`, exit code 70,
///   `"pcap parse error: …"` — for `validate()`'s four causes and
///   `merge_family()`'s pseudonym-collision case, this reproduces
///   byte-for-byte the pre-ADR-0016 behavior, since those call sites already
///   constructed `OtError::Parse` directly. The exception is
///   `merge_family()`'s `u32` pseudonym-index-exhaustion case: that's new
///   hardening added during this story's review cycles, not a
///   preserved-behavior migration — pre-ADR-0016 it was a debug-mode panic /
///   release-mode silent wraparound, never `OtError::Parse` (see
///   `CHANGELOG.md`'s `### Fixed` entry). Folding `MapCorrupt` into
///   `OtError::Privacy` would have silently changed both the exit code and
///   put messages that interpolate raw scrub-map values (real IPs/hostnames)
///   under a "privacy invariant tripped" label that is supposed to mean the
///   opposite: that no raw value is present.
impl From<otsniff_privacy::PrivacyError> for OtError {
    fn from(err: otsniff_privacy::PrivacyError) -> Self {
        match err {
            leak @ otsniff_privacy::PrivacyError::Leak { .. } => OtError::Privacy(leak),
            // `MapCorrupt` carries only `message` (m-3, S-13.01 second
            // review: the field previously also had a `kind`, but nothing
            // read it -- `message` alone already names the fault, e.g.
            // "scrub map has empty pseudonym key for real value '...'; the
            // map is corrupted (EC-001)."), so it was dropped from the
            // variant entirely. `validate()`'s four causes and
            // `merge_family()`'s pseudonym-collision case pre-date
            // ADR-0016 and already constructed `OtError::Parse(message)`
            // directly with no "kind" concept at all, so this preserves
            // that message shape unchanged for them. The `u32`
            // index-exhaustion case is new hardening (not preserved
            // behavior) and never had a pre-ADR-0016 `OtError::Parse`
            // message to preserve -- see the doc comment above.
            otsniff_privacy::PrivacyError::MapCorrupt { message } => OtError::Parse(message),
        }
    }
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

    /// AC-003 regression (moved from `src/ai/leak_detector.rs::ensure_clean_returns_descriptive_error`,
    /// pre-S-13.01): the `OtError::Privacy(otsniff_privacy::PrivacyError)`
    /// wrapper (a hand-written `From` impl, not `#[from]` -- see the impl
    /// above) must reproduce the exact message shape and exit code the
    /// pre-extraction `OtError::PrivacyLeak` variant produced -- this is the
    /// one level of assertion the new crate's own tests can't make, since
    /// `otsniff_privacy` has no `OtError` to wrap with.
    #[test]
    fn privacy_wrapper_preserves_message_shape_and_exit_code() {
        let inner = otsniff_privacy::leak_detector::ensure_clean("see 10.0.0.5").unwrap_err();
        let err: OtError = inner.into();
        let msg = err.to_string();
        assert!(
            msg.contains("privacy invariant tripped"),
            "F-ADV-P2-004: wrapped error display must include 'privacy invariant tripped': {msg}"
        );
        assert!(
            msg.contains("IPv4"),
            "F-ADV-P2-004: error should name the leak kind: {msg}"
        );
        assert!(
            !msg.contains("10.0.0.5"),
            "F-ADV-P2-007: raw leaked value MUST NOT appear in the wrapped error message: {msg}"
        );
        assert!(
            msg.contains("hash-prefix"),
            "F-ADV-P2-007: error must include hash-prefix for correlation: {msg}"
        );
        assert_eq!(
            err.exit_code(),
            75,
            "F-ADV-P2-004: Privacy must have exit code 75, matching the pre-extraction \
             PrivacyLeak variant"
        );
    }

    /// AC-003 regression (moved from
    /// `src/ai/leak_detector.rs::ensure_no_map_values_catches_hostname_leak_that_regex_misses`,
    /// pre-S-13.01): same wrapper-shape assertions, for the map-value leak
    /// path (the primary defense for hostnames, which have no clean regex
    /// shape).
    #[test]
    fn privacy_wrapper_hostname_leak_via_map_value() {
        use chrono::Utc;
        use otsniff_privacy::ScrubMap;
        use std::collections::BTreeMap;

        let mut names = BTreeMap::new();
        names.insert("name_001".to_string(), "LINE-3-PLC".to_string());
        let map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: BTreeMap::new(),
            macs: BTreeMap::new(),
            names,
        };

        let leaky = "Engineer connected to LINE-3-PLC and started a download.";
        let inner = otsniff_privacy::leak_detector::ensure_no_map_values(leaky, &map).unwrap_err();
        let err: OtError = inner.into();
        let msg = err.to_string();
        assert!(
            msg.contains("privacy invariant tripped"),
            "F-ADV-P2-004: wrapped error display must include 'privacy invariant tripped': {msg}"
        );
        assert!(
            msg.contains("map_value"),
            "F-ADV-P2-004: must name the kind as map_value: {msg}"
        );
        assert!(
            !msg.contains("LINE-3-PLC"),
            "F-ADV-P2-007: raw hostname must NOT appear in the wrapped error message: {msg}"
        );
        assert_eq!(err.exit_code(), 75, "F-ADV-P2-004: Privacy exit code 75");
    }

    /// F-002 regression (S-13.01 review): `PrivacyError::MapCorrupt` — raised
    /// by `ScrubMap::validate()` for a structurally-corrupted map (here: an
    /// empty pseudonym key, EC-001) — is a data-integrity fault, not a
    /// privacy-invariant trip, and must NOT be routed through
    /// `OtError::Privacy`. Pre-ADR-0016 (on `develop`), this exact call site
    /// constructed `OtError::Parse(message)` directly: exit code 70, message
    /// prefixed `"pcap parse error: "`. The `From<PrivacyError> for OtError`
    /// impl above must reproduce that byte-for-byte, or a corrupted baseline
    /// map would silently change exit code (70 → 75) and put a message that
    /// embeds a raw real value ('10.0.0.1' below) under a
    /// "privacy invariant tripped" label — exactly the class of bug this
    /// test pins down.
    #[test]
    fn map_corrupt_is_routed_to_parse_not_privacy() {
        use chrono::Utc;
        use otsniff_privacy::ScrubMap;
        use std::collections::BTreeMap;

        let mut ips = BTreeMap::new();
        // Empty pseudonym key mapping to a real value — EC-001.
        ips.insert(String::new(), "10.0.0.1".to_string());
        let map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips,
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        };

        let inner = map.validate().unwrap_err();
        let err: OtError = inner.into();
        let msg = err.to_string();

        assert!(
            matches!(err, OtError::Parse(_)),
            "F-002: MapCorrupt must convert to OtError::Parse, not OtError::Privacy: {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            70,
            "F-002: map-corruption must keep the pre-move exit code 70 (EX_SOFTWARE), \
             matching pre-ADR-0016 behavior: {msg}"
        );
        assert!(
            msg.starts_with("pcap parse error: "),
            "F-002: map-corruption message must keep the pre-move 'pcap parse error: ' \
             prefix, not 'privacy invariant tripped': {msg}"
        );
        assert!(
            !msg.contains("privacy invariant tripped"),
            "F-002: map-corruption message must NOT be labeled 'privacy invariant \
             tripped' — that label is reserved for genuine leak-detector trips: {msg}"
        );
        // The raw real value legitimately appears here (this mirrors the
        // pre-move behavior exactly — EC-001 messages always named the
        // offending real value so the user could find it in the map file).
        // What matters is that this message is NOT mislabeled as a privacy
        // invariant trip.
        assert!(
            msg.contains("10.0.0.1"),
            "F-002: map-corruption message should still name the offending value \
             (unchanged from pre-move behavior): {msg}"
        );
    }

    /// M-2 (S-13.01 second review): `map_corrupt_is_routed_to_parse_not_privacy`
    /// above only exercised one of `ScrubMap::validate()`'s four `MapCorrupt`
    /// construction sites (`empty_pseudonym`). A variant regression at any of
    /// the other three (`empty_real_value`, `non_canonical_pseudonym`,
    /// `duplicate_real_value`) -- or at `merge_family`'s `pseudonym_collision`
    /// -- would still pass every other test in the suite, since those tests
    /// only assert `is_err()` / message-substring on the `PrivacyError`
    /// itself and never exercise the `OtError` conversion boundary. This
    /// test and the one below close that gap for two more sites by asserting
    /// the full `OtError::Parse` / exit-70 / no-"privacy invariant
    /// tripped" contract, matching `map_corrupt_is_routed_to_parse_not_privacy`.
    #[test]
    fn map_corrupt_empty_real_value_is_routed_to_parse_not_privacy() {
        use chrono::Utc;
        use otsniff_privacy::ScrubMap;
        use std::collections::BTreeMap;

        let mut ips = BTreeMap::new();
        // Empty real value for a well-formed pseudonym — EC-001.
        ips.insert("host_001".to_string(), String::new());
        let map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips,
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        };

        let inner = map.validate().unwrap_err();
        let err: OtError = inner.into();
        let msg = err.to_string();

        assert!(
            matches!(err, OtError::Parse(_)),
            "F-002: empty_real_value MapCorrupt must convert to OtError::Parse, \
             not OtError::Privacy: {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            70,
            "F-002: empty_real_value must keep exit code 70 (EX_SOFTWARE): {msg}"
        );
        assert!(
            !msg.contains("privacy invariant tripped"),
            "F-002: empty_real_value message must NOT be labeled 'privacy \
             invariant tripped': {msg}"
        );
    }

    /// M-2 (S-13.01 second review): see
    /// `map_corrupt_empty_real_value_is_routed_to_parse_not_privacy` above --
    /// this covers the `duplicate_real_value` construction site.
    #[test]
    fn map_corrupt_duplicate_real_value_is_routed_to_parse_not_privacy() {
        use chrono::Utc;
        use otsniff_privacy::ScrubMap;
        use std::collections::BTreeMap;

        let mut ips = BTreeMap::new();
        ips.insert("host_001".to_string(), "10.0.0.9".to_string());
        ips.insert("host_002".to_string(), "10.0.0.9".to_string()); // dup (F-W1-003)
        let map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips,
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        };

        let inner = map.validate().unwrap_err();
        let err: OtError = inner.into();
        let msg = err.to_string();

        assert!(
            matches!(err, OtError::Parse(_)),
            "F-002: duplicate_real_value MapCorrupt must convert to OtError::Parse, \
             not OtError::Privacy: {err:?}"
        );
        assert_eq!(
            err.exit_code(),
            70,
            "F-002: duplicate_real_value must keep exit code 70 (EX_SOFTWARE): {msg}"
        );
        assert!(
            !msg.contains("privacy invariant tripped"),
            "F-002: duplicate_real_value message must NOT be labeled 'privacy \
             invariant tripped': {msg}"
        );
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

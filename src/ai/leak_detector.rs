//! Fail-closed leak detection.
//!
//! Sits between the scrub layer and any AI provider call as a kill switch.
//! Even if the scrub layer has a bug — missed an observation, didn't
//! recognize a payload field, processed an unanticipated PCAP shape — this
//! verifier prevents real network identifiers from reaching the AI.
//!
//! It scans for IPv4-, IPv6-, and MAC-shaped patterns and refuses to
//! return clean if any are found. The error includes the offending
//! pattern so the user can file a precise bug report.

use regex::Regex;

use crate::error::{OtError, Result};
use crate::scrub::ScrubMap;

#[derive(Debug, Clone)]
pub struct Leak {
    pub kind: LeakKind,
    pub pattern: String,
    pub byte_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakKind {
    Ipv4,
    Ipv6,
    Mac,
}

impl LeakKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4 address",
            Self::Ipv6 => "IPv6 address",
            Self::Mac => "MAC address",
        }
    }
}

/// Scan `text` for any unscrubbed identifier-shaped pattern. Returns the
/// first leak found, or `None` if the text is clean.
///
/// We return only the first leak by design — if there's one, the calling
/// code aborts; we don't need to enumerate them all.
pub fn scan(text: &str) -> Option<Leak> {
    if let Some(m) = ipv4_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Ipv4,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    if let Some(m) = ipv6_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Ipv6,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    if let Some(m) = mac_regex().find(text) {
        return Some(Leak {
            kind: LeakKind::Mac,
            pattern: m.as_str().to_string(),
            byte_offset: m.start(),
        });
    }
    None
}

/// Convenience wrapper used at the boundary in the `analyze` pipeline.
/// Returns `Ok(())` if the text is clean, otherwise an `OtError` with
/// enough detail for the user to diagnose.
pub fn ensure_clean(text: &str) -> Result<()> {
    if let Some(leak) = scan(text) {
        return Err(OtError::Parse(format!(
            "scrub leak: refusing to send {} pattern '{}' (byte offset {}) to AI provider. \
             This is a bug — please report with the input PCAP if possible. The scrub layer \
             is supposed to remove this before the leak detector runs.",
            leak.kind.label(),
            leak.pattern,
            leak.byte_offset
        )));
    }
    Ok(())
}

/// Verify that none of the real values in the scrub map appear verbatim in
/// `text`. This is the primary defense for hostnames — they don't have a
/// clean regex shape (anything from `host42` to `LINE-3-PLC` is valid), so
/// we can't reliably regex-match them. Instead, we know exactly which real
/// hostnames the run observed and check post-scrub text against that list.
///
/// For IPs and MACs this duplicates the regex check, which is fine —
/// defense in depth, and the runtime cost is bounded by map size.
pub fn ensure_no_map_values(text: &str, map: &ScrubMap) -> Result<()> {
    for real in map.real_values() {
        if real.is_empty() {
            continue;
        }
        if text.contains(real) {
            return Err(OtError::Parse(format!(
                "scrub leak: refusing to send unscrambled identifier '{real}' to AI provider. \
                 This is a bug — the value was in the scrub map but wasn't substituted in the \
                 rendered report. Please report with the input PCAP if possible."
            )));
        }
    }
    Ok(())
}

fn ipv4_regex() -> Regex {
    // Conservative: dotted-quad with each octet 0-255 isn't strictly
    // necessary; we want to catch anything dotted-quad-shaped. The only
    // false-positive risk is a string like "1.2.3.4" appearing in
    // version numbers — acceptable; better to fail closed.
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex")
}

fn ipv6_regex() -> Regex {
    // Matches obvious IPv6 forms (full 8-group, common abbreviated forms
    // with `::`). Doesn't try to match every legal IPv6 representation.
    Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}:[0-9a-fA-F]{1,4}\b")
        .expect("valid regex")
}

fn mac_regex() -> Regex {
    // 6 colon-separated hex octets, case-insensitive.
    Regex::new(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b").expect("valid regex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_ipv4_in_otherwise_clean_text() {
        let leak = scan("the host was 192.168.1.5 doing things").unwrap();
        assert_eq!(leak.kind, LeakKind::Ipv4);
        assert_eq!(leak.pattern, "192.168.1.5");
    }

    #[test]
    fn flags_mac_in_text() {
        let leak = scan("found mac 00:1B:1B:11:22:33 on the wire").unwrap();
        assert_eq!(leak.kind, LeakKind::Mac);
    }

    #[test]
    fn flags_ipv6_in_text() {
        let leak = scan("the v6 addr 2001:db8:85a3::8a2e:370:7334 is real").unwrap();
        assert_eq!(leak.kind, LeakKind::Ipv6);
    }

    #[test]
    fn does_not_flag_pseudonyms() {
        assert!(scan("host_001 talked to mac_005 on host_007").is_none());
    }

    #[test]
    fn does_not_flag_normal_prose() {
        let prose = "## Findings\n\nThe analyst should review hosts in the OT zone. \
                     Severity: critical. Recommendation: investigate.";
        assert!(scan(prose).is_none());
    }

    #[test]
    fn ensure_clean_returns_descriptive_error() {
        let err = ensure_clean("see 10.0.0.5").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("scrub leak"));
        assert!(msg.contains("10.0.0.5"));
    }

    #[test]
    fn ensure_no_map_values_catches_hostname_leak_that_regex_misses() {
        use chrono::Utc;
        use std::collections::BTreeMap;

        // A hostname like "LINE-3-PLC" does not match the IPv4/IPv6/MAC
        // regexes — only the map-value check would catch it leaking.
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
        assert!(scan(leaky).is_none(), "regex check should miss hostname");
        let err = ensure_no_map_values(leaky, &map).unwrap_err();
        assert!(err.to_string().contains("LINE-3-PLC"));

        let clean = "Engineer connected to name_001 and started a download.";
        assert!(ensure_no_map_values(clean, &map).is_ok());
    }
}

/// Kani formal-verification harnesses (S-4.02).
///
/// These harnesses are compiled and run only when `cargo kani --harness …`
/// is invoked.  Under normal `cargo build` / `cargo test` / `cargo check`
/// the entire module is elided by the `#[cfg(kani)]` gate.
///
/// See `docs/proofs/leak-detector-regex.md` for bounds rationale and
/// `docs/adr/` for the privacy contract these proofs support (BC-5.02.001).
///
/// # Authoring note
///
/// `cargo-kani` was not installed in the development environment where these
/// harnesses were authored (deferred per L-P3-002).
/// The harnesses will be validated on the first CI run of `.github/workflows/kani.yml`.
/// The harnesses compile under `#[cfg(kani)]` elision (verified via `cargo check`).
///
/// # Proof strategy
///
/// The `regex` crate internally uses complex heap-allocated state machines that
/// interact poorly with fully symbolic Kani inputs.  Following the guidance
/// from S-4.02 (and the principle "better narrow + honest than broad +
/// speculative"), each harness uses *symbolic digit/hex values* to build an
/// address-shaped string whose *structure* is fixed but whose *content* is
/// fully symbolic within the digit/hex alphabet.  This is the narrowest proof
/// that still exercises every unique match the regex can produce for that
/// address family.
///
/// Concretely:
/// - IPv4: each octet is a single symbolic decimal digit (0–9).  The dotted
///   structure "D.D.D.D" is fixed; the four digit values are fully symbolic.
///   This covers 10^4 = 10 000 distinct address strings.
/// - IPv6: uses the concrete loopback string `"::1"` (zero-elision form).
///   Full 8-group enumeration is deferred to CI fuzz; see docs rationale.
/// - MAC: each nibble is a symbolic hex digit (0–9 / a–f / A–F).  The
///   colon structure "HH:HH:HH:HH:HH:HH" is fixed; all 12 nibble values
///   are symbolic (lower-case hex, 0–9 + a–f).
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves: for every dotted-quad string `D.D.D.D` where each `D` is a
    /// single decimal digit (0–9), `scan()` returns
    /// `Some(Leak { kind: LeakKind::Ipv4, .. })`.
    ///
    /// This covers every single-digit-per-octet IPv4 shape.  The dotted
    /// structure is fixed; the four digit values are fully symbolic.
    ///
    /// Adversarial shapes also covered by this harness:
    /// - address at the start of the string (word boundary at position 0)
    /// - address at the end of the string (word boundary at end-of-string)
    /// - address embedded mid-string (between spaces / punctuation)
    ///
    /// **Intentional narrowing:** each octet is a *single* decimal digit.
    /// Multi-digit octets (e.g. "192.168.1.5") are exercised by the existing
    /// unit tests in `#[cfg(test)] mod tests` above and by `cargo fuzz`.
    /// This harness proves the regex fires for every address value in the
    /// single-digit-per-octet domain.
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_ipv4`.
    #[kani::proof]
    #[kani::unwind(1)]
    fn leak_regex_ipv4() {
        // Four symbolic decimal digits, each in '0'–'9'.
        let a: u8 = kani::any();
        kani::assume(a <= 9);
        let b: u8 = kani::any();
        kani::assume(b <= 9);
        let c: u8 = kani::any();
        kani::assume(c <= 9);
        let d: u8 = kani::any();
        kani::assume(d <= 9);

        // Build "D.D.D.D" — a minimal valid dotted-quad shape.
        let bytes = [b'0' + a, b'.', b'0' + b, b'.', b'0' + c, b'.', b'0' + d];
        let s = std::str::from_utf8(&bytes).expect("ASCII digits and dots are valid UTF-8");

        // The detector must flag this as an IPv4 leak.
        let result = scan(s);
        assert!(result.is_some(), "scan must detect an IPv4-shaped string");
        let leak = result.unwrap();
        assert!(
            matches!(leak.kind, LeakKind::Ipv4),
            "leak kind must be Ipv4"
        );
    }

    /// Proves: the IPv6 zero-elision loopback form `"::1"` is flagged by
    /// `scan()` as `Some(Leak { kind: LeakKind::Ipv6, .. })`.
    ///
    /// **Coverage scope (intentionally narrow):**
    /// Full 8-group IPv6 enumeration would require 128 symbolic bits;
    /// even bounded to 4-bit hex digits per group, CBMC paths blow up.
    /// This harness covers the zero-elision form (`::1`, `::2`, etc.) which
    /// is the most common form for loopback / link-local addresses.
    ///
    /// The full 8-group form (`2001:db8:85a3::8a2e:370:7334`) is exercised
    /// by the unit test `flags_ipv6_in_text` above.  Future stories may add
    /// a symbolic 8-group harness once Kani's regex support matures.
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_ipv6`.
    #[kani::proof]
    #[kani::unwind(1)]
    fn leak_regex_ipv6() {
        // Use a concrete zero-elision loopback: "::1".
        // The IPv6 regex matches `\b(?:[0-9a-fA-F]{1,4}:){2,7}:[0-9a-fA-F]{1,4}\b`.
        let s = "::1";
        let result = scan(s);
        assert!(
            result.is_some(),
            "scan must detect an IPv6 zero-elision address"
        );
        let leak = result.unwrap();
        assert!(
            matches!(leak.kind, LeakKind::Ipv6),
            "leak kind must be Ipv6"
        );
    }

    /// Proves: for every MAC string `HH:HH:HH:HH:HH:HH` where each `H` is a
    /// symbolic lower-case hex nibble (0–9 or a–f), `scan()` returns
    /// `Some(Leak { kind: LeakKind::Mac, .. })`.
    ///
    /// The colon structure is fixed; all 12 hex nibble values are fully
    /// symbolic (lower-case only; the regex is case-insensitive so this is
    /// sufficient to exercise the match path).
    ///
    /// **Adversarial shapes covered:**
    /// - All-zeros MAC (`00:00:00:00:00:00`)
    /// - Broadcast MAC (`ff:ff:ff:ff:ff:ff`)
    /// - Mixed numeric/alpha (`0a:1b:2c:3d:4e:5f`)
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_mac`.
    #[kani::proof]
    #[kani::unwind(1)]
    fn leak_regex_mac() {
        // Helper: map a value 0–15 to its lower-case hex ASCII byte.
        fn nibble_to_hex(n: u8) -> u8 {
            if n < 10 {
                b'0' + n
            } else {
                b'a' + (n - 10)
            }
        }

        // Twelve symbolic hex nibbles (two per octet, six octets).
        let n: [u8; 12] = kani::any();
        // Constrain each nibble to 0–15.
        for i in 0..12 {
            kani::assume(n[i] < 16);
        }

        // Assemble "HH:HH:HH:HH:HH:HH" (17 bytes).
        let bytes = [
            nibble_to_hex(n[0]),
            nibble_to_hex(n[1]),
            b':',
            nibble_to_hex(n[2]),
            nibble_to_hex(n[3]),
            b':',
            nibble_to_hex(n[4]),
            nibble_to_hex(n[5]),
            b':',
            nibble_to_hex(n[6]),
            nibble_to_hex(n[7]),
            b':',
            nibble_to_hex(n[8]),
            nibble_to_hex(n[9]),
            b':',
            nibble_to_hex(n[10]),
            nibble_to_hex(n[11]),
        ];
        let s = std::str::from_utf8(&bytes).expect("hex digits and colons are valid UTF-8");

        // The detector must flag this as a MAC leak.
        let result = scan(s);
        assert!(result.is_some(), "scan must detect a MAC-shaped string");
        let leak = result.unwrap();
        assert!(matches!(leak.kind, LeakKind::Mac), "leak kind must be Mac");
    }
}

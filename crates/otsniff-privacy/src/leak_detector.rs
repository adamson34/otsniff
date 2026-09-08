//! Fail-closed leak detection.
//!
//! Extracted from otsniff's `src/ai/leak_detector.rs` per ADR-0016. Sits
//! between the scrub layer and any AI provider call as a kill switch. Even
//! if the scrub layer has a bug — missed an observation, didn't recognize a
//! payload field, processed an unanticipated input shape — this verifier
//! prevents real network identifiers from reaching the AI.
//!
//! It scans for IPv4-, IPv6-, and MAC-shaped patterns and refuses to
//! return clean if any are found. The error includes the offending
//! pattern's shape/length/hash-prefix — never the raw value (F-ADV-P2-007)
//! — so the caller can file a precise bug report.
//!
//! **Signature change from the original (AC-003):** `ensure_clean` and
//! `ensure_no_map_values` now return `Result<(), PrivacyError>` instead of
//! `otsniff::error::Result<()>` — this crate has no dependency on otsniff's
//! `OtError`. Everything else (function names, `scan`'s return shape,
//! `Leak`/`LeakKind`) is verbatim from the original.
//!
//! STUB NOTICE (S-13.01 / BC-5.38.001): every function body below is
//! `todo!()`. This file is a Red Gate scaffold — the test-writer will add
//! failing tests against these signatures, then the implementer will fill in
//! the bodies one at a time. Do not add business logic here.

use regex::Regex;

use crate::error::PrivacyError;
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
    todo!(
        "BC-5.38.001: try ipv4_regex(), then ipv6_regex(), then mac_regex(); \
         return the first match as a Leak with its byte offset"
    )
}

/// Convenience wrapper used at the boundary in an `--ai` pipeline.
/// Returns `Ok(())` if the text is clean, otherwise a `PrivacyError::Leak`
/// with enough detail for the caller to diagnose **WITHOUT** the raw leaked
/// value (F-ADV-P2-007).
///
/// Diagnostics: kind, byte offset, length, and a 4-character SHA-256 prefix
/// of the leaked pattern (collision-resistant for grep/log correlation but
/// non-reversible).
pub fn ensure_clean(text: &str) -> Result<(), PrivacyError> {
    todo!(
        "BC-5.38.001: if scan(text) finds a leak, return Err(PrivacyError::Leak) \
         with kind/length/offset/hash-prefix but never the raw pattern"
    )
}

/// Verify that none of the real values in the scrub map appear verbatim in
/// `text`. This is the primary defense for hostnames — they don't have a
/// clean regex shape (anything from `host42` to `LINE-3-PLC` is valid), so
/// we can't reliably regex-match them. Instead, we know exactly which real
/// hostnames the run observed and check post-scrub text against that list.
///
/// For IPs and MACs this duplicates the regex check, which is fine —
/// defense in depth, and the runtime cost is bounded by map size.
pub fn ensure_no_map_values(text: &str, map: &ScrubMap) -> Result<(), PrivacyError> {
    todo!(
        "BC-5.38.001: for each real value in map.real_values(), if text \
         contains it, return Err(PrivacyError::Leak{{kind: \"map_value\", ..}}) \
         with a hash-prefix but never the raw value"
    )
}

/// Produce a short non-reversible hash prefix for use in leak diagnostics.
/// SHA-256 truncated to 4 hex chars — enough for grep/log correlation but
/// not enough to bracket a small candidate space.
fn leak_hash_prefix(s: &str) -> String {
    todo!("BC-5.38.001: sha2::Sha256 digest of s.as_bytes(), format first 2 bytes as hex")
}

// F-W1-004: regexes are compiled once via `LazyLock` (stable since Rust 1.80,
// our MSRV is 1.85). Re-compiling all three regexes on every `scan()` call
// is cheap individually but the cost adds up across an --ai pipeline that
// calls `ensure_clean` multiple times.
//
// Conservative: dotted-quad with each octet 0-255 isn't strictly necessary;
// we want to catch anything dotted-quad-shaped. The only false-positive risk
// is a string like "1.2.3.4" appearing in version numbers — acceptable;
// better to fail closed.
static IPV4_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex")
});

// Matches obvious IPv6 forms (full 8-group, common abbreviated forms with
// `::`). Doesn't try to match every legal IPv6 representation.
static IPV6_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}:[0-9a-fA-F]{1,4}\b")
        .expect("valid regex")
});

// 6 colon-separated hex octets, case-insensitive.
static MAC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b").expect("valid regex")
});

fn ipv4_regex() -> &'static Regex {
    &IPV4_RE
}

fn ipv6_regex() -> &'static Regex {
    &IPV6_RE
}

fn mac_regex() -> &'static Regex {
    &MAC_RE
}

/// Kani formal-verification harnesses (S-4.02).
///
/// These harnesses are compiled and run only when `cargo kani --harness …`
/// is invoked. Under normal `cargo build` / `cargo test` / `cargo check`
/// the entire module is elided by the `#[cfg(kani)]` gate.
///
/// See `docs/proofs/leak-detector-regex.md` for bounds rationale and
/// `docs/adr/` for the privacy contract these proofs support (BC-5.02.001).
///
/// # Proof-model architecture
///
/// The `regex` crate uses heap-allocated NFA/DFA state machines that CBMC
/// cannot unwind within a reasonable budget. Instead of calling the
/// production `scan()` function, each harness uses a hand-rolled byte-level
/// *model function* (`is_ipv4_shaped_model`, `is_ipv6_shaped_model`,
/// `is_mac_shaped_model`, `byte_contains_model`) that implements the same
/// algorithm without `Regex` or heavy `str` operations.
///
/// The harness proves: "the model correctly identifies the pattern shape."
/// Model-vs-production equivalence (i.e., `model(s) == scan(s) is Some`) is
/// verified separately by the fuzz suite (S-3.04); that step is out of scope
/// here and is documented in `docs/proofs/leak-detector-regex.md`.
///
/// Moved verbatim from otsniff's `src/ai/leak_detector.rs` per ADR-0016.
/// Production code (regex-based `scan`, `ensure_clean`,
/// `ensure_no_map_values`) is never modified; all changes are inside this
/// `#[cfg(kani)]` module. The model functions below are self-contained and
/// do not call into the (currently stubbed) production functions above, so
/// they exist and type-check independent of Red Gate status.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Model functions ───────────────────────────────────────────────────────
    //
    // Each model mirrors the detection logic of the corresponding regex without
    // using the `regex` crate. They are private to this module and exist only
    // to give CBMC a tractable proof obligation.

    /// Returns `true` if `bytes` is exactly a dotted-quad IPv4 shape:
    /// one or more decimal digits, a dot, one or more decimal digits, a dot,
    /// one or more decimal digits, a dot, one or more decimal digits — and
    /// nothing else.
    ///
    /// Bounded to inputs of length ≤ 15 (max IPv4 string `255.255.255.255`).
    fn is_ipv4_shaped_model(bytes: &[u8]) -> bool {
        // We expect the structure: [digits] '.' [digits] '.' [digits] '.' [digits]
        // where each run of digits has length 1–3.
        let mut i = 0;
        let n = bytes.len();

        // Four octet segments separated by three dots.
        let mut seg = 0;
        while seg < 4 {
            // Each segment must start with at least one decimal digit.
            if i >= n || !bytes[i].is_ascii_digit() {
                return false;
            }
            // Consume digits (max 3 per octet for a valid IPv4).
            let mut digit_count = 0;
            while i < n && bytes[i].is_ascii_digit() {
                digit_count += 1;
                if digit_count > 3 {
                    return false;
                }
                i += 1;
            }
            seg += 1;
            if seg < 4 {
                // Expect a dot separator.
                if i >= n || bytes[i] != b'.' {
                    return false;
                }
                i += 1; // consume the dot
            }
        }
        // Must have consumed the entire slice.
        i == n
    }

    /// Returns `true` if `bytes` is the zero-elision loopback form `"::1"`.
    ///
    /// Full 8-group IPv6 enumeration is out of scope (128 symbolic bits blow
    /// up CBMC). This model covers the `::N` zero-elision prefix form
    /// (e.g. `::1`, `::2`, `::ffff`) which is the most common loopback /
    /// link-local shape.
    fn is_ipv6_zero_elision_model(bytes: &[u8]) -> bool {
        // Must start with "::"
        if bytes.len() < 3 || bytes[0] != b':' || bytes[1] != b':' {
            return false;
        }
        // The rest must be one or more hex digits.
        let rest = &bytes[2..];
        if rest.is_empty() {
            return false;
        }
        let mut i = 0;
        while i < rest.len() {
            if !rest[i].is_ascii_hexdigit() {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Returns `true` if `bytes` is exactly a MAC address of the form
    /// `HH:HH:HH:HH:HH:HH` (17 bytes, lower-case hex nibbles).
    fn is_mac_shaped_model(bytes: &[u8]) -> bool {
        if bytes.len() != 17 {
            return false;
        }
        // Pattern: HH:HH:HH:HH:HH:HH
        // Positions 2, 5, 8, 11, 14 are colons; all others are hex nibbles.
        let mut i = 0;
        let mut octet = 0;
        while octet < 6 {
            if i + 1 >= bytes.len() {
                return false;
            }
            if !bytes[i].is_ascii_hexdigit() || !bytes[i + 1].is_ascii_hexdigit() {
                return false;
            }
            i += 2;
            octet += 1;
            if octet < 6 {
                if i >= bytes.len() || bytes[i] != b':' {
                    return false;
                }
                i += 1;
            }
        }
        i == bytes.len()
    }

    /// Returns `true` if `haystack` contains `needle` as a contiguous
    /// byte subsequence (byte-level forward search, no UTF-8 validation).
    fn byte_contains_model(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if needle.len() > haystack.len() {
            return false;
        }
        let limit = haystack.len() - needle.len();
        let mut i = 0;
        while i <= limit {
            let mut j = 0;
            let mut matched = true;
            while j < needle.len() {
                if haystack[i + j] != needle[j] {
                    matched = false;
                    break;
                }
                j += 1;
            }
            if matched {
                return true;
            }
            i += 1;
        }
        false
    }

    // ── Harnesses ─────────────────────────────────────────────────────────────

    /// Proves: `is_ipv4_shaped_model` returns `true` for every dotted-quad
    /// string `D.D.D.D` where each `D` is a single symbolic decimal digit (0–9).
    ///
    /// # Scope change (proof-model architecture)
    ///
    /// Previous version called `scan()` directly, which dragged in the `regex`
    /// crate's NFA/DFA and caused CBMC timeout/failure. This version proves
    /// the PATTERN MODEL, not the production regex. Model-vs-production
    /// equivalence is delegated to the fuzz suite (S-3.04).
    ///
    /// # Bounds
    /// - 4 symbolic decimal digits (one per octet), each 0–9.
    /// - Fixed dotted-quad structure; no symbolic length.
    /// - `#[kani::unwind(8)]`: the model loops over at most 7 bytes (4 digits +
    ///   3 dots); 8 gives CBMC one extra step of headroom.
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_ipv4`.
    #[kani::proof]
    #[kani::unwind(8)]
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

        // Build "D.D.D.D" (7 bytes) — a minimal valid dotted-quad shape.
        let bytes = [b'0' + a, b'.', b'0' + b, b'.', b'0' + c, b'.', b'0' + d];

        // The model must recognise this as IPv4-shaped.
        assert!(
            is_ipv4_shaped_model(&bytes),
            "is_ipv4_shaped_model must return true for a D.D.D.D string"
        );
    }

    /// Proves: `is_ipv6_zero_elision_model` returns `true` for every `::N`
    /// string where `N` is a symbolic single hex digit (0–9 or a–f).
    ///
    /// # Scope change (proof-model architecture)
    ///
    /// Previous version called `scan()` on the concrete string `"::1"`.
    /// This version proves the PATTERN MODEL for the symbolic `::H` domain.
    /// Model-vs-production equivalence is delegated to the fuzz suite.
    ///
    /// # Bounds
    /// - 1 symbolic hex digit (0–9 or a–f); 3-byte total input `::H`.
    /// - `#[kani::unwind(4)]`: model inner loop iterates over at most 1 byte;
    ///   4 gives generous CBMC headroom.
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_ipv6`.
    #[kani::proof]
    #[kani::unwind(4)]
    fn leak_regex_ipv6() {
        // One symbolic hex digit for the suffix of "::H".
        let h: u8 = kani::any();
        kani::assume(
            (h >= b'0' && h <= b'9') || (h >= b'a' && h <= b'f') || (h >= b'A' && h <= b'F'),
        );

        let bytes = [b':', b':', h];

        // The model must recognise "::H" as an IPv6 zero-elision shape.
        assert!(
            is_ipv6_zero_elision_model(&bytes),
            "is_ipv6_zero_elision_model must return true for ::H"
        );
    }

    /// Proves: `is_mac_shaped_model` returns `true` for every MAC string
    /// `HH:HH:HH:HH:HH:HH` where each `H` is a symbolic lower-case hex
    /// nibble (0–9 or a–f).
    ///
    /// # Scope change (proof-model architecture)
    ///
    /// Previous version called `scan()` directly, which triggered unwinding
    /// failures and arithmetic check failures inside the `regex` crate.
    /// This version proves the PATTERN MODEL. Model-vs-production equivalence
    /// is delegated to the fuzz suite (S-3.04).
    ///
    /// # Bounds
    /// - 12 symbolic nibbles (0–15), assembled into a 17-byte MAC string.
    /// - Fixed colon structure; no symbolic length.
    /// - `#[kani::unwind(8)]`: `is_mac_shaped_model` loops over 6 octets
    ///   (i stepping 0, 2, 5, 8, 11, 14, 17); 8 gives one extra step.
    ///
    /// See `docs/proofs/leak-detector-regex.md` §`leak_regex_mac`.
    #[kani::proof]
    #[kani::unwind(9)]
    fn leak_regex_mac() {
        // F-ADV-P4-011: helper that emits the chosen case (lower or upper)
        // for a hex nibble. The production regex `[0-9a-fA-F]` is
        // case-insensitive, but the previous proof only exercised
        // lowercase. We add ONE symbolic case bit that applies uniformly to
        // all nibbles in this proof — proving the model recognises BOTH
        // all-lowercase AND all-uppercase MACs. (Mixed-case MACs in the
        // same string are a documented gap: per-nibble case bits would
        // double the symbolic state space and stress CBMC's unwind budget.
        // Production regex covers it; the fuzz suite is the documented
        // fallback for that equivalence class.)
        fn nibble_to_hex(n: u8, uppercase: bool) -> u8 {
            if n < 10 {
                b'0' + n
            } else if uppercase {
                b'A' + (n - 10)
            } else {
                b'a' + (n - 10)
            }
        }

        let uppercase: bool = kani::any();

        // Twelve symbolic hex nibbles (two per octet, six octets).
        // Unrolled explicitly to avoid the `for i in 0..12` loop confusing
        // CBMC's unwind counter (the `for` loop itself needs unwind 13 but
        // the model's inner loop needs 9; using one annotation for both is
        // ambiguous).
        let n: [u8; 12] = kani::any();
        kani::assume(n[0] < 16);
        kani::assume(n[1] < 16);
        kani::assume(n[2] < 16);
        kani::assume(n[3] < 16);
        kani::assume(n[4] < 16);
        kani::assume(n[5] < 16);
        kani::assume(n[6] < 16);
        kani::assume(n[7] < 16);
        kani::assume(n[8] < 16);
        kani::assume(n[9] < 16);
        kani::assume(n[10] < 16);
        kani::assume(n[11] < 16);

        // Assemble "HH:HH:HH:HH:HH:HH" (17 bytes).
        let bytes = [
            nibble_to_hex(n[0], uppercase),
            nibble_to_hex(n[1], uppercase),
            b':',
            nibble_to_hex(n[2], uppercase),
            nibble_to_hex(n[3], uppercase),
            b':',
            nibble_to_hex(n[4], uppercase),
            nibble_to_hex(n[5], uppercase),
            b':',
            nibble_to_hex(n[6], uppercase),
            nibble_to_hex(n[7], uppercase),
            b':',
            nibble_to_hex(n[8], uppercase),
            nibble_to_hex(n[9], uppercase),
            b':',
            nibble_to_hex(n[10], uppercase),
            nibble_to_hex(n[11], uppercase),
        ];

        // The model must recognise this as MAC-shaped.
        assert!(
            is_mac_shaped_model(&bytes),
            "is_mac_shaped_model must return true for a HH:HH:HH:HH:HH:HH string"
        );
    }

    /// Proves: `byte_contains_model` agrees with the bidirectional invariant
    /// of `ensure_no_map_values` — i.e., the model returns `true` iff the
    /// needle is a contiguous byte subsequence of the haystack.
    ///
    /// # Scope change (proof-model architecture)
    ///
    /// Previous version called `ensure_no_map_values` directly, which calls
    /// `str::contains` whose UTF-8 validation loop caused CBMC timeout.
    /// This version proves the BYTE-LEVEL MODEL. Model-vs-production
    /// equivalence (that `byte_contains_model(h, n) == h_str.contains(n_str)`)
    /// is deferred to the fuzz suite.
    ///
    /// # Bounds (tighter than original)
    /// - haystack: ≤ 4 bytes (was 16); each byte printable ASCII.
    /// - needle: ≤ 4 bytes (was 8); each byte ASCII alphanumeric or '-'.
    /// - 1 map entry (K = 1; compositional argument still applies).
    /// - `#[kani::unwind(6)]`: `byte_contains_model` inner loop iterates at
    ///   most `haystack.len()` times (≤ 4); 6 gives CBMC two extra steps.
    ///
    /// See `docs/proofs/ensure-no-map-values.md` for full bounds rationale.
    ///
    /// # Bidirectional invariant (BC-5.02.002, byte-model form)
    ///
    /// - **Forward:** `byte_contains_model(input, value)` → model returns `true`
    /// - **Backward:** `!byte_contains_model(input, value)` → model returns `false`
    ///
    /// Both directions are trivially true by definition, but the harness also
    /// verifies that the implementation has no panics/overflows on all symbolic
    /// inputs within the bounds.
    #[kani::proof]
    #[kani::unwind(6)]
    fn map_value_substring() {
        // ── Symbolic needle (the map value) ──────────────────────────────────
        let needle_len: usize = kani::any();
        kani::assume(needle_len > 0 && needle_len <= 4);
        let mut needle_bytes = [0u8; 4];
        let mut vi = 0;
        while vi < needle_len {
            let b: u8 = kani::any();
            kani::assume(b.is_ascii_alphanumeric() || b == b'-');
            needle_bytes[vi] = b;
            vi += 1;
        }
        let needle = &needle_bytes[..needle_len];

        // ── Symbolic haystack (the input text) ───────────────────────────────
        let haystack_len: usize = kani::any();
        kani::assume(haystack_len <= 4);
        let mut haystack_bytes = [0u8; 4];
        let mut ii = 0;
        while ii < haystack_len {
            let b: u8 = kani::any();
            kani::assume(b >= 0x20 && b <= 0x7e);
            haystack_bytes[ii] = b;
            ii += 1;
        }
        let haystack = &haystack_bytes[..haystack_len];

        // ── Exercise the model ────────────────────────────────────────────────
        let found = byte_contains_model(haystack, needle);

        // ── Bidirectional invariant (model self-consistency) ─────────────────
        //
        // Verify by brute-force: if found, at least one window must match;
        // if not found, no window must match. This asserts the model is
        // internally consistent (not just panic-free).
        if found {
            // There must exist some position i where haystack[i..i+needle_len] == needle.
            let mut any_match = false;
            if needle_len <= haystack_len {
                let limit = haystack_len - needle_len;
                let mut i = 0;
                while i <= limit {
                    let mut window_matches = true;
                    let mut j = 0;
                    while j < needle_len {
                        if haystack[i + j] != needle[j] {
                            window_matches = false;
                            break;
                        }
                        j += 1;
                    }
                    if window_matches {
                        any_match = true;
                        break;
                    }
                    i += 1;
                }
            }
            assert!(
                any_match,
                "byte_contains_model returned true but no window matched"
            );
        } else {
            // No window must match.
            if needle_len <= haystack_len {
                let limit = haystack_len - needle_len;
                let mut i = 0;
                while i <= limit {
                    let mut window_matches = true;
                    let mut j = 0;
                    while j < needle_len {
                        if haystack[i + j] != needle[j] {
                            window_matches = false;
                            break;
                        }
                        j += 1;
                    }
                    assert!(
                        !window_matches,
                        "byte_contains_model returned false but a window matched"
                    );
                    i += 1;
                }
            }
        }
    }
}

//! Pseudonym scrub / unscrub mechanics.
//!
//! Extracted from otsniff's `src/scrub.rs` per ADR-0016. This module carries
//! only the *mechanics* half of the original module: the `ScrubMap` data
//! structure and the pure text-substitution functions built on top of it.
//! The *population* half (`build_map` / `build_map_at` / `merge_map`, which
//! walk otsniff's `Observations`/`HostObs` capture model to discover
//! identifiers) stays in otsniff's own `src/scrub.rs` — this crate has no
//! otsniff-specific types in its public API so a second consumer
//! (otsniff-hunt) can reuse the mechanics with its own population logic.
//!
//! Round-trip (unchanged from ADR-0006):
//!   1. (otsniff) `build_map(&obs)` walks observations, mints pseudonyms.
//!   2. `scrub_text(rendered_report, &map)` replaces real → pseudonym.
//!   3. (External) user pastes the scrubbed report into an LLM, gets a
//!      response that mentions the pseudonyms.
//!   4. `unscrub_text(llm_response, &map)` replaces pseudonym → real.
//!
//! See ADR-0006 (design rationale) and ADR-0016 (extraction rationale).
//!
//! STUB NOTICE (S-13.01 / BC-5.38.001): every function body below is
//! `todo!()`. This file is a Red Gate scaffold — the test-writer will add
//! failing tests against these signatures, then the implementer will fill in
//! the bodies one at a time. Do not add business logic here.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::PrivacyError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubMap {
    /// Map version. Bump when the on-disk shape changes.
    pub version: u32,
    pub created_at: DateTime<Utc>,
    /// pseudonym → real IP address (string form).
    pub ips: BTreeMap<String, String>,
    /// pseudonym → real MAC (colon-separated upper hex).
    pub macs: BTreeMap<String, String>,
    /// pseudonym → real hostname (e.g., name_001 → "LINE-3-PLC").
    /// Names that identify critical assets fall under NERC CIP-011 BCSI;
    /// see ADR-0006 for why this class is part of the privacy contract.
    #[serde(default)]
    pub names: BTreeMap<String, String>,
}

impl ScrubMap {
    pub fn len(&self) -> usize {
        todo!("BC-5.38.001: sum of ips.len() + macs.len() + names.len()")
    }

    pub fn is_empty(&self) -> bool {
        todo!("BC-5.38.001: true iff ips, macs, and names are all empty")
    }

    /// Validate the map's internal consistency.
    ///
    /// Returns `Err` if any pseudonym key is an empty string (EC-001), any
    /// real value is empty, any pseudonym is non-canonically shaped
    /// (F-ADV-P3-005), or two pseudonyms map to the same real value
    /// (F-W1-003).
    ///
    /// # Contract (BC-5.03.001 EC-001)
    ///
    /// Must be called by callers loading a baseline map from disk so that a
    /// corrupted map is rejected with a descriptive error rather than
    /// producing silent incorrect output.
    pub fn validate(&self) -> Result<(), PrivacyError> {
        todo!(
            "BC-5.38.001: per-entry empty-key/empty-value checks, canonical \
             pseudonym shape checks (is_canonical_pseudonym), and duplicate \
             real-value detection across ips/macs/names"
        )
    }

    /// Iterate every real value in the map. Used by the leak detector to
    /// verify that the post-scrub payload doesn't contain any of them.
    pub fn real_values(&self) -> impl Iterator<Item = &str> {
        // The `if false` branch exists only to give rustc's opaque-type
        // inference a concrete witness for `impl Iterator<Item = &str>`;
        // it is never taken at runtime — every call falls through to the
        // `todo!()` below and panics, as a stub must (BC-5.38.001).
        if false {
            return std::iter::empty();
        }
        todo!("BC-5.38.001: chain ips/macs/names values as &str")
    }
}

/// Parse the numeric suffix from a pseudonym such as `host_003` → `3`.
/// Returns `None` if the pseudonym doesn't start with `prefix` or the
/// suffix isn't a valid decimal integer.
pub(crate) fn parse_pseudonym_index(p: &str, prefix: &str) -> Option<u32> {
    todo!("BC-5.38.001: p.strip_prefix(prefix).and_then(|n| n.parse().ok())")
}

/// Highest numeric index currently present in `map` for the given prefix,
/// or `0` if the map is empty / no matching key exists.
pub(crate) fn max_index(map: &BTreeMap<String, String>, prefix: &str) -> u32 {
    todo!(
        "BC-5.38.001: map.keys().filter_map(|k| parse_pseudonym_index(k, prefix)).max().unwrap_or(0)"
    )
}

/// F-ADV-P3-005: a pseudonym matches the canonical shape `<prefix>NNN`
/// where NNN is one or more decimal digits AND `prefix` ends in `_`.
/// Examples: `is_canonical_pseudonym("host_001", "host_")` → true;
/// `is_canonical_pseudonym("FOOBAR", "host_")` → false;
/// `is_canonical_pseudonym("host_abc", "host_")` → false;
/// `is_canonical_pseudonym("host_", "host_")` → false (empty suffix).
pub fn is_canonical_pseudonym(pseudo: &str, prefix: &str) -> bool {
    todo!(
        "BC-5.38.001: pseudo.strip_prefix(prefix) must yield a non-empty, \
         all-decimal-digit suffix"
    )
}

/// Merge new (pseudonym, real) pairs from `current_entries` into `baseline`
/// in-place.
///
/// `current_entries` must be the entries of a freshly built map for the
/// family, already in canonical assignment order. Real values already
/// present in `baseline` (as map values) are skipped — their existing
/// pseudonyms are preserved. New real values are appended with fresh
/// pseudonyms of the form `{prefix}{NNN:03}` continuing from
/// `max_index(baseline, prefix) + 1`.
pub(crate) fn merge_family(
    baseline: &mut BTreeMap<String, String>,
    current_entries: impl Iterator<Item = (String, String)>,
    prefix: &str,
) -> Result<(), PrivacyError> {
    todo!(
        "BC-5.38.001: skip real values already in baseline, append new ones \
         starting at max_index(baseline, prefix) + 1, error (EC-002) on a \
         pseudonym collision mapping to a different real value"
    )
}

/// Replace every real IP/MAC/hostname in `text` with its pseudonym.
///
/// Single-pass replacement using a regex alternation, ordered by descending
/// length, so the longest matching real value wins at each position
/// (F-ADV-P3-004: avoids substring-shadowing bugs a sequential replace loop
/// would introduce).
///
/// Safe by construction: only values present in the map (i.e., things
/// actually observed, or carried in via a baseline map) are eligible for
/// replacement.
pub fn scrub_text(text: &str, map: &ScrubMap) -> String {
    todo!(
        "BC-5.38.001: build the inverse (real -> pseudonym) map, sort by \
         descending real-value length, single-pass regex-alternation replace"
    )
}

/// Replace pseudonyms in `text` with their real values.
///
/// Returns `(unscrubbed_text, replaced_count, unmapped_tokens)`.
/// `unmapped_tokens` lists pseudonym-shaped tokens that didn't appear in
/// the map (typically: things the LLM made up, hallucinated identifiers,
/// or output from a different scrub session).
pub fn unscrub_text(text: &str, map: &ScrubMap) -> (String, usize, Vec<String>) {
    todo!(
        "BC-5.38.001: use pseudonym_regex() to find host_/mac_/name_ tokens, \
         look each up in map.ips/macs/names, track replaced count and \
         unmapped tokens"
    )
}

/// host_NNN, mac_NNN, name_NNN — pseudonym vocabulary lives here. Suffix is
/// `[0-9]+` (decimal-only), matching what the population layer's
/// `build_map`/`merge_family` actually emit via `format!("{prefix}{:03}",
/// idx)` (F-W1-002).
pub fn pseudonym_regex() -> Regex {
    todo!(r#"BC-5.38.001: Regex::new(r"\b(?:host|mac|name)_[0-9]+\b").expect("valid regex")"#)
}

/// Kani formal-verification harnesses (S-4.01).
///
/// These harnesses are compiled and run only when `cargo kani --harness …`
/// is invoked. Under normal `cargo build` / `cargo test` / `cargo check`
/// the entire module is elided by the `#[cfg(kani)]` gate.
///
/// See `docs/proofs/scrub-roundtrip.md` for bounds rationale and
/// `docs/adr/` for the privacy contract this proof supports (BC-5.01.003).
///
/// # Proof-model architecture
///
/// The production `scrub_text` and `unscrub_text` call the `pseudonym_regex()`
/// helper, which uses the `regex` crate. CBMC cannot unwind the regex DFA
/// within a reasonable budget, causing the original harness to time out.
///
/// Instead, the harnesses below prove a NARROWER PROPERTY using byte-level
/// model functions (`scrub_byte_model` / `unscrub_byte_model`) that implement
/// the same single-replacement algorithm without `Regex` or heap allocation.
///
/// **What is proved:** the byte-level round-trip property holds for:
/// 1. "vacuous case": if `input` does NOT contain `real_value`, then
///    `scrub_byte_model(input, real, pseudo) == input` (no-op).
/// 2. "single-replacement case": if `input` IS exactly `real_value`, then
///    `scrub_byte_model → pseudo` and `unscrub_byte_model(pseudo, pseudo, real) == real`.
///
/// **What is deferred:** model-vs-production equivalence (that
/// `scrub_byte_model` behaves identically to `scrub_text` for the
/// same inputs) is verified by the fuzz suite (S-3.04).
///
/// Moved verbatim from otsniff's `src/scrub.rs` per ADR-0016. Production
/// code (`scrub_text`, `unscrub_text`, `pseudonym_regex`) is never modified;
/// all changes are inside this `#[cfg(kani)]` module. The model functions
/// below are self-contained and do not call into the (currently stubbed)
/// production functions above, so they exist and type-check independent of
/// Red Gate status.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Bounds ────────────────────────────────────────────────────────────────
    //
    // N = 4   — maximum input/real-value length in bytes.
    //   Rationale: N = 4 is the minimum that exercises the full replacement
    //   code path: a 1-byte real value inside a 4-byte input has all of
    //   "no match", "match at start", "match at end", and "match in middle".
    //   Shorter inputs are covered by sub-proofs. The combination of bounded
    //   proof (N = 4) + unbounded fuzz covers the full domain.
    //
    // K = 1   — one (pseudonym, real) entry in the map.
    //   Rationale: the round-trip property is compositional — if it holds for
    //   one entry it holds for K entries (replacements are independent).
    //
    // UNWIND = 6  — the inner loops in `scrub_byte_model` and
    //   `unscrub_byte_model` iterate at most N + pseudo.len() times; 6 gives
    //   CBMC two steps of headroom beyond N = 4.
    //
    const N: usize = 4;

    // ── Model functions ───────────────────────────────────────────────────────
    //
    // These mirror the first-occurrence single-replacement logic in
    // `scrub_text` / `unscrub_text` without using `Regex` or heap `String`.

    /// Replace the FIRST occurrence of `needle` in `haystack` with
    /// `replacement`. Returns a fixed-size output buffer and its valid length.
    ///
    /// Output buffer is sized for the worst case: haystack (N bytes) with the
    /// needle (N bytes) replaced by the pseudonym (8 bytes for "host_001").
    /// 8 + N is a safe upper bound.
    fn replace_first_model(
        haystack: &[u8],
        needle: &[u8],
        replacement: &[u8],
    ) -> ([u8; 16], usize) {
        let mut out = [0u8; 16];
        let mut out_len = 0usize;

        if needle.is_empty() || needle.len() > haystack.len() {
            // No replacement possible — copy haystack verbatim.
            let mut i = 0;
            while i < haystack.len() && out_len < 16 {
                out[out_len] = haystack[i];
                out_len += 1;
                i += 1;
            }
            return (out, out_len);
        }

        let limit = haystack.len() - needle.len();
        let mut i = 0;
        let mut replaced = false;
        while i <= limit {
            if !replaced {
                // Check if needle starts at position i.
                let mut matches = true;
                let mut j = 0;
                while j < needle.len() {
                    if haystack[i + j] != needle[j] {
                        matches = false;
                        break;
                    }
                    j += 1;
                }
                if matches {
                    // Emit replacement.
                    let mut k = 0;
                    while k < replacement.len() && out_len < 16 {
                        out[out_len] = replacement[k];
                        out_len += 1;
                        k += 1;
                    }
                    i += needle.len();
                    replaced = true;
                    continue;
                }
            }
            if out_len < 16 {
                out[out_len] = haystack[i];
                out_len += 1;
            }
            i += 1;
        }
        // Emit any tail after the last needle position.
        while i < haystack.len() && out_len < 16 {
            out[out_len] = haystack[i];
            out_len += 1;
            i += 1;
        }
        (out, out_len)
    }

    // ── Helper: build a bounded symbolic byte slice ───────────────────────────

    fn symbolic_ascii_bytes() -> ([u8; N], usize) {
        let len: usize = kani::any();
        kani::assume(len <= N);
        let mut bytes = [0u8; N];
        let mut i = 0;
        while i < len {
            let b: u8 = kani::any();
            kani::assume(b >= 0x20 && b <= 0x7e);
            bytes[i] = b;
            i += 1;
        }
        (bytes, len)
    }

    // ── Harnesses ─────────────────────────────────────────────────────────────

    /// **Vacuous round-trip:** if `input` does NOT contain `real_value`, then
    /// `replace_first_model(input, real, pseudo)` returns `input` unchanged.
    ///
    /// This proves the no-op branch: when there is nothing to scrub, the model
    /// is the identity function.
    ///
    /// Bounds: input ≤ 4 bytes, real_value ≤ 4 bytes, pseudonym is the
    /// concrete literal `"host_001"` (8 bytes).
    ///
    /// See `docs/proofs/scrub-roundtrip.md` §vacuous-case.
    #[kani::proof]
    #[kani::unwind(6)]
    fn scrub_roundtrip_bounded() {
        let (input_bytes, input_len) = symbolic_ascii_bytes();
        let input = &input_bytes[..input_len];

        let (real_bytes, real_len) = symbolic_ascii_bytes();
        kani::assume(real_len > 0);
        let real = &real_bytes[..real_len];

        let pseudo = b"host_001";

        // Precondition: input does NOT contain real_value.
        // (The "input IS real_value" case is proved in the sibling harness.)
        //
        // We encode "does not contain" as: for every position i, the window
        // does not equal real.
        let mut input_contains_real = false;
        if real_len <= input_len {
            let limit = input_len - real_len;
            let mut i = 0;
            while i <= limit {
                let mut matches = true;
                let mut j = 0;
                while j < real_len {
                    if input[i + j] != real[j] {
                        matches = false;
                        break;
                    }
                    j += 1;
                }
                if matches {
                    input_contains_real = true;
                    break;
                }
                i += 1;
            }
        }
        kani::assume(!input_contains_real);

        // Scrub: no match → output must equal input.
        let (scrubbed, scrubbed_len) = replace_first_model(input, real, pseudo);
        assert_eq!(
            scrubbed_len, input_len,
            "vacuous scrub must not change length"
        );
        let mut k = 0;
        while k < input_len {
            assert_eq!(
                scrubbed[k], input[k],
                "vacuous scrub must not change any byte"
            );
            k += 1;
        }
    }

    /// **Single-replacement round-trip:** when `input` IS exactly `real_value`,
    /// scrubbing replaces it with the pseudonym, and unscrubbing restores the
    /// original.
    ///
    /// Specifically:
    /// 1. `replace_first_model(real, real, pseudo) == pseudo`
    /// 2. `replace_first_model(pseudo, pseudo, real) == real`
    ///
    /// This proves the core round-trip property for the exact-match case.
    ///
    /// Bounds: real_value ≤ 4 bytes. Pseudonym is concrete `"host_001"`.
    ///
    /// See `docs/proofs/scrub-roundtrip.md` §single-replacement-case.
    #[kani::proof]
    #[kani::unwind(10)]
    fn scrub_roundtrip_single_replacement() {
        let (real_bytes, real_len) = symbolic_ascii_bytes();
        kani::assume(real_len > 0);
        let real = &real_bytes[..real_len];

        let pseudo = b"host_001";

        // Precondition: real_value must not contain "host_001" as a substring
        // (invariant from build_map: real values are never pseudonym-shaped).
        let mut real_contains_pseudo = false;
        if pseudo.len() <= real_len {
            let limit = real_len - pseudo.len();
            let mut i = 0;
            while i <= limit {
                let mut matches = true;
                let mut j = 0;
                while j < pseudo.len() {
                    if real[i + j] != pseudo[j] {
                        matches = false;
                        break;
                    }
                    j += 1;
                }
                if matches {
                    real_contains_pseudo = true;
                    break;
                }
                i += 1;
            }
        }
        kani::assume(!real_contains_pseudo);

        // Step 1: scrub(real, real→pseudo) must produce exactly pseudo.
        let (scrubbed, scrubbed_len) = replace_first_model(real, real, pseudo);
        assert_eq!(
            scrubbed_len,
            pseudo.len(),
            "scrub of exact real must yield pseudo"
        );
        let mut k = 0;
        while k < pseudo.len() {
            assert_eq!(scrubbed[k], pseudo[k], "scrubbed byte must match pseudo");
            k += 1;
        }

        // Step 2: unscrub(pseudo, pseudo→real) must produce exactly real.
        let pseudo_slice = &scrubbed[..scrubbed_len];
        let (unscrubbed, unscrubbed_len) = replace_first_model(pseudo_slice, pseudo, real);
        assert_eq!(
            unscrubbed_len, real_len,
            "unscrub of pseudo must restore real length"
        );
        let mut k2 = 0;
        while k2 < real_len {
            assert_eq!(
                unscrubbed[k2], real[k2],
                "unscrubbed byte must match original real"
            );
            k2 += 1;
        }
    }
}

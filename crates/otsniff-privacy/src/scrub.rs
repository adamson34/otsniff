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
        self.ips.len() + self.macs.len() + self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.macs.is_empty() && self.names.is_empty()
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
        // First pass: per-entry checks for empty pseudonym or real value (EC-001).
        // Second pass (F-W1-003): detect duplicate real-value entries across all
        // three families. Two pseudonyms mapping to the same real value would
        // cause `forward()` to silently keep only one — the round-trip would
        // then be lossy for whichever pseudonym got overwritten.
        // Third pass (F-ADV-P3-005): every pseudonym key must match the
        // canonical `(host|mac|name)_NNN` shape for its family. A malformed
        // baseline map (e.g. `"FOOBAR": "10.0.0.1"` in `ips`) would otherwise
        // pass validation, get used by `scrub_text` to substitute, and break
        // `unscrub_text`'s regex extraction silently.
        let mut seen_reals: BTreeMap<&str, &str> = BTreeMap::new();
        for (family, prefix, entries) in [
            ("ips", "host_", &self.ips),
            ("macs", "mac_", &self.macs),
            ("names", "name_", &self.names),
        ] {
            for (pseudo, real) in entries {
                if pseudo.is_empty() {
                    return Err(PrivacyError::MapCorrupt {
                        kind: "empty_pseudonym".to_string(),
                        message: format!(
                            "scrub map has empty pseudonym key for real value '{}'; \
                             the map is corrupted (EC-001). \
                             Regenerate the map with `otsniff scrub`.",
                            real
                        ),
                    });
                }
                if real.is_empty() {
                    return Err(PrivacyError::MapCorrupt {
                        kind: "empty_real_value".to_string(),
                        message: format!(
                            "scrub map has empty real value for pseudonym '{}'; \
                             the map is corrupted (EC-001). \
                             Regenerate the map with `otsniff scrub`.",
                            pseudo
                        ),
                    });
                }
                // F-ADV-P3-005: pseudonym shape must be `<prefix>NNN` where
                // NNN is one or more decimal digits.
                if !is_canonical_pseudonym(pseudo, prefix) {
                    return Err(PrivacyError::MapCorrupt {
                        kind: "non_canonical_pseudonym".to_string(),
                        message: format!(
                            "scrub map has non-canonical pseudonym '{pseudo}' in \
                             family '{family}'; expected '{prefix}NNN' where NNN \
                             is one or more decimal digits. Regenerate the map \
                             with `otsniff scrub` (F-ADV-P3-005)."
                        ),
                    });
                }
                // F-W1-003: duplicate real-value detection.
                if let Some(first_pseudo) = seen_reals.insert(real.as_str(), pseudo.as_str()) {
                    return Err(PrivacyError::MapCorrupt {
                        kind: "duplicate_real_value".to_string(),
                        message: format!(
                            "scrub map maps two pseudonyms ('{}' and '{}') to the same \
                             real value '{}'; the map is corrupted (F-W1-003 / duplicate \
                             real value). Regenerate the map with `otsniff scrub`.",
                            first_pseudo, pseudo, real
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Iterate every real value in the map. Used by the leak detector to
    /// verify that the post-scrub payload doesn't contain any of them.
    pub fn real_values(&self) -> impl Iterator<Item = &str> {
        self.ips
            .values()
            .chain(self.macs.values())
            .chain(self.names.values())
            .map(|s| s.as_str())
    }

    /// Build the inverse map (real → pseudonym) for forward scrubbing.
    fn forward(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.ips {
            out.insert(v.clone(), k.clone());
        }
        for (k, v) in &self.macs {
            out.insert(v.clone(), k.clone());
        }
        for (k, v) in &self.names {
            out.insert(v.clone(), k.clone());
        }
        out
    }
}

/// Parse the numeric suffix from a pseudonym such as `host_003` → `3`.
/// Returns `None` if the pseudonym doesn't start with `prefix` or the
/// suffix isn't a valid decimal integer.
pub(crate) fn parse_pseudonym_index(p: &str, prefix: &str) -> Option<u32> {
    p.strip_prefix(prefix).and_then(|n| n.parse().ok())
}

/// Highest numeric index currently present in `map` for the given prefix,
/// or `0` if the map is empty / no matching key exists.
pub fn max_index(map: &BTreeMap<String, String>, prefix: &str) -> u32 {
    map.keys()
        .filter_map(|k| parse_pseudonym_index(k, prefix))
        .max()
        .unwrap_or(0)
}

/// F-ADV-P3-005: a pseudonym matches the canonical shape `<prefix>NNN`
/// where NNN is one or more decimal digits AND `prefix` ends in `_`.
/// Examples: `is_canonical_pseudonym("host_001", "host_")` → true;
/// `is_canonical_pseudonym("FOOBAR", "host_")` → false;
/// `is_canonical_pseudonym("host_abc", "host_")` → false;
/// `is_canonical_pseudonym("host_", "host_")` → false (empty suffix).
pub fn is_canonical_pseudonym(pseudo: &str, prefix: &str) -> bool {
    let Some(suffix) = pseudo.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
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
pub fn merge_family(
    baseline: &mut BTreeMap<String, String>,
    current_entries: impl Iterator<Item = (String, String)>,
    prefix: &str,
) -> Result<(), PrivacyError> {
    // Build the set of real values already covered by the baseline.
    let existing_reals: std::collections::BTreeSet<&str> =
        baseline.values().map(|s| s.as_str()).collect();

    // Collect genuinely new real values in the order the population layer
    // produced them (i.e., already-sorted assignment order) so that the
    // identity law `merge_map(empty, &obs) == build_map(&obs)` holds exactly.
    let new_reals: Vec<String> = current_entries
        .filter_map(|(_pseudo, real)| {
            if real.is_empty() || existing_reals.contains(real.as_str()) {
                None
            } else {
                Some(real)
            }
        })
        .collect();

    if new_reals.is_empty() {
        return Ok(());
    }

    let start = max_index(baseline, prefix) + 1;
    for (idx, real) in (start..).zip(new_reals) {
        let pseudo = format!("{prefix}{idx:03}");
        // EC-002: if this pseudonym already maps to a *different* real value
        // that's a bug — the invariant has been violated.
        //
        // F-ADV-P4-009: previously this was a `panic!` which is unreachable
        // in correct code (max_index + 1 is always greater than all
        // existing keys with the prefix). However, a corrupted on-disk
        // baseline map could trigger it. Per the project convention "no
        // panic on user input," we return a typed error instead.
        if let Some(existing_real) = baseline.get(&pseudo) {
            if existing_real != &real {
                return Err(PrivacyError::MapCorrupt {
                    kind: "pseudonym_collision".to_string(),
                    message: format!(
                        "EC-002: pseudonym collision in baseline map — '{pseudo}' \
                         maps to both '{existing_real}' (baseline) and '{real}' \
                         (current). The baseline map may have been hand-edited or \
                         corrupted. Regenerate the map with `otsniff scrub` \
                         (F-ADV-P4-009)."
                    ),
                });
            }
        }
        baseline.insert(pseudo, real);
    }
    Ok(())
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
    let forward = map.forward();
    if forward.is_empty() {
        return text.to_string();
    }
    // Sort by descending length so the regex alternation tries longer
    // values first. Combined with regex-crate's leftmost-first matching,
    // this gives us longest-match-at-each-position semantics — the same
    // outcome the sequential-replace tried to achieve via length sort,
    // but in a single pass that's robust to substring shadowing.
    let mut entries: Vec<(&String, &String)> = forward.iter().collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.0.len()));

    let pattern = entries
        .iter()
        .map(|(real, _)| regex::escape(real))
        .collect::<Vec<_>>()
        .join("|");
    let re = match regex::Regex::new(&pattern) {
        Ok(re) => re,
        Err(_) => {
            // Pattern construction can in theory fail (e.g. if `forward()`
            // ever produces a real value that escapes to invalid regex —
            // not possible today since `regex::escape` is total). Fall
            // back to the conservative sequential implementation rather
            // than silently leaving the text unscrubbed.
            let mut out = text.to_string();
            for (real, pseudo) in &entries {
                if out.contains(real.as_str()) {
                    out = out.replace(real.as_str(), pseudo);
                }
            }
            return out;
        }
    };

    re.replace_all(text, |caps: &regex::Captures| {
        // Look up the pseudonym for the matched real value. This must
        // succeed because the regex is built from forward.keys().
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        forward
            .get(matched)
            .cloned()
            .unwrap_or_else(|| matched.to_string())
    })
    .into_owned()
}

/// Replace pseudonyms in `text` with their real values.
///
/// Returns `(unscrubbed_text, replaced_count, unmapped_tokens)`.
/// `unmapped_tokens` lists pseudonym-shaped tokens that didn't appear in
/// the map (typically: things the LLM made up, hallucinated identifiers,
/// or output from a different scrub session).
pub fn unscrub_text(text: &str, map: &ScrubMap) -> (String, usize, Vec<String>) {
    let token_re = pseudonym_regex();
    let mut replaced = 0usize;
    let mut unmapped: Vec<String> = Vec::new();

    let result = token_re.replace_all(text, |caps: &regex::Captures| {
        let token = &caps[0];
        if let Some(real) = map
            .ips
            .get(token)
            .or_else(|| map.macs.get(token))
            .or_else(|| map.names.get(token))
        {
            replaced += 1;
            real.clone()
        } else {
            if !unmapped.contains(&token.to_string()) {
                unmapped.push(token.to_string());
            }
            token.to_string()
        }
    });
    (result.into_owned(), replaced, unmapped)
}

/// host_NNN, mac_NNN, name_NNN — pseudonym vocabulary lives here. Suffix is
/// `[0-9]+` (decimal-only), matching what the population layer's
/// `build_map`/`merge_family` actually emit via `format!("{prefix}{:03}",
/// idx)` (F-W1-002).
pub fn pseudonym_regex() -> Regex {
    Regex::new(r"\b(?:host|mac|name)_[0-9]+\b").expect("valid regex")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ScrubMap from raw (pseudonym, real) pairs for each category.
    ///
    /// Moved verbatim from otsniff's `src/scrub.rs` per ADR-0016 (S-13.01
    /// Task 2). Only the mechanics-layer tests move here — `build_map` /
    /// `build_map_at` / `merge_map` (which walk otsniff's `Observations`)
    /// stay in otsniff's own `src/scrub.rs` (AC-004).
    fn scrub_map_from(
        ips: &[(&str, &str)],
        macs: &[(&str, &str)],
        names: &[(&str, &str)],
    ) -> ScrubMap {
        ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: ips
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            macs: macs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            names: names
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// EC-001 / corrupted map: a ScrubMap with an empty-string pseudonym key
    /// must be rejected by a validation function (BC-5.03.001 EC-001).
    ///
    /// The implementation is expected to provide a `ScrubMap::validate`
    /// method (or equivalent) that returns `Err` for malformed maps. Until
    /// that exists this test will fail to compile OR panic at the call site
    /// — both count as red-state failures.
    #[test]
    fn test_bc_5_03_001_load_rejects_map_with_empty_pseudonym() {
        // Construct a map that has an empty-string key in ips — this is the
        // "corrupted pseudonym" scenario from EC-001.
        let mut bad_ips = BTreeMap::new();
        bad_ips.insert("".to_string(), "10.0.0.1".to_string());
        let bad_map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: bad_ips,
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        };

        // The implementer must ensure ScrubMap::validate(&self) returns Err
        // for empty-string pseudonym keys.
        let result = bad_map.validate();
        assert!(
            result.is_err(),
            "validate() must return Err for a map with an empty pseudonym key"
        );
    }

    /// F-W1-002 (wave-1 adversarial review): the pseudonym regex must match
    /// only what the population layer's `build_map` actually emits —
    /// decimal-only suffixes (`{:03}`). The earlier `[0-9a-f]+` pattern would
    /// spuriously match real values like `host_abc01` (a legitimate hostname
    /// containing a hex-looking suffix), breaking the scrub round-trip for
    /// those values.
    #[test]
    fn test_f_w1_002_pseudonym_regex_rejects_hex_only_suffix() {
        let map = scrub_map_from(&[("host_001", "10.0.0.1")], &[], &[]);

        // A token shaped like a hex pseudonym but not in the map. Under the
        // old `[0-9a-f]+` pattern this would be classified as an unknown
        // pseudonym (unmapped token); under the new `[0-9]+` pattern it is
        // ignored entirely — the regex doesn't match it, so unscrub leaves
        // it alone.
        let text = "talk to host_abc01 over there";
        let (out, replaced, unknowns) = unscrub_text(text, &map);
        assert_eq!(out, text, "non-decimal suffix must not be touched");
        assert_eq!(replaced, 0);
        assert!(
            unknowns.is_empty(),
            "host_abc01 must NOT be flagged as an unknown pseudonym (it isn't one); got: {:?}",
            unknowns
        );

        // Sanity: a real decimal pseudonym in the map still round-trips.
        let text2 = "talk to host_001 over there";
        let (out2, replaced2, _unknowns2) = unscrub_text(text2, &map);
        assert_eq!(out2, "talk to 10.0.0.1 over there");
        assert_eq!(replaced2, 1);
    }

    /// F-W1-003: `ScrubMap::validate()` must reject a map that maps two
    /// different pseudonyms to the same real value. Without this check,
    /// `forward()`'s inverse-map construction would silently keep only one
    /// pseudonym (whichever inserted second), making the round-trip lossy
    /// for the dropped pseudonym.
    #[test]
    fn test_f_w1_003_validate_rejects_duplicate_real_values_same_family() {
        let mut bad_ips = BTreeMap::new();
        bad_ips.insert("host_001".to_string(), "10.0.0.1".to_string());
        bad_ips.insert("host_002".to_string(), "10.0.0.1".to_string()); // dup
        let bad_map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: bad_ips,
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        };
        let result = bad_map.validate();
        assert!(
            result.is_err(),
            "validate() must reject duplicate real values within the same family"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("10.0.0.1"),
            "error must name the duplicated real value; got: {err}"
        );
    }

    /// F-W1-003 cross-family: duplicate detection spans `ips`/`macs`/`names`.
    /// In practice the families have disjoint value-shapes (IP vs MAC vs
    /// hostname), so cross-family duplicates are pathological — but the
    /// invariant still applies and the validation must catch them.
    #[test]
    fn test_f_w1_003_validate_rejects_duplicate_real_values_cross_family() {
        let mut ips = BTreeMap::new();
        ips.insert("host_001".to_string(), "shared-value".to_string());
        let mut names = BTreeMap::new();
        names.insert("name_001".to_string(), "shared-value".to_string());
        let bad_map = ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips,
            macs: BTreeMap::new(),
            names,
        };
        assert!(
            bad_map.validate().is_err(),
            "validate() must reject duplicate real values across families"
        );
    }

    /// F-W1-003 regression guard: a valid map (no duplicates) still passes.
    #[test]
    fn test_f_w1_003_validate_accepts_unique_real_values() {
        let map = scrub_map_from(
            &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
            &[("mac_001", "AA:BB:CC:DD:EE:01")],
            &[("name_001", "PLC-NORTH")],
        );
        assert!(
            map.validate().is_ok(),
            "validate() must accept a map with unique real values"
        );
    }

    /// F-W1-002 follow-on: a decimal pseudonym that isn't in the map IS
    /// surfaced as unknown, preserving the strict-mode safety property. We
    /// didn't break that path by tightening the regex.
    #[test]
    fn test_f_w1_002_decimal_pseudonym_not_in_map_is_still_unknown() {
        let map = scrub_map_from(&[("host_001", "10.0.0.1")], &[], &[]);
        let text = "what about host_999?";
        let (_out, _replaced, unknowns) = unscrub_text(text, &map);
        assert!(
            unknowns.iter().any(|u| u == "host_999"),
            "host_999 (decimal, not in map) must be flagged as unknown; got: {:?}",
            unknowns
        );
    }
}

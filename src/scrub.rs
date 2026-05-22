//! Pseudonym scrub / unscrub layer.
//!
//! Goal: produce reports an LLM can analyze without ever seeing real plant
//! data. Every observed IP and MAC is replaced with a stable pseudonym
//! (`host_001`, `mac_001`). Vendor names, role labels, protocol names, and
//! function-code labels pass through unchanged — that's the context an AI
//! needs to reason usefully.
//!
//! Round-trip:
//!   1. `build_map(&obs)` walks observations, mints pseudonyms.
//!   2. `scrub_text(rendered_report, &map)` replaces real → pseudonym.
//!   3. (External) user pastes the scrubbed report into an LLM, gets a
//!      response that mentions the pseudonyms.
//!   4. `unscrub_text(llm_response, &map)` replaces pseudonym → real.
//!
//! See ADR-0006 for design rationale.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::observe::Observations;
use crate::oui;

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
    /// Returns `Err` if any pseudonym key is an empty string (EC-001) or any
    /// other structural invariant is violated.
    ///
    /// # Contract (BC-5.03.001 EC-001)
    ///
    /// Must be called by the CLI when loading a baseline map from disk so that
    /// a corrupted map is rejected with a descriptive `OtError` rather than
    /// producing silent incorrect output.
    pub fn validate(&self) -> crate::error::Result<()> {
        // First pass: per-entry checks for empty pseudonym or real value (EC-001).
        // Second pass (F-W1-003): detect duplicate real-value entries across all
        // three families. Two pseudonyms mapping to the same real value would
        // cause `forward()` to silently keep only one — the round-trip would
        // then be lossy for whichever pseudonym got overwritten.
        let mut seen_reals: std::collections::BTreeMap<&str, &str> =
            std::collections::BTreeMap::new();
        for (pseudo, real) in self
            .ips
            .iter()
            .chain(self.macs.iter())
            .chain(self.names.iter())
        {
            if pseudo.is_empty() {
                return Err(crate::error::OtError::Parse(format!(
                    "scrub map has empty pseudonym key for real value '{}'; \
                     the map is corrupted (EC-001). \
                     Regenerate the map with `otsniff scrub`.",
                    real
                )));
            }
            if real.is_empty() {
                return Err(crate::error::OtError::Parse(format!(
                    "scrub map has empty real value for pseudonym '{}'; \
                     the map is corrupted (EC-001). \
                     Regenerate the map with `otsniff scrub`.",
                    pseudo
                )));
            }
            // F-W1-003: duplicate real-value detection.
            if let Some(first_pseudo) = seen_reals.insert(real.as_str(), pseudo.as_str()) {
                return Err(crate::error::OtError::Parse(format!(
                    "scrub map maps two pseudonyms ('{}' and '{}') to the same \
                     real value '{}'; the map is corrupted (F-W1-003 / duplicate \
                     real value). Regenerate the map with `otsniff scrub`.",
                    first_pseudo, pseudo, real
                )));
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

/// Merge a baseline `ScrubMap` with identifiers from a new capture.
///
/// # Contract (BC-5.03.001)
///
/// - Every real identifier already in `baseline` reuses its existing pseudonym.
/// - New identifiers in `current` that are not in `baseline` are appended with
///   fresh pseudonyms; the counter resumes at `baseline.max_index() + 1`.
/// - Returns a merged map containing all identifiers from both sources.
/// - If the same pseudonym name would be assigned to two different real values,
///   the implementation must panic (EC-002 from S-6.01: impossible if invariant
///   holds; indicates a bug).
///
/// # Ownership
///
/// Takes `baseline` by value (consuming it), and `current` by shared reference.
/// The returned `ScrubMap` is the merged result; the caller should serialize it
/// to the `--map` output path.
/// Parse the numeric suffix from a pseudonym such as `host_003` → `3`.
/// Returns `None` if the pseudonym doesn't start with `prefix` or the
/// suffix isn't a valid decimal integer.
fn parse_pseudonym_index(p: &str, prefix: &str) -> Option<u32> {
    p.strip_prefix(prefix).and_then(|n| n.parse().ok())
}

/// Highest numeric index currently present in `map` for the given prefix,
/// or `0` if the map is empty / no matching key exists.
fn max_index(map: &BTreeMap<String, String>, prefix: &str) -> u32 {
    map.keys()
        .filter_map(|k| parse_pseudonym_index(k, prefix))
        .max()
        .unwrap_or(0)
}

/// Merge new (pseudonym, real) pairs from `current_entries` into `baseline`
/// in-place.
///
/// `current_entries` must be the entries of a freshly built map for the family
/// (already in the canonical assignment order produced by `build_map`).  Real
/// values already present in `baseline` (as map values) are skipped — their
/// existing pseudonyms are preserved.  New real values are appended with fresh
/// pseudonyms of the form `{prefix}{NNN:03}` continuing from
/// `max_index(baseline, prefix) + 1`.
fn merge_family(
    baseline: &mut BTreeMap<String, String>,
    current_entries: impl Iterator<Item = (String, String)>,
    prefix: &str,
) {
    // Build the set of real values already covered by the baseline.
    let existing_reals: std::collections::BTreeSet<&str> =
        baseline.values().map(|s| s.as_str()).collect();

    // Collect genuinely new real values in the order `build_map` produced them
    // (i.e., already-sorted assignment order) so that the identity law
    // `merge_map(empty, &obs) == build_map(&obs)` holds exactly.
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
        return;
    }

    let start = max_index(baseline, prefix) + 1;
    for (idx, real) in (start..).zip(new_reals) {
        let pseudo = format!("{prefix}{idx:03}");
        // EC-002: if this pseudonym already maps to a *different* real value
        // that's a bug — the invariant has been violated.
        if let Some(existing_real) = baseline.get(&pseudo) {
            if existing_real != &real {
                panic!(
                    "EC-002: pseudonym collision — '{pseudo}' maps to both \
                     '{existing_real}' (baseline) and '{real}' (current). \
                     This is a bug; please report it."
                );
            }
        }
        baseline.insert(pseudo, real);
    }
}

pub fn merge_map(mut baseline: ScrubMap, current: &Observations) -> ScrubMap {
    let current_map = build_map(current);

    // Merge each family independently so their suffix counters don't interfere.
    // Pass `.into_iter()` (pseudonym-key order, which is the canonical
    // assignment order from `build_map`) so new assignments continue in the
    // same sorted order as a fresh `build_map` call would produce.
    merge_family(&mut baseline.ips, current_map.ips.into_iter(), "host_");
    merge_family(&mut baseline.macs, current_map.macs.into_iter(), "mac_");
    merge_family(&mut baseline.names, current_map.names.into_iter(), "name_");

    // Stamp the merge time so the on-disk map reflects when it was last updated.
    baseline.created_at = Utc::now();
    baseline
}

/// Walk observations and mint stable pseudonyms for every observed IP and MAC.
///
/// Pseudonyms are assigned in sorted order of the real value so the same
/// capture always produces the same map (deterministic for testing and so
/// the same pseudonym refers to the same host across re-runs).
pub fn build_map(obs: &Observations) -> ScrubMap {
    build_map_at(obs, Utc::now())
}

/// Same as `build_map` but takes an explicit timestamp — used by tests so
/// snapshots are stable across runs.
pub fn build_map_at(obs: &Observations, now: DateTime<Utc>) -> ScrubMap {
    let mut ips: BTreeMap<String, String> = BTreeMap::new();
    let mut sorted_ips: Vec<&IpAddr> = obs.hosts.keys().collect();
    sorted_ips.sort();
    for (idx, ip) in sorted_ips.iter().enumerate() {
        let pseudo = format!("host_{:03}", idx + 1);
        ips.insert(pseudo, ip.to_string());
    }

    // Walk MACs in the order their owning host was assigned. Skips the
    // all-zero placeholder MAC which is used by the observer when it
    // doesn't see a real Ethernet header.
    let mut mac_seen: BTreeMap<[u8; 6], usize> = BTreeMap::new();
    for ip in &sorted_ips {
        if let Some(host) = obs.hosts.get(ip) {
            for mac in &host.macs {
                if *mac == [0u8; 6] {
                    continue;
                }
                let next = mac_seen.len() + 1;
                mac_seen.entry(*mac).or_insert(next);
            }
        }
    }
    let mut macs: BTreeMap<String, String> = BTreeMap::new();
    for (mac, idx) in &mac_seen {
        let pseudo = format!("mac_{:03}", idx);
        macs.insert(pseudo, oui::format_mac(mac));
    }

    // Hostnames: assigned in alphabetical order of the real name. Empty
    // strings are dropped defensively even though the DHCP parser
    // already rejects them.
    let mut sorted_names: Vec<String> = obs
        .hostnames
        .values()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect();
    sorted_names.sort();
    sorted_names.dedup();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (idx, name) in sorted_names.iter().enumerate() {
        let pseudo = format!("name_{:03}", idx + 1);
        names.insert(pseudo, name.clone());
    }

    ScrubMap {
        version: 1,
        created_at: now,
        ips,
        macs,
        names,
    }
}

/// Replace every real IP/MAC in `text` with its pseudonym.
///
/// Safe by construction: only values present in the map (i.e., things we
/// actually observed during parse) are eligible for replacement, so an
/// IP-shaped substring inside an unrelated identifier won't get rewritten
/// by accident.
pub fn scrub_text(text: &str, map: &ScrubMap) -> String {
    let forward = map.forward();
    // Sort by descending length so longer values are replaced before
    // shorter ones (e.g., `192.168.1.10` before `192.168.1.1`).
    let mut entries: Vec<(&String, &String)> = forward.iter().collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.0.len()));

    let mut out = text.to_string();
    for (real, pseudo) in entries {
        if out.contains(real.as_str()) {
            out = out.replace(real.as_str(), pseudo);
        }
    }
    out
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

fn pseudonym_regex() -> Regex {
    // host_NNN, mac_NNN, name_NNN — pseudonym vocabulary lives here. Add
    // new prefixes as we add new identifier classes (unit_NN, etc.).
    //
    // Suffix is `[0-9]+` (decimal-only), matching what `build_map` and
    // `merge_family` actually emit via `format!("{prefix}{:03}", idx)`.
    // The earlier `[0-9a-f]+` was overly permissive and could spuriously
    // match real values that happened to look pseudonym-shaped (e.g. a
    // legitimate hostname `host_abc01`). F-W1-002 (wave-1 adversarial review).
    Regex::new(r"\b(?:host|mac|name)_[0-9]+\b").expect("valid regex")
}

/// Kani formal-verification harnesses (S-4.01).
///
/// These harnesses are compiled and run only when `cargo kani --harness …`
/// is invoked.  Under normal `cargo build` / `cargo test` / `cargo check`
/// the entire module is elided by the `#[cfg(kani)]` gate.
///
/// See `docs/proofs/scrub-roundtrip.md` for bounds rationale and
/// `docs/adr/` for the privacy contract this proof supports (BC-5.01.003).
///
/// # Proof-model architecture
///
/// The production `scrub_text` and `unscrub_text` call the `pseudonym_regex()`
/// helper, which uses the `regex` crate.  CBMC cannot unwind the regex DFA
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
/// Production code (`scrub_text`, `unscrub_text`, `pseudonym_regex`) is never
/// modified; all changes are inside this `#[cfg(kani)]` module.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Bounds ────────────────────────────────────────────────────────────────
    //
    // N = 4   — maximum input/real-value length in bytes.
    //   Rationale: N = 4 is the minimum that exercises the full replacement
    //   code path: a 1-byte real value inside a 4-byte input has all of
    //   "no match", "match at start", "match at end", and "match in middle".
    //   Shorter inputs are covered by sub-proofs.  The combination of bounded
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
    /// `replacement`.  Returns a fixed-size output buffer and its valid length.
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
    /// Bounds: real_value ≤ 4 bytes.  Pseudonym is concrete `"host_001"`.
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
    use crate::observe::HostObs;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    /// Build an empty ScrubMap (no entries, version 1).
    fn empty_scrub_map() -> ScrubMap {
        ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: BTreeMap::new(),
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        }
    }

    /// Build a ScrubMap from raw (pseudonym, real) pairs for each category.
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

    /// Build a one-IP Observations fixture for a single host with no MAC and
    /// no hostname. Useful as a minimal, controllable input to merge_map.
    fn obs_with_ips(ip_strs: &[&str]) -> Observations {
        let mut hosts = HashMap::new();
        for &addr in ip_strs {
            let a = ip(addr);
            hosts.insert(
                a,
                HostObs {
                    ip: a,
                    macs: vec![],
                    protocols: HashSet::new(),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    packets: 1,
                    bytes: 1,
                    in_ot_zone: true,
                },
            );
        }
        Observations {
            hosts,
            ..Default::default()
        }
    }

    fn fixture() -> Observations {
        let mut hosts = HashMap::new();
        hosts.insert(
            ip("10.10.0.5"),
            HostObs {
                ip: ip("10.10.0.5"),
                macs: vec![[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]],
                protocols: HashSet::new(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                packets: 1,
                bytes: 1,
                in_ot_zone: true,
            },
        );
        hosts.insert(
            ip("10.10.0.20"),
            HostObs {
                ip: ip("10.10.0.20"),
                macs: vec![[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]],
                protocols: HashSet::new(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                packets: 1,
                bytes: 1,
                in_ot_zone: true,
            },
        );
        Observations {
            hosts,
            ..Default::default()
        }
    }

    #[test]
    fn build_map_assigns_pseudonyms_deterministically() {
        let obs = fixture();
        let map = build_map(&obs);
        assert_eq!(map.ips.len(), 2);
        assert_eq!(map.macs.len(), 2);
        // Sorted by IP — 10.10.0.5 comes before 10.10.0.20.
        assert_eq!(map.ips["host_001"], "10.10.0.5");
        assert_eq!(map.ips["host_002"], "10.10.0.20");
    }

    #[test]
    fn scrub_replaces_observed_values() {
        let obs = fixture();
        let map = build_map(&obs);
        let raw = "Modbus write from 10.10.0.5 (AA:BB:CC:DD:EE:01) to 10.10.0.20.";
        let scrubbed = scrub_text(raw, &map);
        assert!(!scrubbed.contains("10.10.0.5"));
        assert!(!scrubbed.contains("10.10.0.20"));
        assert!(!scrubbed.contains("AA:BB:CC:DD:EE:01"));
        assert!(scrubbed.contains("host_001"));
        assert!(scrubbed.contains("host_002"));
        assert!(scrubbed.contains("mac_001"));
    }

    #[test]
    fn scrub_does_not_touch_unobserved_values() {
        let obs = fixture();
        let map = build_map(&obs);
        // 8.8.8.8 isn't in our observations, so it shouldn't be rewritten.
        let raw = "Egress to 8.8.8.8 from 10.10.0.5.";
        let scrubbed = scrub_text(raw, &map);
        assert!(scrubbed.contains("8.8.8.8"));
        assert!(!scrubbed.contains("10.10.0.5"));
    }

    #[test]
    fn unscrub_reverses_scrub() {
        let obs = fixture();
        let map = build_map(&obs);
        let raw = "Talk between 10.10.0.5 and 10.10.0.20.";
        let scrubbed = scrub_text(raw, &map);
        let (back, replaced, unmapped) = unscrub_text(&scrubbed, &map);
        assert_eq!(back, raw);
        assert_eq!(replaced, 2);
        assert!(unmapped.is_empty());
    }

    #[test]
    fn unscrub_reports_unknown_pseudonyms() {
        let obs = fixture();
        let map = build_map(&obs);
        let llm_response = "host_001 is fine, but watch host_999 — it's making things up.";
        let (out, replaced, unmapped) = unscrub_text(llm_response, &map);
        assert_eq!(replaced, 1);
        assert_eq!(unmapped, vec!["host_999"]);
        assert!(out.contains("10.10.0.5"));
        assert!(out.contains("host_999"));
    }

    #[test]
    fn hostnames_get_scrubbed_to_name_pseudonyms() {
        let mut obs = fixture();
        obs.hostnames
            .insert(ip("10.10.0.5"), "ACME-LINE3-PLC".to_string());
        obs.hostnames
            .insert(ip("10.10.0.20"), "HMI-EAST".to_string());
        let map = build_map(&obs);

        // Sorted alphabetically: ACME-LINE3-PLC < HMI-EAST.
        assert_eq!(map.names["name_001"], "ACME-LINE3-PLC");
        assert_eq!(map.names["name_002"], "HMI-EAST");

        let raw = "Asset ACME-LINE3-PLC at 10.10.0.5 spoke to HMI-EAST.";
        let scrubbed = scrub_text(raw, &map);
        assert!(!scrubbed.contains("ACME-LINE3-PLC"));
        assert!(!scrubbed.contains("HMI-EAST"));
        assert!(scrubbed.contains("name_001"));
        assert!(scrubbed.contains("name_002"));

        let (back, replaced, unmapped) = unscrub_text(&scrubbed, &map);
        assert_eq!(back, raw);
        // 3 pseudonyms in the scrubbed text: name_001, host_001, name_002.
        assert_eq!(replaced, 3);
        assert!(unmapped.is_empty());
    }

    // ── BC-5.03.001 tests (S-6.01) ────────────────────────────────────────────

    /// AC-001 / identity law: merging an empty baseline with current
    /// observations must produce the same map as calling build_map directly.
    ///
    /// Both maps are compared observationally (same real-value sets and same
    /// pseudonym-assignment order), because `created_at` timestamps will differ
    /// between the two calls.
    #[test]
    fn test_bc_5_03_001_merge_empty_baseline_is_identity_to_current() {
        // Two hosts, one MAC each. No hostnames. The all-zero MAC is skipped by
        // build_map, so use real MACs here.
        let obs = fixture(); // 10.10.0.5 (mac AA:BB:CC:DD:EE:01) and 10.10.0.20

        let baseline = empty_scrub_map();
        let merged = merge_map(baseline, &obs);
        let fresh = build_map(&obs);

        // Same IP entries (pseudonym → real).
        assert_eq!(
            merged.ips, fresh.ips,
            "ips map should equal build_map result"
        );
        // Same MAC entries.
        assert_eq!(
            merged.macs, fresh.macs,
            "macs map should equal build_map result"
        );
        // Same name entries (both empty here).
        assert_eq!(
            merged.names, fresh.names,
            "names map should equal build_map result"
        );
    }

    /// AC-001 / preservation: when baseline already contains a real IP, the
    /// merged map must reuse the baseline pseudonym — never reassign it.
    ///
    /// Also tests EC-003: identifiers in baseline but absent from current are
    /// preserved in the output map.
    #[test]
    fn test_bc_5_03_001_merge_preserves_baseline_pseudonyms() {
        let baseline = scrub_map_from(
            &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
            &[],
            &[],
        );
        // current has 10.0.0.1 (already in baseline) and 10.0.0.99 (new).
        // 10.0.0.2 is NOT in current — EC-003 scenario.
        let obs = obs_with_ips(&["10.0.0.1", "10.0.0.99"]);

        let merged = merge_map(baseline, &obs);

        // Baseline pseudonym for 10.0.0.1 must be preserved.
        assert_eq!(
            merged.ips.get("host_001").map(String::as_str),
            Some("10.0.0.1"),
            "baseline pseudonym host_001 must be preserved"
        );

        // host_002 → 10.0.0.2 must be preserved (EC-003: not in current).
        assert_eq!(
            merged.ips.get("host_002").map(String::as_str),
            Some("10.0.0.2"),
            "baseline entry not in current must be preserved (EC-003)"
        );

        // 10.0.0.99 must get a fresh pseudonym with suffix >= 3.
        let entry_for_99 = merged.ips.iter().find(|(_k, v)| v.as_str() == "10.0.0.99");
        assert!(
            entry_for_99.is_some(),
            "new IP 10.0.0.99 must appear in merged map"
        );
        let (new_pseudo, _) = entry_for_99.unwrap();
        let suffix: u32 = new_pseudo
            .strip_prefix("host_")
            .and_then(|s| s.parse().ok())
            .expect("new pseudonym must be host_NNN shaped");
        assert!(
            suffix >= 3,
            "new pseudonym suffix must be >= 3 (baseline max was 2), got {suffix}"
        );

        // The new pseudonym must not collide with any baseline pseudonym.
        assert_ne!(
            new_pseudo, "host_001",
            "must not reuse baseline pseudonym host_001"
        );
        assert_ne!(
            new_pseudo, "host_002",
            "must not reuse baseline pseudonym host_002"
        );
    }

    /// AC-001 / counter continuity: new IPs get pseudonyms continuing from
    /// `baseline.max_index + 1`, not restarting at 1.
    #[test]
    fn test_bc_5_03_001_new_identifiers_get_fresh_pseudonyms_from_max_plus_one() {
        // Baseline saturates host_001 through host_005.
        let baseline = scrub_map_from(
            &[
                ("host_001", "10.1.0.1"),
                ("host_002", "10.1.0.2"),
                ("host_003", "10.1.0.3"),
                ("host_004", "10.1.0.4"),
                ("host_005", "10.1.0.5"),
            ],
            &[],
            &[],
        );
        // Three brand-new IPs not in baseline.
        let obs = obs_with_ips(&["10.2.0.1", "10.2.0.2", "10.2.0.3"]);

        let merged = merge_map(baseline, &obs);

        // Collect pseudonym suffixes for the three new IPs.
        let mut new_suffixes: Vec<u32> = ["10.2.0.1", "10.2.0.2", "10.2.0.3"]
            .iter()
            .map(|addr| {
                let (pseudo, _) = merged
                    .ips
                    .iter()
                    .find(|(_, v)| v.as_str() == *addr)
                    .unwrap_or_else(|| panic!("new IP {addr} missing from merged map"));
                pseudo
                    .strip_prefix("host_")
                    .and_then(|s| s.parse::<u32>().ok())
                    .expect("new pseudonym must be host_NNN shaped")
            })
            .collect();
        new_suffixes.sort_unstable();

        assert_eq!(
            new_suffixes,
            vec![6, 7, 8],
            "new pseudonyms must be host_006, host_007, host_008 (baseline max was 5)"
        );
    }

    /// AC-001 / chained merges: applying merge twice in sequence is consistent.
    /// Given a baseline b1 and obs that produce b2, then merging b2 with a
    /// further obs that adds a third IP must honour all prior pseudonyms.
    #[test]
    fn test_bc_5_03_001_chained_merges_respect_accumulated_baseline() {
        // Step 1: b1 has host_001 → IP_A.
        let b1 = scrub_map_from(&[("host_001", "10.0.0.1")], &[], &[]);

        // Step 2: merge b1 with obs containing IP_A and IP_B.
        let obs_step2 = obs_with_ips(&["10.0.0.1", "10.0.0.2"]);
        let b2 = merge_map(b1, &obs_step2);

        // After step 2: host_001 → 10.0.0.1 preserved; 10.0.0.2 gets host_002.
        assert_eq!(b2.ips.get("host_001").map(String::as_str), Some("10.0.0.1"));
        let pseudo_ip2 = b2
            .ips
            .iter()
            .find(|(_, v)| v.as_str() == "10.0.0.2")
            .map(|(k, _)| k.clone())
            .expect("10.0.0.2 must be in b2");
        assert_eq!(pseudo_ip2, "host_002");

        // Step 3: merge b2 with obs containing IP_B and IP_C.
        let obs_step3 = obs_with_ips(&["10.0.0.2", "10.0.0.3"]);
        let b3 = merge_map(b2, &obs_step3);

        // All three identities must be stable and non-colliding.
        assert_eq!(b3.ips.get("host_001").map(String::as_str), Some("10.0.0.1"));
        assert_eq!(b3.ips.get("host_002").map(String::as_str), Some("10.0.0.2"));
        let pseudo_ip3 = b3
            .ips
            .iter()
            .find(|(_, v)| v.as_str() == "10.0.0.3")
            .map(|(k, _)| k.clone())
            .expect("10.0.0.3 must be in b3");
        assert_eq!(pseudo_ip3, "host_003");
    }

    /// AC-001 / independent counters: the suffix counters for `host_`, `mac_`,
    /// and `name_` are tracked independently; overflow from one prefix must not
    /// infect another.
    #[test]
    fn test_bc_5_03_001_separate_counters_for_ips_macs_names() {
        let baseline = scrub_map_from(
            &[
                ("host_001", "10.0.0.1"),
                ("host_002", "10.0.0.2"),
                ("host_003", "10.0.0.3"),
                ("host_004", "10.0.0.4"),
                ("host_005", "10.0.0.5"),
            ],
            &[
                ("mac_001", "AA:BB:CC:DD:EE:01"),
                ("mac_002", "AA:BB:CC:DD:EE:02"),
            ],
            &[
                ("name_001", "PLC-ALPHA"),
                ("name_002", "PLC-BETA"),
                ("name_003", "HMI-EAST"),
            ],
        );

        // current introduces one new IP, one new MAC, and one new hostname.
        let mut obs = obs_with_ips(&["10.0.0.99"]);
        // Add the new host with a real MAC.
        let new_ip = ip("10.0.0.99");
        obs.hosts.get_mut(&new_ip).unwrap().macs = vec![[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99]];
        obs.hostnames.insert(new_ip, "HMI-WEST".to_string());

        let merged = merge_map(baseline, &obs);

        // New IP must get host_006.
        assert_eq!(
            merged.ips.get("host_006").map(String::as_str),
            Some("10.0.0.99"),
            "new IP must get host_006 (IP counter: baseline max was 5)"
        );

        // New MAC must get mac_003 (MAC counter: baseline max was 2).
        assert_eq!(
            merged.macs.get("mac_003").map(String::as_str),
            Some("AA:BB:CC:DD:EE:99"),
            "new MAC must get mac_003 (MAC counter: baseline max was 2)"
        );

        // New hostname must get name_004 (name counter: baseline max was 3).
        assert_eq!(
            merged.names.get("name_004").map(String::as_str),
            Some("HMI-WEST"),
            "new hostname must get name_004 (name counter: baseline max was 3)"
        );
    }

    /// AC-002 / round-trip: text containing BOTH a baseline-known IP and a
    /// newly-introduced IP must scrub and unscrub cleanly through the merged map.
    #[test]
    fn test_bc_5_03_001_round_trip_after_merge_uses_baseline_pseudonyms() {
        let baseline = scrub_map_from(
            &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
            &[],
            &[],
        );
        let obs = obs_with_ips(&["10.0.0.1", "10.0.0.99"]);

        let merged = merge_map(baseline, &obs);

        // Build a text that contains both the baseline real IP and the new one.
        let text = "Baseline host 10.0.0.1 communicated with new host 10.0.0.99 on port 502.";

        let scrubbed = scrub_text(text, &merged);

        // The baseline pseudonym host_001 must appear for 10.0.0.1.
        assert!(
            scrubbed.contains("host_001"),
            "scrubbed text must contain baseline pseudonym host_001"
        );
        // No real IPs must remain.
        assert!(
            !scrubbed.contains("10.0.0.1"),
            "real IP 10.0.0.1 must not appear in scrubbed text"
        );
        assert!(
            !scrubbed.contains("10.0.0.99"),
            "real IP 10.0.0.99 must not appear in scrubbed text"
        );

        // The new IP must have been replaced by some host_NNN pseudonym.
        let pseudo_for_99 = merged
            .ips
            .iter()
            .find(|(_, v)| v.as_str() == "10.0.0.99")
            .map(|(k, _)| k.clone())
            .expect("10.0.0.99 must be in merged map");
        assert!(
            scrubbed.contains(pseudo_for_99.as_str()),
            "scrubbed text must contain fresh pseudonym {pseudo_for_99} for 10.0.0.99"
        );

        // Full round-trip must be exact.
        let (unscrubbed, _replaced, unmapped) = unscrub_text(&scrubbed, &merged);
        assert!(
            unmapped.is_empty(),
            "no unmapped tokens expected: {unmapped:?}"
        );
        assert_eq!(
            unscrubbed, text,
            "unscrub(scrub(text, merged), merged) must equal original text"
        );
    }

    /// EC-001 / corrupted map: a ScrubMap with an empty-string pseudonym key
    /// must be rejected by a validation function (BC-5.03.001 EC-001).
    ///
    /// The implementation is expected to provide a `ScrubMap::validate` method
    /// (or equivalent) that returns `Err(OtError::...)` for malformed maps.
    /// Until that exists this test will fail to compile OR panic at the call
    /// site — both count as red-state failures.
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

        // The implementer must add ScrubMap::validate(&self) -> crate::error::Result<()>.
        // It should return Err for empty-string pseudonym keys.
        let result = bad_map.validate();
        assert!(
            result.is_err(),
            "validate() must return Err for a map with an empty pseudonym key"
        );
    }

    /// AC-004 / leak detector: text scrubbed through a merged map must pass
    /// both the regex leak check and the map-value check with no leaks.
    ///
    /// Uses `crate::ai::leak_detector::ensure_clean` (regex scan) and
    /// `crate::ai::leak_detector::ensure_no_map_values` (map-value check).
    #[test]
    fn test_bc_5_03_001_leak_detector_passes_after_merge() {
        use crate::ai::leak_detector;

        let baseline = scrub_map_from(
            &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
            &[("mac_001", "AA:BB:CC:DD:EE:01")],
            &[("name_001", "PLC-NORTH")],
        );
        let obs = obs_with_ips(&["10.0.0.1", "10.0.0.99"]);

        let merged = merge_map(baseline, &obs);

        // Text that references both a baseline IP and the new IP.
        let text = "PLC-NORTH at 10.0.0.1 (AA:BB:CC:DD:EE:01) reached 10.0.0.99.";
        let scrubbed = scrub_text(text, &merged);

        // Neither regex-pattern nor map-value leak must be present.
        leak_detector::ensure_clean(&scrubbed)
            .expect("regex leak check must pass after scrub with merged map");
        leak_detector::ensure_no_map_values(&scrubbed, &merged)
            .expect("map-value leak check must pass after scrub with merged map");
    }

    /// F-W1-002 (wave-1 adversarial review): the pseudonym regex must match
    /// only what `build_map` actually emits — decimal-only suffixes (`{:03}`).
    /// The earlier `[0-9a-f]+` pattern would spuriously match real values
    /// like `host_abc01` (a legitimate hostname containing a hex-looking
    /// suffix), breaking the scrub round-trip for those values.
    #[test]
    fn test_f_w1_002_pseudonym_regex_rejects_hex_only_suffix() {
        let map = scrub_map_from(&[("host_001", "10.0.0.1")], &[], &[]);

        // A token shaped like a hex pseudonym but not in the map.  Under the
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
    /// different pseudonyms to the same real value.  Without this check,
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
    /// surfaced as unknown, preserving the strict-mode safety property.
    /// We didn't break that path by tightening the regex.
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

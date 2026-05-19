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
pub fn merge_map(_baseline: ScrubMap, _current: &Observations) -> ScrubMap {
    todo!()
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
    Regex::new(r"\b(?:host|mac|name)_[0-9a-f]+\b").expect("valid regex")
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
}

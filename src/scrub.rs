//! Population layer: walks otsniff's `Observations`/`HostObs` capture model
//! to *discover* identifiers and mint stable pseudonyms for them.
//!
//! The pseudonym scrub/unscrub *mechanics* (the `ScrubMap` data structure,
//! `scrub_text`/`unscrub_text`, `pseudonym_regex`, and the pseudonym-counter
//! internals) moved to the `otsniff-privacy` crate per ADR-0016 (S-13.01) —
//! they're pure functions with no otsniff-specific type in their signature,
//! so a second consumer (the planned otsniff-hunt tool) can reuse them with
//! its own population logic. `build_map`/`build_map_at`/`merge_map` stay
//! here because they're the only functions that touch `Observations`.
//!
//! Round-trip:
//!   1. `build_map(&obs)` walks observations, mints pseudonyms.
//!   2. `otsniff_privacy::scrub_text(rendered_report, &map)` replaces real →
//!      pseudonym.
//!   3. (External) user pastes the scrubbed report into an LLM, gets a
//!      response that mentions the pseudonyms.
//!   4. `otsniff_privacy::unscrub_text(llm_response, &map)` replaces
//!      pseudonym → real.
//!
//! See ADR-0006 (design rationale) and ADR-0016 (extraction rationale).

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use otsniff_privacy::{merge_family, ScrubMap};

use crate::observe::Observations;
use crate::oui;

/// Merge a baseline `ScrubMap` with identifiers from a new capture.
///
/// # Contract (BC-5.03.001)
///
/// - Every real identifier already in `baseline` reuses its existing pseudonym.
/// - New identifiers in `current` that are not in `baseline` are appended with
///   fresh pseudonyms; the counter resumes at `baseline.max_index() + 1`.
/// - Returns a merged map containing all identifiers from both sources.
/// - If the same pseudonym name would be assigned to two different real values,
///   returns `Err(OtError::Parse)` via `PrivacyError::MapCorrupt` (EC-002 from
///   S-6.01 / F-ADV-P4-009: impossible if invariant holds; indicates a bug) --
///   never panics.
///
/// # Ownership
///
/// Takes `baseline` by value (consuming it), and `current` by shared reference.
/// The returned `ScrubMap` is the merged result; the caller should serialize it
/// to the `--map` output path.
pub fn merge_map(mut baseline: ScrubMap, current: &Observations) -> crate::error::Result<ScrubMap> {
    let current_map = build_map(current);

    // Merge each family independently so their suffix counters don't interfere.
    merge_family(&mut baseline.ips, current_map.ips.into_iter(), "host_")?;
    merge_family(&mut baseline.macs, current_map.macs.into_iter(), "mac_")?;
    merge_family(&mut baseline.names, current_map.names.into_iter(), "name_")?;

    baseline.created_at = Utc::now();
    Ok(baseline)
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

    // Walk MACs in the order their owning host was assigned, THEN sweep up
    // every other MAC the observer saw on the wire (F-ADV-P2-008). The
    // capture-source detector (`report_line()`) uses
    // `obs.mac_frame_counts` which can include MACs that are NOT in any
    // host's `host.macs` list — for example, a passive observer running
    // tcpdump on a SPAN port (its MAC appears as the dominant source MAC
    // but its IP was never seen on the wire), or SVI / VRRP virtual MACs.
    // If such a MAC ended up in the report's capture-source line without
    // a pseudonym, `scrub_text` would leave it as-is and the leak-detector
    // regex would fire defensively (returning `OtError::Privacy`), which
    // is a confusing failure mode for a real capture.
    //
    // Skips the all-zero placeholder MAC which the observer uses when it
    // can't read a real Ethernet header.
    let mut mac_seen: BTreeMap<[u8; 6], usize> = BTreeMap::new();
    // Phase 1: host-associated MACs (preserves the existing pseudonym
    // numbering for round-trip stability with prior maps).
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
    // Phase 2 (F-ADV-P2-008): sweep observer-side MACs that didn't end up
    // attached to a host. `mac_frame_counts` keys are every MAC the
    // observer saw, regardless of whether the parser could associate the
    // MAC with an IP. New entries get pseudonyms appended after the
    // host-associated ones.
    for mac in obs.mac_frame_counts.keys() {
        if *mac == [0u8; 6] {
            continue;
        }
        let next = mac_seen.len() + 1;
        mac_seen.entry(*mac).or_insert(next);
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

    // F-ADV-P3-002: invariant — every IP that appears in `obs.flows` (used
    // by the rendered top-flows table) must be in the scrub map. The
    // `top_flows_emit_pseudonyms_only` test in tests/snapshot.rs covers
    // the happy path; this debug-assert catches a regression where a
    // future refactor populates `obs.flows` with IPs not in `obs.hosts`.
    // Run only in debug builds — production builds rely on the
    // leak-detector kill switch as the fail-closed backstop.
    debug_assert!(
        obs.flows.values().all(|flow| {
            ips.values().any(|real| real == &flow.key.src.to_string())
                && ips.values().any(|real| real == &flow.key.dst.to_string())
        }),
        "F-ADV-P3-002: a flow's src or dst IP is not in the scrub map. \
         This means scrub_text would render the IP unscrubbed in the \
         top-flows table. Either the observer populated flows with an \
         IP that wasn't observed as a host, or build_map missed an IP. \
         The fail-closed leak detector should catch this at write time, \
         but it's a bug worth surfacing in debug builds."
    );

    ScrubMap {
        version: 1,
        created_at: now,
        ips,
        macs,
        names,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::HostObs;
    use otsniff_privacy::{scrub_text, unscrub_text};
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
        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");
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

        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");

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

        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");

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
        let b2 = merge_map(b1, &obs_step2).expect("merge_map should succeed on test fixture");

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
        let b3 = merge_map(b2, &obs_step3).expect("merge_map should succeed on test fixture");

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

        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");

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

        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");

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

    /// AC-004 / leak detector: text scrubbed through a merged map must pass
    /// both the regex leak check and the map-value check with no leaks.
    ///
    /// Uses `otsniff_privacy::leak_detector::ensure_clean` (regex scan) and
    /// `otsniff_privacy::leak_detector::ensure_no_map_values` (map-value check).
    #[test]
    fn test_bc_5_03_001_leak_detector_passes_after_merge() {
        use otsniff_privacy::leak_detector;

        let baseline = scrub_map_from(
            &[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")],
            &[("mac_001", "AA:BB:CC:DD:EE:01")],
            &[("name_001", "PLC-NORTH")],
        );
        let obs = obs_with_ips(&["10.0.0.1", "10.0.0.99"]);

        let merged = merge_map(baseline, &obs).expect("merge_map should succeed on test fixture");

        // Text that references both a baseline IP and the new IP.
        let text = "PLC-NORTH at 10.0.0.1 (AA:BB:CC:DD:EE:01) reached 10.0.0.99.";
        let scrubbed = scrub_text(text, &merged);

        // Neither regex-pattern nor map-value leak must be present.
        leak_detector::ensure_clean(&scrubbed)
            .expect("regex leak check must pass after scrub with merged map");
        leak_detector::ensure_no_map_values(&scrubbed, &merged)
            .expect("map-value leak check must pass after scrub with merged map");
    }
}

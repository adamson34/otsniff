//! Cross-capture diff core (P1-3, S-6.02).
//!
//! Computes the delta between two captures using their merged ScrubMaps
//! (S-6.01) so identification is by pseudonym, not raw IP. Output is a
//! pure-data `Diff` struct; rendering lives in S-6.03.

use std::collections::{HashMap, HashSet};

use crate::findings::Finding;
use crate::inventory::{self, Asset};
use crate::observe::Observations;
use crate::scrub::ScrubMap;
use serde::Serialize;

/// Role inference result for a host. Mirror the shape used by inventory.
pub type Role = String;

/// A change in a host's inferred role between the baseline and current capture.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RoleShift {
    pub pseudonym: String,
    pub old_role: Role,
    pub new_role: Role,
}

/// A change in a single flow's traffic shape between baseline and current.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowDelta {
    pub src: String,
    pub dst: String,
    pub dst_port: u16,
    pub proto: String,
    /// Baseline byte count; None means the flow did not exist in baseline.
    pub baseline_bytes: Option<u64>,
    /// Current byte count; None means the flow disappeared in current.
    pub current_bytes: Option<u64>,
}

/// Top-level diff output. Pure data; renderer (S-6.03) consumes this.
///
/// Note: `Deserialize` is intentionally omitted — `Finding` contains
/// `&'static str` fields that do not implement `Deserialize`. The implementer
/// should address round-trip serialization in S-6.03 if needed.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Diff {
    pub hosts_new: Vec<Asset>,
    pub hosts_gone: Vec<Asset>,
    pub findings_new: Vec<Finding>,
    pub findings_recurring: Vec<Finding>,
    pub findings_resolved: Vec<Finding>,
    pub role_shifts: Vec<RoleShift>,
    pub flow_shifts: Vec<FlowDelta>,
}

/// Inputs to `compute`: each side carries its own observations + merged map
/// plus the pre-computed findings for that capture (AC-003, BC-3.08.002).
///
/// Findings are passed in here (rather than re-derived inside `compute`)
/// because the findings layer already ran as part of the normal report
/// pipeline and the diff doesn't need to re-parse the PCAP.
pub struct DiffInput<'a> {
    pub observations: &'a Observations,
    pub map: &'a ScrubMap,
    /// Pre-computed findings for this capture side.
    pub findings: &'a [Finding],
}

/// Configurable threshold for the flow-shift detector (AC-004). Default 2×.
pub const DEFAULT_FLOW_SHIFT_MULTIPLIER: f64 = 2.0;

/// Extract a finding's diff key: `(rule_id, src_pseudo, dst_pseudo, dst_port)`.
///
/// The key is parsed from the first evidence line, which may contain
/// `src=...`, `dst=...`, and `port=...` tokens (format produced by the test
/// helper and future detectors that adopt this convention). Falls back to
/// empty strings / zero port when evidence is absent or unparseable — two
/// findings with identical rule_id and no parseable evidence still compare
/// as equal, which is the conservative (matching) behaviour for recurring
/// findings.
fn finding_diff_key(finding: &Finding) -> (String, String, String, u16) {
    let rule_id = finding.id.to_string();

    // Best-effort: try to parse `src=...`, `dst=...`, `port=...` from evidence[0].
    let evidence = finding.evidence.first().map(String::as_str).unwrap_or("");

    let src = extract_kv(evidence, "src");
    let dst = extract_kv(evidence, "dst");
    let port: u16 = extract_kv(evidence, "port").parse().unwrap_or(0);

    (rule_id, src, dst, port)
}

/// Extract `key=value` from a space-separated evidence string.
/// Returns the value as a `String`, or an empty string if not found.
fn extract_kv(text: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    for token in text.split_whitespace() {
        if let Some(val) = token.strip_prefix(&prefix) {
            return val.to_string();
        }
    }
    String::new()
}

/// Compute the delta between two captures.
///
/// **AC-002 (BC-3.08.001):** identifies hosts by pseudonym, not raw IP.
/// **AC-003 (BC-3.08.002):** matches findings on `(rule_id, src_pseudo, dst_pseudo, dst_port)`.
/// **AC-004 (BC-3.08.003):** detects role inference changes and 2×-default flow-volume shifts.
/// **EC-002:** when maps share no pseudonyms, warns to stderr and proceeds (treating
/// it like EC-001: all current hosts are new, all baseline hosts are gone).
pub fn compute(baseline: DiffInput<'_>, current: DiffInput<'_>) -> Diff {
    // ---- EC-002: warn when maps share no pseudonyms -----------------------
    let base_pseudo_set: HashSet<&str> = baseline.map.ips.keys().map(String::as_str).collect();
    let curr_pseudo_set: HashSet<&str> = current.map.ips.keys().map(String::as_str).collect();
    if !base_pseudo_set.is_empty()
        && !curr_pseudo_set.is_empty()
        && base_pseudo_set.is_disjoint(&curr_pseudo_set)
    {
        eprintln!(
            "WARNING (EC-002): baseline map and current map share no IP pseudonyms. \
             Treating all hosts as new/gone. Verify that both maps were built from \
             the same pseudonym namespace (e.g. via `otsniff scrub --baseline-map`)."
        );
    }

    // ---- AC-002 (BC-3.08.001): host deltas --------------------------------
    //
    // Build a reverse index: real_ip_str → pseudonym, for each side.
    // Identification is by pseudonym, not raw IP.
    let base_ip_to_pseudo: HashMap<&str, &str> = baseline
        .map
        .ips
        .iter()
        .map(|(pseudo, real)| (real.as_str(), pseudo.as_str()))
        .collect();
    let curr_ip_to_pseudo: HashMap<&str, &str> = current
        .map
        .ips
        .iter()
        .map(|(pseudo, real)| (real.as_str(), pseudo.as_str()))
        .collect();

    // Collect pseudonyms actually present on each side (based on which hosts
    // appear in observations.hosts).
    let base_pseudonyms: HashSet<&str> = baseline
        .observations
        .hosts
        .keys()
        .filter_map(|ip| base_ip_to_pseudo.get(ip.to_string().as_str()).copied())
        .collect();
    let curr_pseudonyms: HashSet<&str> = current
        .observations
        .hosts
        .keys()
        .filter_map(|ip| curr_ip_to_pseudo.get(ip.to_string().as_str()).copied())
        .collect();

    // Build inventory for each side (role inference, etc.).
    let base_inventory = inventory::build(baseline.observations);
    let curr_inventory = inventory::build(current.observations);

    // Index inventory by IP for quick lookup.
    let base_asset_by_ip: HashMap<std::net::IpAddr, &Asset> =
        base_inventory.iter().map(|a| (a.ip, a)).collect();
    let curr_asset_by_ip: HashMap<std::net::IpAddr, &Asset> =
        curr_inventory.iter().map(|a| (a.ip, a)).collect();

    // hosts_new = current pseudonyms not in baseline pseudonym set.
    let mut hosts_new: Vec<Asset> = current
        .observations
        .hosts
        .keys()
        .filter(|ip| {
            let pseudo = curr_ip_to_pseudo
                .get(ip.to_string().as_str())
                .copied()
                .unwrap_or("");
            !base_pseudonyms.contains(pseudo)
        })
        .filter_map(|ip| curr_asset_by_ip.get(ip).copied().cloned())
        .collect();
    hosts_new.sort_by_key(|a| a.ip);

    // hosts_gone = baseline pseudonyms not in current pseudonym set.
    let mut hosts_gone: Vec<Asset> = baseline
        .observations
        .hosts
        .keys()
        .filter(|ip| {
            let pseudo = base_ip_to_pseudo
                .get(ip.to_string().as_str())
                .copied()
                .unwrap_or("");
            !curr_pseudonyms.contains(pseudo)
        })
        .filter_map(|ip| base_asset_by_ip.get(ip).copied().cloned())
        .collect();
    hosts_gone.sort_by_key(|a| a.ip);

    // ---- AC-003 (BC-3.08.002): finding deltas -----------------------------
    //
    // Match by exact tuple (rule_id, src_pseudo, dst_pseudo, dst_port).
    let base_keys: HashMap<(String, String, String, u16), &Finding> = baseline
        .findings
        .iter()
        .map(|f| (finding_diff_key(f), f))
        .collect();
    let curr_keys: HashMap<(String, String, String, u16), &Finding> = current
        .findings
        .iter()
        .map(|f| (finding_diff_key(f), f))
        .collect();

    let base_key_set: HashSet<&(String, String, String, u16)> = base_keys.keys().collect();
    let curr_key_set: HashSet<&(String, String, String, u16)> = curr_keys.keys().collect();

    // findings_new: in current but not in baseline.
    let mut findings_new: Vec<Finding> = curr_key_set
        .difference(&base_key_set)
        .filter_map(|k| curr_keys.get(*k).copied().cloned())
        .collect();
    findings_new.sort_by(|a, b| a.id.cmp(b.id));

    // findings_resolved: in baseline but not in current.
    let mut findings_resolved: Vec<Finding> = base_key_set
        .difference(&curr_key_set)
        .filter_map(|k| base_keys.get(*k).copied().cloned())
        .collect();
    findings_resolved.sort_by(|a, b| a.id.cmp(b.id));

    // findings_recurring: in both.
    let mut findings_recurring: Vec<Finding> = curr_key_set
        .intersection(&base_key_set)
        .filter_map(|k| curr_keys.get(*k).copied().cloned())
        .collect();
    findings_recurring.sort_by(|a, b| a.id.cmp(b.id));

    // ---- AC-004 (BC-3.08.003): role shifts --------------------------------
    //
    // For each pseudonym present in BOTH captures, compare inferred roles.
    // Build a map: pseudonym → IP for each side.
    let base_pseudo_to_ip: HashMap<&str, std::net::IpAddr> = baseline
        .map
        .ips
        .iter()
        .filter_map(|(pseudo, real)| {
            real.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| (pseudo.as_str(), ip))
        })
        .collect();
    let curr_pseudo_to_ip: HashMap<&str, std::net::IpAddr> = current
        .map
        .ips
        .iter()
        .filter_map(|(pseudo, real)| {
            real.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| (pseudo.as_str(), ip))
        })
        .collect();

    let shared_pseudonyms: HashSet<&str> = base_pseudonyms
        .intersection(&curr_pseudonyms)
        .copied()
        .collect();

    let mut role_shifts: Vec<RoleShift> = shared_pseudonyms
        .iter()
        .filter_map(|&pseudo| {
            let base_ip = base_pseudo_to_ip.get(pseudo)?;
            let curr_ip = curr_pseudo_to_ip.get(pseudo)?;
            let base_asset = base_asset_by_ip.get(base_ip)?;
            let curr_asset = curr_asset_by_ip.get(curr_ip)?;
            let old_role = base_asset.role.label().to_string();
            let new_role = curr_asset.role.label().to_string();
            if old_role != new_role {
                Some(RoleShift {
                    pseudonym: pseudo.to_string(),
                    old_role,
                    new_role,
                })
            } else {
                None
            }
        })
        .collect();
    role_shifts.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));

    // ---- AC-004 (BC-3.08.003): flow shifts --------------------------------
    //
    // Key flows by pseudonymized (src, dst, dst_port, proto).
    // Build lookup: real_ip_str → pseudonym (both sides merged, prefer
    // current map; falls back to raw IP string if not in either map).
    let ip_to_pseudo = |ip: std::net::IpAddr, map: &ScrubMap| -> String {
        let ip_str = ip.to_string();
        // Try current map first, then baseline map.
        map.ips
            .iter()
            .find(|(_, v)| v.as_str() == ip_str)
            .map(|(k, _)| k.clone())
            .unwrap_or(ip_str)
    };

    // Build flow key maps: pseudonymized key → bytes.
    // Pseudonymized flow key: (src_pseudo, dst_pseudo, dst_port, proto_num)
    type FlowPseudoKey = (String, String, u16, u8);

    let base_flows: HashMap<FlowPseudoKey, u64> = baseline
        .observations
        .flows
        .values()
        .map(|f| {
            let src_pseudo = ip_to_pseudo(f.key.src, baseline.map);
            let dst_pseudo = ip_to_pseudo(f.key.dst, baseline.map);
            (
                (src_pseudo, dst_pseudo, f.key.dst_port, f.key.proto),
                f.bytes,
            )
        })
        .collect();

    let curr_flows: HashMap<FlowPseudoKey, u64> = current
        .observations
        .flows
        .values()
        .map(|f| {
            let src_pseudo = ip_to_pseudo(f.key.src, current.map);
            let dst_pseudo = ip_to_pseudo(f.key.dst, current.map);
            (
                (src_pseudo, dst_pseudo, f.key.dst_port, f.key.proto),
                f.bytes,
            )
        })
        .collect();

    let all_flow_keys: HashSet<&FlowPseudoKey> =
        base_flows.keys().chain(curr_flows.keys()).collect();

    let multiplier = DEFAULT_FLOW_SHIFT_MULTIPLIER;
    let mut flow_shifts: Vec<FlowDelta> = all_flow_keys
        .iter()
        .filter_map(|key| {
            let base_bytes = base_flows.get(*key).copied();
            let curr_bytes = curr_flows.get(*key).copied();
            let proto_str = proto_label(key.3);
            match (base_bytes, curr_bytes) {
                (None, Some(cb)) => Some(FlowDelta {
                    src: key.0.clone(),
                    dst: key.1.clone(),
                    dst_port: key.2,
                    proto: proto_str,
                    baseline_bytes: None,
                    current_bytes: Some(cb),
                }),
                (Some(bb), None) => Some(FlowDelta {
                    src: key.0.clone(),
                    dst: key.1.clone(),
                    dst_port: key.2,
                    proto: proto_str,
                    baseline_bytes: Some(bb),
                    current_bytes: None,
                }),
                (Some(bb), Some(cb)) => {
                    // Volume-shift check: max/min >= multiplier threshold.
                    // Both are > 0 (flow exists means at least 1 byte); guard
                    // against division by zero anyway.
                    let (hi, lo) = if cb >= bb { (cb, bb) } else { (bb, cb) };
                    if lo == 0 || (hi as f64 / lo as f64) >= multiplier {
                        Some(FlowDelta {
                            src: key.0.clone(),
                            dst: key.1.clone(),
                            dst_port: key.2,
                            proto: proto_str,
                            baseline_bytes: Some(bb),
                            current_bytes: Some(cb),
                        })
                    } else {
                        None
                    }
                }
                (None, None) => None,
            }
        })
        .collect();
    flow_shifts.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
    });

    Diff {
        hosts_new,
        hosts_gone,
        findings_new,
        findings_recurring,
        findings_resolved,
        role_shifts,
        flow_shifts,
    }
}

/// Human-readable protocol label for use in `FlowDelta.proto`.
fn proto_label(proto: u8) -> String {
    match proto {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        1 => "icmp".to_string(),
        _ => format!("ip/{proto}"),
    }
}

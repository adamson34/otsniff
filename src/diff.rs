//! Cross-capture diff core (P1-3, S-6.02).
//!
//! Computes the delta between two captures using their merged ScrubMaps
//! (S-6.01) so identification is by pseudonym, not raw IP. Output is a
//! pure-data `Diff` struct; rendering lives in S-6.03.
//!
//! The output is fully pseudonymized — no real IPs, MACs, or hostnames
//! reach the `Diff` data structure (F-W2-003). Host references use a
//! `HostRef` type (a pseudonym + behavioral fields) instead of `Asset`.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use crate::findings::Finding;
use crate::inventory::{self, Asset};
use crate::observe::Observations;
use crate::scrub::ScrubMap;
use regex::Regex;
use serde::Serialize;

/// Role inference result for a host. Mirror the shape used by inventory.
pub type Role = String;

/// A pseudonymized reference to a host in the diff output.
///
/// **F-W2-003:** the diff's output must never carry real identifiers (raw IP,
/// MAC, vendor lookup against MAC, or DHCP hostname). `HostRef` keeps the
/// behavioral fields a downstream renderer actually needs — role, protocols
/// spoken, packet/byte counts, zone classification — and replaces every
/// real-identifier field with the host's pseudonym.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostRef {
    /// Stable pseudonym (e.g. `host_001`) drawn from the merged scrub map.
    /// Falls back to `unmapped:<ip>` if the asset's IP is not in the map —
    /// callers should treat this fallback as a map-coverage warning.
    pub pseudonym: String,
    /// Role inference label (e.g. `"plc"`, `"hmi"`, `"engineering"`).
    pub role: Role,
    /// Protocols this host was observed speaking, sorted.
    pub protocols: Vec<String>,
    pub packets: u64,
    pub bytes: u64,
    pub in_ot_zone: bool,
}

impl HostRef {
    /// Build a `HostRef` from an `Asset` by resolving the asset's IP to its
    /// pseudonym in `map`. Strips the IP, MAC, vendor, and hostname fields.
    pub fn from_asset(asset: &Asset, map: &ScrubMap) -> Self {
        // F-ADV-P2-002: previously this fell back to `format!("unmapped:{}",
        // asset.ip)` — embedding the raw IP with a known prefix. Now we use
        // a hash-based opaque label so map misses don't leak the IP.
        let pseudonym = resolve_ip_to_pseudonym(&asset.ip.to_string(), map)
            .unwrap_or_else(|| unmapped_label(&asset.ip.to_string()));
        HostRef {
            pseudonym,
            role: asset.role.label().to_string(),
            protocols: asset.protocols.clone(),
            packets: asset.packets,
            bytes: asset.bytes,
            in_ot_zone: asset.in_ot_zone,
        }
    }
}

/// A change in a host's inferred role between the baseline and current capture.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RoleShift {
    pub pseudonym: String,
    pub old_role: Role,
    pub new_role: Role,
}

/// A summary of a single flow's pseudonymized endpoints + byte count.
///
/// Used by `flows_new` / `flows_gone` (F-W2-002 split) to enumerate flows
/// that appeared in only one capture without padding `flow_shifts` with
/// every disjoint flow.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowSummary {
    pub src: String,
    pub dst: String,
    pub dst_port: u16,
    pub proto: String,
    pub bytes: u64,
}

/// A volume shift on a flow that exists in BOTH captures.
///
/// **F-W2-002:** `FlowDelta` is now reserved for flows whose `max/min` byte
/// ratio meets or exceeds the configured `flow_shift_multiplier`. Flows that
/// exist on only one side go into `Diff::flows_new` or `Diff::flows_gone`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FlowDelta {
    pub src: String,
    pub dst: String,
    pub dst_port: u16,
    pub proto: String,
    pub baseline_bytes: u64,
    pub current_bytes: u64,
    /// `max / min` ratio. Always ≥ `flow_shift_multiplier` for entries
    /// in `flow_shifts`.
    pub ratio: f64,
}

/// Top-level diff output. Pure data; renderer (S-6.03) consumes this.
///
/// Note: `Deserialize` is intentionally omitted — `Finding` contains
/// `&'static str` fields that do not implement `Deserialize`. The implementer
/// should address round-trip serialization in S-6.03 if needed.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Diff {
    /// Hosts present in `current` whose pseudonym is absent from `baseline`.
    pub hosts_new: Vec<HostRef>,
    /// Hosts present in `baseline` whose pseudonym is absent from `current`.
    pub hosts_gone: Vec<HostRef>,
    pub findings_new: Vec<Finding>,
    pub findings_recurring: Vec<Finding>,
    pub findings_resolved: Vec<Finding>,
    pub role_shifts: Vec<RoleShift>,
    /// **F-W2-002:** flows whose volume changed by `>= multiplier` AND that
    /// exist in both captures. Per-flow byte counts are kept so the renderer
    /// can show the direction of the change.
    pub flow_shifts: Vec<FlowDelta>,
    /// **F-W2-002:** flows present in `current` but not in `baseline`.
    pub flows_new: Vec<FlowSummary>,
    /// **F-W2-002:** flows present in `baseline` but not in `current`.
    pub flows_gone: Vec<FlowSummary>,
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

// ----------------------------------------------------------------------------
// F-W2-004: structured finding-endpoint extraction
//
// Real detectors emit evidence in three families:
//   A. "<ip> -> <ip>:<port> : <descriptor>"   — most cross-zone findings
//   B. "<ip>:<port> (...)"                    — server-side findings
//      (creds.ftp, creds.telnet, creds.http_basic, creds.snmp, …)
//   C. pseudonymized "host_NNN -> host_NNN:port"
//      (engineering_commands rendered post-scrub)
//
// The test-helper format `src=X dst=Y port=Z` is also recognised so the
// existing test fixtures keep working without rewrite.
//
// If no pattern matches, the key falls back to (rule_id, "", "", 0) and
// findings of the same `rule_id` will collide. This is an HONEST limitation:
// rule_id-only matching is the v1 floor when evidence isn't endpoint-shaped.
// The renderer (S-6.03) should call this out so reviewers know the diff is
// rolling up at rule-id granularity for such findings.
// ----------------------------------------------------------------------------

static IPV4: &str = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";

static PATTERN_IP_ARROW_IP_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({IPV4})\s*->\s*({IPV4}):(\d+)")).expect("valid regex"));
static PATTERN_IP_ARROW_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({IPV4})\s*->\s*({IPV4})")).expect("valid regex"));
static PATTERN_IP_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"({IPV4}):(\d+)")).expect("valid regex"));
static PATTERN_PSEUDO_ARROW_PSEUDO_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(host_\d+)\s*->\s*(host_\d+):(\d+)").expect("valid regex"));
static PATTERN_PSEUDO_ARROW_PSEUDO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(host_\d+)\s*->\s*(host_\d+)").expect("valid regex"));
/// Server-side pseudonymized endpoint with port — matches evidence like
/// `"host_049:21 (34 packet(s))"` after F-W2-003's scrubbing pass.
static PATTERN_PSEUDO_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(host_\d+):(\d+)").expect("valid regex"));

/// Extract a finding's diff key. Pseudonymizes any raw IPs via `map`.
///
/// Order matters: more specific patterns (with explicit ports) are tried
/// first so that a richer match doesn't get clipped by a less specific one.
fn finding_diff_key(finding: &Finding, map: &ScrubMap) -> (String, String, String, u16) {
    let rule_id = finding.id.to_string();
    let evidence = finding.evidence.first().map(String::as_str).unwrap_or("");

    // Test-helper format (back-compat): "src=X dst=Y port=Z"
    //
    // F-ADV-P4-003: require ALL THREE tokens to be present before taking
    // this branch. The previous OR-condition would short-circuit on any
    // future production evidence that happened to contain a whitespace-
    // delimited `port=NNN` token (e.g. a recommendation string referencing
    // a port number), producing a wrong tuple key. Requiring all three
    // makes the test format unambiguous and the production-collision
    // surface vanishingly small.
    let test_src = extract_kv(evidence, "src");
    let test_dst = extract_kv(evidence, "dst");
    let test_port_str = extract_kv(evidence, "port");
    if !test_src.is_empty() && !test_dst.is_empty() && !test_port_str.is_empty() {
        let test_port: u16 = test_port_str.parse().unwrap_or(0);
        return (
            rule_id,
            resolve_endpoint(&test_src, map),
            resolve_endpoint(&test_dst, map),
            test_port,
        );
    }

    // Already-pseudonymized "host_NNN -> host_NNN:port"
    if let Some(caps) = PATTERN_PSEUDO_ARROW_PSEUDO_PORT.captures(evidence) {
        return (
            rule_id,
            caps[1].to_string(),
            caps[2].to_string(),
            caps[3].parse().unwrap_or(0),
        );
    }

    // Raw "IP -> IP:port"
    if let Some(caps) = PATTERN_IP_ARROW_IP_PORT.captures(evidence) {
        return (
            rule_id,
            resolve_endpoint(&caps[1], map),
            resolve_endpoint(&caps[2], map),
            caps[3].parse().unwrap_or(0),
        );
    }

    // Already-pseudonymized "host_NNN -> host_NNN" (no port)
    if let Some(caps) = PATTERN_PSEUDO_ARROW_PSEUDO.captures(evidence) {
        return (rule_id, caps[1].to_string(), caps[2].to_string(), 0);
    }

    // Raw "IP -> IP" (no port)
    if let Some(caps) = PATTERN_IP_ARROW_IP.captures(evidence) {
        return (
            rule_id,
            resolve_endpoint(&caps[1], map),
            resolve_endpoint(&caps[2], map),
            0,
        );
    }

    // Server-side pseudo `host_NNN:port` (matches AFTER F-W2-003 scrubbing).
    if let Some(caps) = PATTERN_PSEUDO_PORT.captures(evidence) {
        return (
            rule_id,
            String::new(),
            caps[1].to_string(),
            caps[2].parse().unwrap_or(0),
        );
    }

    // Server-side raw "IP:port" — only the destination is known.
    if let Some(caps) = PATTERN_IP_PORT.captures(evidence) {
        return (
            rule_id,
            String::new(),
            resolve_endpoint(&caps[1], map),
            caps[2].parse().unwrap_or(0),
        );
    }

    // No endpoint pattern matched — degenerate key (rule-id only).
    (rule_id, String::new(), String::new(), 0)
}

/// Extract `key=value` from a space-separated evidence string.
fn extract_kv(text: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    for token in text.split_whitespace() {
        if let Some(val) = token.strip_prefix(&prefix) {
            return val.to_string();
        }
    }
    String::new()
}

/// Resolve a raw IP (or pseudonym) to its pseudonym via the map.
/// - Already-pseudonymized strings (`host_NNN` / `mac_NNN` / `name_NNN`)
///   pass through unchanged.
/// - Empty strings pass through unchanged.
/// - Raw IPs are looked up in `map.ips`; if absent, an opaque
///   `unmapped_<hash>` label is returned — never the raw value.
///
/// ADV-W2-001: the map-miss fallback emits `unmapped_label` rather than
/// returning the raw input, matching the `ip_to_pseudo` closure used on the
/// serialized-output path. This keeps the function fail-closed on its own,
/// so a diff key can never carry a real IP even if a future caller routes
/// its return value into serialized output.
fn resolve_endpoint(s: &str, map: &ScrubMap) -> String {
    if s.is_empty() || is_pseudonym(s) {
        return s.to_string();
    }
    resolve_ip_to_pseudonym(s, map).unwrap_or_else(|| unmapped_label(s))
}

/// True if `s` already carries a canonical scrub pseudonym prefix
/// (`host_` / `mac_` / `name_`) and must pass through unchanged.
fn is_pseudonym(s: &str) -> bool {
    s.starts_with("host_") || s.starts_with("mac_") || s.starts_with("name_")
}

/// Look up an IP string in the map and return its pseudonym if present.
fn resolve_ip_to_pseudonym(ip: &str, map: &ScrubMap) -> Option<String> {
    map.ips
        .iter()
        .find(|(_, real)| real.as_str() == ip)
        .map(|(pseudo, _)| pseudo.clone())
}

// ----------------------------------------------------------------------------
// compute()
// ----------------------------------------------------------------------------

/// Compute the delta between two captures.
///
/// - **AC-002 (BC-3.08.001):** identifies hosts by pseudonym. Outputs use
///   `HostRef` (pseudonym + behavioral fields), never `Asset` (which carries
///   raw IPs / MACs).
/// - **AC-003 (BC-3.08.002):** matches findings on
///   `(rule_id, src_pseudo, dst_pseudo, dst_port)`. Endpoint extraction
///   handles the three real evidence formats; falls back to `(rule_id, "", "", 0)`
///   for findings without endpoint-shaped evidence (documented limitation).
/// - **AC-004 (BC-3.08.003):** role-inference changes and flow-volume shifts.
///   Flows existing in only one capture are now in `flows_new`/`flows_gone`
///   (F-W2-002 split); `flow_shifts` is reserved for both-sides shifts at
///   or above the multiplier threshold.
/// - **EC-002:** when maps share no pseudonyms, warns to stderr and proceeds.
///
/// Uses `DEFAULT_FLOW_SHIFT_MULTIPLIER` for the flow-shift threshold. For a
/// custom threshold call [`compute_with_multiplier`].
pub fn compute(baseline: DiffInput<'_>, current: DiffInput<'_>) -> Diff {
    compute_with_multiplier(baseline, current, DEFAULT_FLOW_SHIFT_MULTIPLIER)
}

/// Same as [`compute`] but with a caller-supplied flow-shift multiplier.
///
/// **F-ADV-P1-002:** the CLI previously only post-filtered `flow_shifts` for a
/// user-supplied multiplier, which silently no-op'd values < 2.0 (the dropped
/// flows were already gone). Now the multiplier flows into `compute` and is
/// applied inside the ratio loop, so any value ≥ 1.0 behaves correctly.
pub fn compute_with_multiplier(
    baseline: DiffInput<'_>,
    current: DiffInput<'_>,
    flow_shift_multiplier: f64,
) -> Diff {
    // ---- EC-002 ----------------------------------------------------------
    let base_pseudo_set: HashSet<&str> = baseline.map.ips.keys().map(String::as_str).collect();
    let curr_pseudo_set: HashSet<&str> = current.map.ips.keys().map(String::as_str).collect();
    if !base_pseudo_set.is_empty()
        && !curr_pseudo_set.is_empty()
        && base_pseudo_set.is_disjoint(&curr_pseudo_set)
    {
        eprintln!(
            "WARNING (EC-002): baseline map and current map share no IP pseudonyms. \
             Treating all hosts as new/gone. Verify both maps were built from the \
             same pseudonym namespace (e.g. via `otsniff scrub --baseline-map`)."
        );
    }

    // ---- AC-002: host deltas (pseudonym-keyed) ---------------------------
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

    let base_inventory = inventory::build(baseline.observations);
    let curr_inventory = inventory::build(current.observations);

    let base_asset_by_ip: HashMap<std::net::IpAddr, &Asset> =
        base_inventory.iter().map(|a| (a.ip, a)).collect();
    let curr_asset_by_ip: HashMap<std::net::IpAddr, &Asset> =
        curr_inventory.iter().map(|a| (a.ip, a)).collect();

    let mut hosts_new: Vec<HostRef> = current
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
        .filter_map(|ip| curr_asset_by_ip.get(ip).copied())
        .map(|asset| HostRef::from_asset(asset, current.map))
        .collect();
    hosts_new.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));

    let mut hosts_gone: Vec<HostRef> = baseline
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
        .filter_map(|ip| base_asset_by_ip.get(ip).copied())
        .map(|asset| HostRef::from_asset(asset, baseline.map))
        .collect();
    hosts_gone.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));

    // ---- AC-003: finding deltas ------------------------------------------
    //
    // F-W2-003 (extended): pseudonymize finding evidence + summary BEFORE
    // tuple extraction. Findings come from the normal analyze pipeline with
    // raw IPs in evidence strings; the diff output must be pseudonym-safe so
    // it can be shown to the same audience as a scrubbed report. We apply
    // `scrub_text` to each finding's evidence and summary using the
    // appropriate side's map, then compute keys against the scrubbed copies.
    let base_scrubbed: Vec<Finding> = baseline
        .findings
        .iter()
        .map(|f| scrub_finding(f, baseline.map))
        .collect();
    let curr_scrubbed: Vec<Finding> = current
        .findings
        .iter()
        .map(|f| scrub_finding(f, current.map))
        .collect();

    let base_keys: HashMap<(String, String, String, u16), &Finding> = base_scrubbed
        .iter()
        .map(|f| (finding_diff_key(f, baseline.map), f))
        .collect();
    let curr_keys: HashMap<(String, String, String, u16), &Finding> = curr_scrubbed
        .iter()
        .map(|f| (finding_diff_key(f, current.map), f))
        .collect();

    let base_key_set: HashSet<&(String, String, String, u16)> = base_keys.keys().collect();
    let curr_key_set: HashSet<&(String, String, String, u16)> = curr_keys.keys().collect();

    let mut findings_new: Vec<Finding> = curr_key_set
        .difference(&base_key_set)
        .filter_map(|k| curr_keys.get(*k).copied().cloned())
        .collect();
    findings_new.sort_by(|a, b| a.id.cmp(b.id));

    let mut findings_resolved: Vec<Finding> = base_key_set
        .difference(&curr_key_set)
        .filter_map(|k| base_keys.get(*k).copied().cloned())
        .collect();
    findings_resolved.sort_by(|a, b| a.id.cmp(b.id));

    let mut findings_recurring: Vec<Finding> = curr_key_set
        .intersection(&base_key_set)
        .filter_map(|k| curr_keys.get(*k).copied().cloned())
        .collect();
    findings_recurring.sort_by(|a, b| a.id.cmp(b.id));

    // ---- AC-004: role shifts ---------------------------------------------
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

    // ---- AC-004 / F-W2-002: flow shifts split into 3 buckets -------------
    //
    // F-ADV-P2-002: previously this returned the raw IP string on map miss
    // (`.unwrap_or(ip_str)`), which emitted real IPs into the FlowSummary /
    // FlowDelta fields of the JSON output. Now we return an opaque
    // hash-based label so unmapped flows are visible to the renderer but
    // carry no real identifier. The downstream `ensure_clean` /
    // `ensure_no_map_values` checks in `run_diff` are the fail-closed
    // backstop if this fallback ever fires.
    let ip_to_pseudo = |ip: std::net::IpAddr, map: &ScrubMap| -> String {
        let ip_str = ip.to_string();
        map.ips
            .iter()
            .find(|(_, v)| v.as_str() == ip_str)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| unmapped_label(&ip_str))
    };

    type FlowPseudoKey = (String, String, u16, u8);

    let base_flows: HashMap<FlowPseudoKey, u64> = baseline
        .observations
        .flows
        .values()
        .map(|f| {
            (
                (
                    ip_to_pseudo(f.key.src, baseline.map),
                    ip_to_pseudo(f.key.dst, baseline.map),
                    f.key.dst_port,
                    f.key.proto,
                ),
                f.bytes,
            )
        })
        .collect();

    let curr_flows: HashMap<FlowPseudoKey, u64> = current
        .observations
        .flows
        .values()
        .map(|f| {
            (
                (
                    ip_to_pseudo(f.key.src, current.map),
                    ip_to_pseudo(f.key.dst, current.map),
                    f.key.dst_port,
                    f.key.proto,
                ),
                f.bytes,
            )
        })
        .collect();

    let all_flow_keys: HashSet<&FlowPseudoKey> =
        base_flows.keys().chain(curr_flows.keys()).collect();

    let multiplier = flow_shift_multiplier;

    let mut flows_new: Vec<FlowSummary> = Vec::new();
    let mut flows_gone: Vec<FlowSummary> = Vec::new();
    let mut flow_shifts: Vec<FlowDelta> = Vec::new();

    for key in all_flow_keys {
        let base_bytes = base_flows.get(key).copied();
        let curr_bytes = curr_flows.get(key).copied();
        let proto_str = proto_label(key.3);
        match (base_bytes, curr_bytes) {
            (None, Some(cb)) => flows_new.push(FlowSummary {
                src: key.0.clone(),
                dst: key.1.clone(),
                dst_port: key.2,
                proto: proto_str,
                bytes: cb,
            }),
            (Some(bb), None) => flows_gone.push(FlowSummary {
                src: key.0.clone(),
                dst: key.1.clone(),
                dst_port: key.2,
                proto: proto_str,
                bytes: bb,
            }),
            (Some(bb), Some(cb)) => {
                let (hi, lo) = if cb >= bb { (cb, bb) } else { (bb, cb) };
                if lo == 0 {
                    continue;
                }
                let ratio = hi as f64 / lo as f64;
                if ratio >= multiplier {
                    flow_shifts.push(FlowDelta {
                        src: key.0.clone(),
                        dst: key.1.clone(),
                        dst_port: key.2,
                        proto: proto_str,
                        baseline_bytes: bb,
                        current_bytes: cb,
                        ratio,
                    });
                }
            }
            (None, None) => {}
        }
    }

    flows_new.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
    });
    flows_gone.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
    });
    flow_shifts.sort_by(|a, b| {
        // Largest-ratio first so the renderer can show the loudest signals.
        b.ratio
            .partial_cmp(&a.ratio)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.src.cmp(&b.src))
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
        flows_new,
        flows_gone,
    }
}

/// F-W2-003: pseudonymize a Finding's evidence + summary using `map`.
/// Title, recommendation, and playbook steps are also scrubbed since they
/// can interpolate real IPs (e.g. recommendation: "rotate creds on 192.168.1.5").
fn scrub_finding(f: &Finding, map: &ScrubMap) -> Finding {
    Finding {
        id: f.id,
        severity: f.severity,
        title: crate::scrub::scrub_text(&f.title, map),
        summary: crate::scrub::scrub_text(&f.summary, map),
        evidence: f
            .evidence
            .iter()
            .map(|e| crate::scrub::scrub_text(e, map))
            .collect(),
        recommendation: f.recommendation,
        playbook: f
            .playbook
            .iter()
            .map(|step| crate::scrub::scrub_text(step, map))
            .collect(),
    }
}

/// F-ADV-P2-002 (strengthened by F-ADV-P3-006): produce an opaque label for
/// an IP that's not in the scrub map. The label has a recognisable prefix
/// (so a renderer can flag it as "unmapped — likely indicates baseline/
/// current map mismatch") but does NOT carry the raw IP.
///
/// **F-ADV-P3-006:** the original implementation used only 16 bits of
/// SHA-256 (2 hex chars = 65,536 possible values), which is trivially
/// brute-forceable against any small IP candidate space (a /24 subnet has
/// 256 IPs; recovering all the mappings is sub-second). This version uses:
///   1. **64 bits of SHA-256 prefix** (16 hex chars), raising the brute-force
///      cost from O(2^16) to O(2^64) per recovery attempt.
///   2. **Per-process random salt** — the salt is initialised once per
///      `otsniff diff` invocation. Two diff runs against the same IP
///      produce *different* unmapped labels, so an attacker cannot reuse
///      a rainbow table across runs.
fn unmapped_label(ip_str: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(UNMAPPED_SALT.as_bytes());
    hasher.update(ip_str.as_bytes());
    let digest = hasher.finalize();
    format!(
        "unmapped_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    )
}

/// Per-process random salt for `unmapped_label`. Initialised once on first
/// access to a cryptographically-random 32-byte hex string. The salt is
/// NOT exposed; only the hashed labels appear in output.
static UNMAPPED_SALT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    // Mix system time + process ID into the salt. Not cryptographically
    // perfect (no OsRng) but sufficient for the threat model: an attacker
    // observing diff output cannot predict the salt for that specific run.
    // For stronger guarantees, callers can supply `OTSNIFF_UNMAPPED_SALT`
    // env var (used primarily for tests that need deterministic output).
    if let Ok(env_salt) = std::env::var("OTSNIFF_UNMAPPED_SALT") {
        return env_salt;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
});

/// Human-readable protocol label for use in `FlowDelta.proto`.
fn proto_label(proto: u8) -> String {
    match proto {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        1 => "icmp".to_string(),
        _ => format!("ip/{proto}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn scrub_map(entries: &[(&str, &str)]) -> ScrubMap {
        ScrubMap {
            version: 1,
            created_at: Utc::now(),
            ips: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            macs: BTreeMap::new(),
            names: BTreeMap::new(),
        }
    }

    fn finding_with_evidence(evidence: &str) -> Finding {
        Finding {
            id: "test.rule",
            severity: Severity::Medium,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: vec![evidence.to_string()],
            recommendation: "r",
            playbook: vec![],
        }
    }

    // finding_diff_key: the test-format branch (F-ADV-P4-003) requires ALL
    // THREE of src/dst/port to be present. Each `&&` in that guard must hold;
    // mutating either to `||` would let partial-field evidence wrongly take
    // the branch and produce a mismatched tuple key.

    #[test]
    fn finding_diff_key_test_format_requires_all_three_tokens() {
        let map = scrub_map(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);
        let f = finding_with_evidence("src=10.0.0.1 dst=10.0.0.2 port=502");
        assert_eq!(
            finding_diff_key(&f, &map),
            (
                "test.rule".to_string(),
                "host_001".to_string(),
                "host_002".to_string(),
                502
            ),
            "all three tokens present should take the test-format branch and resolve endpoints",
        );
    }

    #[test]
    fn finding_diff_key_missing_dst_does_not_take_test_branch() {
        let map = scrub_map(&[("host_001", "10.0.0.1")]);
        // dst token absent → the all-three guard must be false → fall through
        // to the degenerate default (no IP-arrow / IP:port shape present).
        let f = finding_with_evidence("src=10.0.0.1 port=502");
        assert_eq!(
            finding_diff_key(&f, &map),
            ("test.rule".to_string(), String::new(), String::new(), 0),
            "missing dst must NOT take the test-format branch (guards the && in the all-three check)",
        );
    }

    #[test]
    fn finding_diff_key_missing_port_does_not_take_test_branch() {
        let map = scrub_map(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);
        let f = finding_with_evidence("src=10.0.0.1 dst=10.0.0.2");
        assert_eq!(
            finding_diff_key(&f, &map),
            ("test.rule".to_string(), String::new(), String::new(), 0),
            "missing port must NOT take the test-format branch (guards the second && in the check)",
        );
    }

    // resolve_endpoint: pseudonymizes raw IPs, passes `host_NNN` and empty
    // strings through unchanged. Asserting concrete non-empty returns kills
    // whole-body replacement mutants (String::new() / "xyzzy".into()).

    #[test]
    fn resolve_endpoint_maps_raw_ip_to_pseudonym() {
        let map = scrub_map(&[("host_001", "10.0.0.1")]);
        assert_eq!(resolve_endpoint("10.0.0.1", &map), "host_001");
    }

    #[test]
    fn resolve_endpoint_passes_through_pseudonym_unchanged() {
        let map = scrub_map(&[("host_001", "10.0.0.1")]);
        // ADV-W2-004: all canonical pseudonym prefixes pass through unchanged.
        assert_eq!(resolve_endpoint("host_005", &map), "host_005");
        assert_eq!(resolve_endpoint("mac_005", &map), "mac_005");
        assert_eq!(resolve_endpoint("name_005", &map), "name_005");
    }

    #[test]
    fn resolve_endpoint_unmapped_ip_yields_opaque_label_not_raw() {
        let map = scrub_map(&[("host_001", "10.0.0.1")]);
        // ADV-W2-001: a genuine map-miss must NOT leak the raw IP; it emits an
        // opaque unmapped_<hash> label instead (fail-closed, like ip_to_pseudo).
        let out = resolve_endpoint("192.168.1.1", &map);
        assert_ne!(out, "192.168.1.1", "map-miss must not return the raw IP");
        assert!(
            out.starts_with("unmapped_"),
            "map-miss must yield an unmapped_<hash> label, got {out}"
        );
    }
}

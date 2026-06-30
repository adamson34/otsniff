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

/// Segmentation-drift section (P1-13). Present on `Diff` only when BOTH diff
/// inputs carried a Zonewarden `ConformanceResult` (i.e. `diff --policy`).
///
/// One policy scores both captures (single-policy-held-constant — see
/// `docs/specs/segmentation-drift.md`), so `policy_digest` is identical on both
/// sides by construction and recorded here as a displayed audit anchor.
///
/// **Privacy:** every endpoint in `violations_*` is a pseudonym resolved through
/// the side's `ScrubMap` at construction time; raw IPs from the underlying
/// `Violation` rows never reach this struct.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SegmentationDrift {
    /// SHA-256 of the policy document the drift was measured against. Identical
    /// on both sides (one policy); a displayed audit anchor, not a comparison.
    pub policy_digest: String,
    /// One row per conformance metric, in a fixed order (see [`TALLY_METRICS`]).
    pub tally: Vec<TallyDelta>,
    /// Violations present in current but not baseline (matched on the scrubbed key).
    pub violations_new: Vec<ViolationRef>,
    /// Violations present in baseline but not current.
    pub violations_resolved: Vec<ViolationRef>,
    /// Violations present in both captures.
    pub violations_persisting: Vec<ViolationRef>,
}

/// Baseline → current movement of a single conformance tally metric. The
/// direction (▲/▼/—) is derived in the view layer via `current.cmp(&baseline)`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TallyDelta {
    /// Metric id, e.g. `"idmz_bypasses"`, `"allowed"`.
    pub metric: String,
    pub baseline: u64,
    pub current: u64,
}

/// A pseudonymized projection of a Zonewarden `Violation`. This is the
/// privacy-load-bearing type: the engine's `Violation` carries raw `src_ip` /
/// `dst_ip`, so the drift builder resolves both endpoints to pseudonyms via the
/// side's `ScrubMap` (`resolve_ip_to_pseudonym`, falling back to
/// `unmapped_label`) before constructing this — a raw IP never reaches output.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ViolationRef {
    /// Finding-id-style kind: `"idmz_bypass" | "wrong_direction" | "deny_by_default"`.
    pub kind: String,
    pub src_pseudonym: String,
    pub dst_pseudonym: String,
    pub dst_port: u16,
    pub proto: String,
    /// `"established" | "attempted"`.
    pub severity: String,
}

/// Top-level diff output. Pure data; renderer (S-6.03) consumes this.
///
/// Note: `Deserialize` is intentionally omitted — `Finding` contains
/// `&'static str` fields that do not implement `Deserialize`. The implementer
/// should address round-trip serialization in S-6.03 if needed.
#[derive(Debug, Clone, Serialize)]
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
    /// The flow-shift threshold this diff was computed with (used by renderers
    /// for accurate labels). Default is `DEFAULT_FLOW_SHIFT_MULTIPLIER` (2.0).
    pub flow_shift_multiplier: f64,
    /// **P1-13:** segmentation-drift section, present only when both diff inputs
    /// carried a Zonewarden conformance result (`diff --policy`). Absent from
    /// JSON output otherwise (`skip_serializing_if`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segmentation: Option<SegmentationDrift>,
    /// **S-11.01:** `true` iff the flow-shift ratios were computed on per-second
    /// rates (bytes/sec) because BOTH capture windows were usable. `false` ⇒ a
    /// degenerate (missing / sub-second) window on at least one side forced the
    /// fallback to raw byte ratios (the pre-S-11.01 behavior).
    pub rate_normalized: bool,
    /// **S-11.01:** baseline capture-window duration in seconds. `None` when the
    /// window is missing or sub-second (degenerate; see [`window_secs`]).
    pub baseline_window_secs: Option<f64>,
    /// **S-11.01:** current capture-window duration in seconds. `None` when the
    /// window is missing or sub-second.
    pub current_window_secs: Option<f64>,
}

impl Default for Diff {
    fn default() -> Self {
        Self {
            hosts_new: Vec::new(),
            hosts_gone: Vec::new(),
            findings_new: Vec::new(),
            findings_recurring: Vec::new(),
            findings_resolved: Vec::new(),
            role_shifts: Vec::new(),
            flow_shifts: Vec::new(),
            flows_new: Vec::new(),
            flows_gone: Vec::new(),
            flow_shift_multiplier: DEFAULT_FLOW_SHIFT_MULTIPLIER,
            segmentation: None,
            rate_normalized: false,
            baseline_window_secs: None,
            current_window_secs: None,
        }
    }
}

/// **S-11.01:** the usable capture-window duration of a capture, in seconds.
///
/// Returns `Some(secs)` only when BOTH `min_ts`/`max_ts` are present AND the
/// span is at least 1 second. A missing, zero, or sub-second window is the
/// S-10.01 "degenerate" case — it cannot serve as a rate-normalization
/// denominator, so it yields `None` and the caller falls back to raw byte
/// ratios.
fn window_secs(obs: &Observations) -> Option<f64> {
    match (obs.min_ts, obs.max_ts) {
        (Some(min), Some(max)) => {
            let s = (max - min).num_milliseconds() as f64 / 1000.0;
            if s >= 1.0 {
                Some(s)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// **S-11.01:** format a capture-window duration for display (e.g. `1800` or
/// `1800.5`). Whole-second windows render without a trailing `.0`.
fn fmt_window_secs(s: f64) -> String {
    if (s.fract()).abs() < 1e-9 {
        format!("{s:.0}")
    } else {
        format!("{s:.1}")
    }
}

/// **S-11.01:** the capture-window condition that drives both the `diff` stderr
/// WARNING (AC-003) and the diff-report banner (AC-004). `None` ⇒ the two
/// windows are comparable AND rate-normalized (no advisory: a normal diff).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WindowAdvisory {
    /// A capture window was missing or sub-second on at least one side, so
    /// flow-shift ratios fell back to raw byte counts (could not normalize).
    Degenerate,
    /// Both windows were usable but differ by 2× or more (inclusive); ratios
    /// are rate-normalized. `factor` is the larger/smaller window ratio.
    Mismatch { factor: f64 },
}

impl Diff {
    /// **S-11.01:** the active [`WindowAdvisory`], or `None` when the windows are
    /// comparable and normalized. The `>= 2.0` test means windows that differ by
    /// 2× **or more** raise a mismatch — so the motivating 1h-vs-30min (exactly
    /// 2×) case warns (EC-002), and the threshold matches the flow-shift
    /// detector's own `>=` multiplier semantics.
    pub fn window_advisory(&self) -> Option<WindowAdvisory> {
        if !self.rate_normalized {
            return Some(WindowAdvisory::Degenerate);
        }
        match (self.baseline_window_secs, self.current_window_secs) {
            (Some(b), Some(c)) if b > 0.0 && c > 0.0 => {
                let (hi, lo) = if b >= c { (b, c) } else { (c, b) };
                if hi / lo >= 2.0 {
                    Some(WindowAdvisory::Mismatch { factor: hi / lo })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// **S-11.01:** pre-formatted informational line shown whenever both
    /// per-side windows are known, e.g. `Capture windows: baseline 3600s vs
    /// current 1800s`. `None` when either window is degenerate.
    pub fn capture_windows_line(&self) -> Option<String> {
        match (self.baseline_window_secs, self.current_window_secs) {
            (Some(b), Some(c)) => Some(format!(
                "Capture windows: baseline {}s vs current {}s",
                fmt_window_secs(b),
                fmt_window_secs(c)
            )),
            _ => None,
        }
    }

    /// **S-11.01:** pre-formatted banner text for the diff report, present only
    /// when a [`WindowAdvisory`] holds. The renderer emits no banner when this
    /// is `None` (comparable + normalized).
    pub fn window_banner(&self) -> Option<String> {
        match self.window_advisory()? {
            WindowAdvisory::Degenerate => Some(
                "Capture-window mismatch: a capture window is missing or sub-second; \
                 flow-shift ratios are raw byte counts (not rate-normalized) and may be \
                 duration artifacts."
                    .to_string(),
            ),
            WindowAdvisory::Mismatch { factor } => {
                let b = self.baseline_window_secs.unwrap_or(0.0);
                let c = self.current_window_secs.unwrap_or(0.0);
                Some(format!(
                    "Capture-window mismatch: windows differ {factor:.1}× (baseline {}s vs \
                     current {}s); flow-shift ratios are rate-normalized (bytes/sec).",
                    fmt_window_secs(b),
                    fmt_window_secs(c)
                ))
            }
        }
    }

    /// **S-11.01:** stderr WARNING text for the capture-window advisory, or
    /// `None` when the windows are comparable and rate-normalized. Routes the
    /// durations through `fmt_window_secs` so the stderr numbers match the
    /// report banner exactly (the renderers and `run_diff` share this).
    pub fn window_warning(&self) -> Option<String> {
        match self.window_advisory()? {
            WindowAdvisory::Degenerate => Some(
                "a capture window is missing or sub-second; flow-shift ratios are raw \
                 byte counts and may be duration artifacts"
                    .to_string(),
            ),
            WindowAdvisory::Mismatch { factor } => {
                let b = self.baseline_window_secs.unwrap_or(0.0);
                let c = self.current_window_secs.unwrap_or(0.0);
                Some(format!(
                    "capture windows differ {factor:.1}× (baseline {}s vs current {}s); \
                     flow-shift ratios are rate-normalized (bytes/sec)",
                    fmt_window_secs(b),
                    fmt_window_secs(c)
                ))
            }
        }
    }

    /// **S-11.01:** the noun for the flow-shift heading — `"rate"` when ratios
    /// are rate-normalized (bytes/sec), `"volume"` when raw byte counts were
    /// used. So a normalized table reads "≥2× rate change", never the
    /// misleading "volume change" with a rate ratio over raw byte columns.
    pub fn flow_shift_basis(&self) -> &'static str {
        if self.rate_normalized {
            "rate"
        } else {
            "volume"
        }
    }

    /// **S-11.01:** an explanatory note rendered above the flow-shift table
    /// whenever ratios are rate-normalized — including the within-2× band where
    /// no mismatch banner is shown — so the ratio column is never read as a raw
    /// byte change. `None` when raw byte ratios were used (no note needed).
    pub fn flow_shift_rate_note(&self) -> Option<String> {
        if !self.rate_normalized {
            return None;
        }
        match (self.baseline_window_secs, self.current_window_secs) {
            (Some(b), Some(c)) => Some(format!(
                "Ratios are per-second rates, normalized by each capture's window \
                 (baseline {}s vs current {}s); the byte columns are raw totals.",
                fmt_window_secs(b),
                fmt_window_secs(c)
            )),
            _ => None,
        }
    }
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
    /// Optional Zonewarden conformance result for this capture side, produced by
    /// the `analyze --policy` path (`segmentation::run_conformance_path`). Present
    /// only when `diff --policy` ran the engine; `None` for a plain diff. When
    /// BOTH sides carry a result the diff emits a `SegmentationDrift` section
    /// (P1-13). The raw result holds real IPs in its `Violation` rows and is
    /// never stored on `Diff` or serialized — only the pseudonymized
    /// `ViolationRef` projection reaches output.
    pub conformance: Option<&'a zonewarden::types::ConformanceResult>,
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

    // ---- S-11.01: per-side capture windows for rate normalization --------
    let baseline_window_secs = window_secs(baseline.observations);
    let current_window_secs = window_secs(current.observations);
    let rate_normalized = baseline_window_secs.is_some() && current_window_secs.is_some();

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
                // S-11.01: compare per-second rates when BOTH windows are usable
                // so a flow that is merely steady over unequal capture durations
                // isn't reported as a duration-artifact shift. When either window
                // is degenerate (`None`), fall back to the raw byte counts.
                let (base_metric, curr_metric) = match (baseline_window_secs, current_window_secs) {
                    (Some(bw), Some(cw)) => (bb as f64 / bw, cb as f64 / cw),
                    _ => (bb as f64, cb as f64),
                };
                let (hi, lo) = if curr_metric >= base_metric {
                    (curr_metric, base_metric)
                } else {
                    (base_metric, curr_metric)
                };
                if lo == 0.0 {
                    continue;
                }
                let ratio = hi / lo;
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

    // ---- P1-13: segmentation drift (only when BOTH sides ran conformance) ----
    let segmentation = match (baseline.conformance, current.conformance) {
        (Some(base_conf), Some(curr_conf)) => Some(build_segmentation_drift(
            base_conf,
            curr_conf,
            baseline.map,
            current.map,
        )),
        _ => None,
    };

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
        flow_shift_multiplier,
        segmentation,
        rate_normalized,
        baseline_window_secs,
        current_window_secs,
    }
}

/// Fixed metric order for the tally-delta table (spec §Determinism). Each tuple
/// is `(metric id, selector)`; the selector reads the `u64` off a
/// `ConformanceResult` so baseline and current rows stay aligned.
type TallyMetric = (
    &'static str,
    fn(&zonewarden::types::ConformanceResult) -> u64,
);
const TALLY_METRICS: [TallyMetric; 8] = [
    ("allowed", |r| r.allowed),
    ("intra_zone", |r| r.intra_zone),
    ("distinct_violating_flows", |r| r.distinct_violating_flows),
    ("idmz_bypasses", |r| r.idmz_bypasses),
    ("no_matching_conduit", |r| r.no_matching_conduit),
    ("wrong_direction", |r| r.wrong_direction),
    ("multicast_exempt", |r| r.multicast_exempt),
    ("external_endpoints", |r| r.external_endpoints),
];

/// Build the [`SegmentationDrift`] from two conformance results scored against
/// the same policy (P1-13).
///
/// - **Tally:** one [`TallyDelta`] per metric in [`TALLY_METRICS`] order.
/// - **policy_digest:** taken from `curr_conf` (identical to baseline by
///   construction — one policy scores both captures).
/// - **Violations:** each `Violation` is pseudonymized into a [`ViolationRef`]
///   (raw IPs resolved through the side's `ScrubMap`), deduplicated, then matched
///   on the scrubbed key `(kind, src_pseudonym, dst_pseudonym, dst_port, proto)`.
///   `flow_index` is deliberately NOT a match key — it is a per-capture dense
///   index, not stable across captures.
/// - **Determinism:** every output vector is sorted by its scrubbed key.
fn build_segmentation_drift(
    base_conf: &zonewarden::types::ConformanceResult,
    curr_conf: &zonewarden::types::ConformanceResult,
    base_map: &ScrubMap,
    curr_map: &ScrubMap,
) -> SegmentationDrift {
    let tally: Vec<TallyDelta> = TALLY_METRICS
        .iter()
        .map(|(metric, sel)| TallyDelta {
            metric: (*metric).to_string(),
            baseline: sel(base_conf),
            current: sel(curr_conf),
        })
        .collect();

    // Deduplicated, sorted sets of pseudonymized violations per side.
    let base_refs = violation_refs(&base_conf.violations, base_map);
    let curr_refs = violation_refs(&curr_conf.violations, curr_map);

    let base_set: HashSet<ViolationKey> = base_refs.iter().map(violation_ref_key).collect();
    let curr_set: HashSet<ViolationKey> = curr_refs.iter().map(violation_ref_key).collect();

    let mut violations_new: Vec<ViolationRef> = curr_refs
        .iter()
        .filter(|v| !base_set.contains(&violation_ref_key(v)))
        .cloned()
        .collect();
    let mut violations_resolved: Vec<ViolationRef> = base_refs
        .iter()
        .filter(|v| !curr_set.contains(&violation_ref_key(v)))
        .cloned()
        .collect();
    let mut violations_persisting: Vec<ViolationRef> = curr_refs
        .iter()
        .filter(|v| base_set.contains(&violation_ref_key(v)))
        .cloned()
        .collect();

    sort_violation_refs(&mut violations_new);
    sort_violation_refs(&mut violations_resolved);
    sort_violation_refs(&mut violations_persisting);

    SegmentationDrift {
        // Identical to baseline by construction; take from current (source of truth).
        policy_digest: curr_conf.policy_digest.clone(),
        tally,
        violations_new,
        violations_resolved,
        violations_persisting,
    }
}

/// The scrubbed match key for a violation: `(kind, src, dst, dst_port, proto)`.
/// Mirrors `finding_diff_key` (P1-13 spec). Never includes `flow_index`.
type ViolationKey = (String, String, String, u16, String);

fn violation_ref_key(v: &ViolationRef) -> ViolationKey {
    (
        v.kind.clone(),
        v.src_pseudonym.clone(),
        v.dst_pseudonym.clone(),
        v.dst_port,
        v.proto.clone(),
    )
}

/// Project + deduplicate a list of raw `Violation`s into pseudonymized
/// `ViolationRef`s. A `ConformanceResult` can carry multiple `Violation` rows
/// per flow (e.g. `NoMatchingConduit` plus an additive `IdmzBypass`), and the
/// scrubbed key can collapse distinct flows, so we dedup on the key.
fn violation_refs(
    violations: &[zonewarden::types::Violation],
    map: &ScrubMap,
) -> Vec<ViolationRef> {
    let mut seen: HashSet<ViolationKey> = HashSet::new();
    let mut out: Vec<ViolationRef> = Vec::new();
    for v in violations {
        let vref = violation_to_ref(v, map);
        if seen.insert(violation_ref_key(&vref)) {
            out.push(vref);
        }
    }
    out
}

/// Pseudonymize a single `Violation` into a `ViolationRef` (PRIVACY-CRITICAL —
/// resolves the raw `src_ip` / `dst_ip` through `map`, never storing them).
fn violation_to_ref(v: &zonewarden::types::Violation, map: &ScrubMap) -> ViolationRef {
    let src = v.src_ip.to_string();
    let dst = v.dst_ip.to_string();
    ViolationRef {
        kind: violation_kind_id(&v.kind).to_string(),
        src_pseudonym: resolve_ip_to_pseudonym(&src, map).unwrap_or_else(|| unmapped_label(&src)),
        dst_pseudonym: resolve_ip_to_pseudonym(&dst, map).unwrap_or_else(|| unmapped_label(&dst)),
        dst_port: v.dst_port.unwrap_or(0),
        proto: violation_proto_label(&v.proto),
        severity: violation_severity_id(&v.severity).to_string(),
    }
}

/// Map a `ViolationKind` to the matching `zonewarden.*` finding-id-style string.
fn violation_kind_id(kind: &zonewarden::types::ViolationKind) -> &'static str {
    use zonewarden::types::ViolationKind::*;
    match kind {
        IdmzBypass => "idmz_bypass",
        WrongDirection => "wrong_direction",
        NoMatchingConduit => "deny_by_default",
    }
}

/// Map a `Severity` to its lowercase id.
fn violation_severity_id(sev: &zonewarden::types::Severity) -> &'static str {
    use zonewarden::types::Severity::*;
    match sev {
        Established => "established",
        Attempted => "attempted",
    }
}

/// Lowercase transport label for a zonewarden `Proto` (distinct from
/// `proto_label`, which takes the IP-protocol `u8` off a `FlowKey`).
fn violation_proto_label(proto: &zonewarden::types::Proto) -> String {
    use zonewarden::types::Proto::*;
    match proto {
        Tcp => "tcp".to_string(),
        Udp => "udp".to_string(),
        Icmp => "icmp".to_string(),
        Other(_) => "other".to_string(),
    }
}

/// Deterministic sort for a `ViolationRef` vector by its scrubbed key.
fn sort_violation_refs(refs: &mut [ViolationRef]) {
    refs.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.src_pseudonym.cmp(&b.src_pseudonym))
            .then_with(|| a.dst_pseudonym.cmp(&b.dst_pseudonym))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
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

    // ──────────────────────────────────────────────────────────────────────
    // P1-13: segmentation drift
    // ──────────────────────────────────────────────────────────────────────

    use zonewarden::types as zw;

    /// Build a zonewarden `Violation` for tests. `flow_index` is varied
    /// independently of the endpoints to prove it is NOT a match key.
    fn violation(
        flow_index: u64,
        kind: zw::ViolationKind,
        src_ip: &str,
        dst_ip: &str,
        dst_port: Option<u16>,
        proto: zw::Proto,
        severity: zw::Severity,
    ) -> zw::Violation {
        zw::Violation {
            flow_index,
            src_zone: zw::ZoneId("a".into()),
            dst_zone: zw::ZoneId("b".into()),
            kind,
            severity,
            idmz_bypass: false,
            explanation: String::new(),
            ts: zw::Timestamp(0),
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            src_port: Some(40000),
            dst_port,
            proto,
            service: None,
            service_source: zw::ServiceSource::Unknown,
            conn_state: None,
        }
    }

    fn conf(violations: Vec<zw::Violation>) -> zw::ConformanceResult {
        zw::ConformanceResult {
            violations,
            policy_digest: "digest123".into(),
            ..Default::default()
        }
    }

    #[test]
    fn drift_violation_kind_severity_proto_mappings() {
        assert_eq!(
            violation_kind_id(&zw::ViolationKind::IdmzBypass),
            "idmz_bypass"
        );
        assert_eq!(
            violation_kind_id(&zw::ViolationKind::WrongDirection),
            "wrong_direction"
        );
        assert_eq!(
            violation_kind_id(&zw::ViolationKind::NoMatchingConduit),
            "deny_by_default"
        );
        assert_eq!(
            violation_severity_id(&zw::Severity::Established),
            "established"
        );
        assert_eq!(violation_severity_id(&zw::Severity::Attempted), "attempted");
        assert_eq!(violation_proto_label(&zw::Proto::Tcp), "tcp");
        assert_eq!(violation_proto_label(&zw::Proto::Udp), "udp");
        assert_eq!(violation_proto_label(&zw::Proto::Icmp), "icmp");
        assert_eq!(violation_proto_label(&zw::Proto::Other(99)), "other");
    }

    #[test]
    fn drift_tally_values_and_fixed_order() {
        let base = zw::ConformanceResult {
            allowed: 10,
            intra_zone: 5,
            distinct_violating_flows: 2,
            idmz_bypasses: 1,
            no_matching_conduit: 2,
            wrong_direction: 0,
            multicast_exempt: 3,
            external_endpoints: 4,
            policy_digest: "d".into(),
            ..Default::default()
        };
        let curr = zw::ConformanceResult {
            allowed: 11,
            intra_zone: 5,
            distinct_violating_flows: 3,
            idmz_bypasses: 2,
            no_matching_conduit: 1,
            wrong_direction: 1,
            multicast_exempt: 3,
            external_endpoints: 4,
            policy_digest: "d".into(),
            ..Default::default()
        };
        let map = scrub_map(&[]);
        let drift = build_segmentation_drift(&base, &curr, &map, &map);

        let metrics: Vec<&str> = drift.tally.iter().map(|t| t.metric.as_str()).collect();
        assert_eq!(
            metrics,
            vec![
                "allowed",
                "intra_zone",
                "distinct_violating_flows",
                "idmz_bypasses",
                "no_matching_conduit",
                "wrong_direction",
                "multicast_exempt",
                "external_endpoints",
            ],
            "tally must be in the fixed spec order"
        );
        // Spot-check a couple of (baseline, current) pairs.
        assert_eq!((drift.tally[0].baseline, drift.tally[0].current), (10, 11));
        assert_eq!((drift.tally[3].baseline, drift.tally[3].current), (1, 2));
        // policy_digest taken from current.
        assert_eq!(drift.policy_digest, "d");
    }

    #[test]
    fn drift_matches_new_resolved_persisting() {
        let map = scrub_map(&[
            ("host_001", "10.0.0.1"),
            ("host_002", "10.0.0.2"),
            ("host_003", "10.0.0.3"),
        ]);
        // Baseline: V1 (host_001->host_002) + V2 (host_002->host_003)
        let base = conf(vec![
            violation(
                0,
                zw::ViolationKind::NoMatchingConduit,
                "10.0.0.1",
                "10.0.0.2",
                Some(502),
                zw::Proto::Tcp,
                zw::Severity::Established,
            ),
            violation(
                1,
                zw::ViolationKind::WrongDirection,
                "10.0.0.2",
                "10.0.0.3",
                Some(102),
                zw::Proto::Tcp,
                zw::Severity::Attempted,
            ),
        ]);
        // Current: V1 (persisting) + V3 (host_001->host_003, new)
        let curr = conf(vec![
            violation(
                7, // different flow_index — must not affect matching
                zw::ViolationKind::NoMatchingConduit,
                "10.0.0.1",
                "10.0.0.2",
                Some(502),
                zw::Proto::Tcp,
                zw::Severity::Established,
            ),
            violation(
                8,
                zw::ViolationKind::IdmzBypass,
                "10.0.0.1",
                "10.0.0.3",
                Some(44818),
                zw::Proto::Tcp,
                zw::Severity::Established,
            ),
        ]);
        let drift = build_segmentation_drift(&base, &curr, &map, &map);

        assert_eq!(drift.violations_new.len(), 1, "V3 is new");
        assert_eq!(drift.violations_new[0].kind, "idmz_bypass");
        assert_eq!(drift.violations_new[0].dst_pseudonym, "host_003");

        assert_eq!(drift.violations_resolved.len(), 1, "V2 resolved");
        assert_eq!(drift.violations_resolved[0].kind, "wrong_direction");

        assert_eq!(drift.violations_persisting.len(), 1, "V1 persists");
        assert_eq!(drift.violations_persisting[0].kind, "deny_by_default");
        assert_eq!(drift.violations_persisting[0].dst_port, 502);
    }

    #[test]
    fn drift_flow_index_is_not_a_match_key() {
        // Two captures with the SAME endpoints/kind/port/proto but DIFFERENT
        // flow_index must match as persisting — proving flow_index is not keyed.
        let map = scrub_map(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);
        let base = conf(vec![violation(
            0,
            zw::ViolationKind::NoMatchingConduit,
            "10.0.0.1",
            "10.0.0.2",
            Some(502),
            zw::Proto::Tcp,
            zw::Severity::Established,
        )]);
        let curr = conf(vec![violation(
            999,
            zw::ViolationKind::NoMatchingConduit,
            "10.0.0.1",
            "10.0.0.2",
            Some(502),
            zw::Proto::Tcp,
            zw::Severity::Established,
        )]);
        let drift = build_segmentation_drift(&base, &curr, &map, &map);
        assert!(drift.violations_new.is_empty());
        assert!(drift.violations_resolved.is_empty());
        assert_eq!(
            drift.violations_persisting.len(),
            1,
            "same endpoints, differing flow_index, must still match as persisting"
        );
    }

    #[test]
    fn drift_dedups_multiple_violation_rows_per_flow() {
        // A flow can yield multiple Violation rows (e.g. NoMatchingConduit +
        // additive IdmzBypass). Distinct kinds stay distinct, but identical
        // scrubbed keys collapse to one row.
        let map = scrub_map(&[("host_001", "10.0.0.1"), ("host_002", "10.0.0.2")]);
        let dup = || {
            violation(
                0,
                zw::ViolationKind::NoMatchingConduit,
                "10.0.0.1",
                "10.0.0.2",
                Some(502),
                zw::Proto::Tcp,
                zw::Severity::Established,
            )
        };
        let refs = violation_refs(&[dup(), dup()], &map);
        assert_eq!(refs.len(), 1, "identical violation keys must dedup");
    }

    #[test]
    fn drift_is_order_independent() {
        let map = scrub_map(&[
            ("host_001", "10.0.0.1"),
            ("host_002", "10.0.0.2"),
            ("host_003", "10.0.0.3"),
        ]);
        let v_a = violation(
            0,
            zw::ViolationKind::NoMatchingConduit,
            "10.0.0.1",
            "10.0.0.2",
            Some(502),
            zw::Proto::Tcp,
            zw::Severity::Established,
        );
        let v_b = violation(
            1,
            zw::ViolationKind::IdmzBypass,
            "10.0.0.1",
            "10.0.0.3",
            Some(80),
            zw::Proto::Tcp,
            zw::Severity::Attempted,
        );
        let base = conf(vec![]);
        let curr1 = conf(vec![v_a.clone(), v_b.clone()]);
        let curr2 = conf(vec![v_b, v_a]);
        let d1 = build_segmentation_drift(&base, &curr1, &map, &map);
        let d2 = build_segmentation_drift(&base, &curr2, &map, &map);
        assert_eq!(d1, d2, "swapped violation order must yield identical drift");
    }

    #[test]
    fn drift_pseudonymizes_endpoints_no_raw_ip() {
        // PRIVACY: a violation carrying a raw canary IP must project to a
        // pseudonym (mapped) — and on a map miss to an opaque label, never raw.
        let map = scrub_map(&[("host_001", "10.0.0.1")]);
        let v = violation(
            0,
            zw::ViolationKind::NoMatchingConduit,
            "10.0.0.1",
            "203.0.113.45", // canary, not in map
            Some(502),
            zw::Proto::Tcp,
            zw::Severity::Established,
        );
        let drift = build_segmentation_drift(&conf(vec![]), &conf(vec![v]), &map, &map);
        let vref = &drift.violations_new[0];
        assert_eq!(vref.src_pseudonym, "host_001");
        assert_ne!(vref.dst_pseudonym, "203.0.113.45");
        assert!(vref.dst_pseudonym.starts_with("unmapped_"));
    }

    // ──────────────────────────────────────────────────────────────────────
    // S-11.01: diff capture-window normalization
    // ──────────────────────────────────────────────────────────────────────

    use crate::observe::{FlowKey, FlowObs};
    use std::collections::HashSet as StdHashSet;

    /// Build an `Observations` carrying a single `10.9.0.1 -> 10.9.0.2:502/tcp`
    /// flow of `bytes`, with the capture window set from `window` seconds
    /// (`None` ⇒ leave `min_ts`/`max_ts` unset = degenerate).
    fn obs_with_flow(bytes: u64, window: Option<f64>) -> Observations {
        let src: std::net::IpAddr = "10.9.0.1".parse().unwrap();
        let dst: std::net::IpAddr = "10.9.0.2".parse().unwrap();
        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut obs = Observations::default();
        if let Some(w) = window {
            obs.min_ts = Some(t0);
            obs.max_ts = Some(t0 + chrono::Duration::milliseconds((w * 1000.0) as i64));
        }
        let key = FlowKey {
            src,
            dst,
            dst_port: 502,
            proto: 6,
        };
        obs.flows.insert(
            "10.9.0.1->10.9.0.2:502/6".to_string(),
            FlowObs {
                key,
                packets: 1,
                bytes,
                first_seen: t0,
                last_seen: t0,
                label: None,
                unique_src_ports: StdHashSet::new(),
            },
        );
        obs
    }

    fn map_910() -> ScrubMap {
        scrub_map(&[("host_910", "10.9.0.1"), ("host_911", "10.9.0.2")])
    }

    /// AC-002 worked example: a steady flow with 2× bytes over a 2× window is a
    /// pure duration artifact. The raw ratio (2.0) would flag it, but the
    /// rate ratio is 1.0 → NOT flagged. `rate_normalized` is `true`.
    #[test]
    fn s_11_01_worked_example_steady_flow_not_flagged_when_rate_normalized() {
        let base = obs_with_flow(2000, Some(3600.0)); // 2X bytes over 3600s
        let curr = obs_with_flow(1000, Some(1800.0)); // X bytes over 1800s
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(
            diff.rate_normalized,
            "both windows usable ⇒ rate_normalized must be true"
        );
        assert!(
            diff.flow_shifts.is_empty(),
            "rate ratio is 1.0 (2X/3600 vs X/1800) ⇒ steady flow must NOT be flagged; \
             got {:?}",
            diff.flow_shifts
        );
        assert_eq!(diff.baseline_window_secs, Some(3600.0));
        assert_eq!(diff.current_window_secs, Some(1800.0));
    }

    /// AC-002 / EC-005: a flow whose true *rate* doubled (same windows) is still
    /// flagged — a real behavioral shift is preserved.
    #[test]
    fn s_11_01_real_rate_doubled_still_flagged() {
        let base = obs_with_flow(1000, Some(1800.0));
        let curr = obs_with_flow(2000, Some(1800.0)); // same window, 2× rate
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(
            diff.rate_normalized,
            "both windows usable ⇒ rate_normalized"
        );
        assert_eq!(
            diff.flow_shifts.len(),
            1,
            "a genuine 2× rate increase must still be flagged"
        );
        assert!(
            (diff.flow_shifts[0].ratio - 2.0).abs() < 1e-9,
            "rate ratio for 2000/1800 vs 1000/1800 should be 2.0, got {}",
            diff.flow_shifts[0].ratio
        );
    }

    /// AC-002 / EC-003: a degenerate window on one side forces the raw-byte
    /// fallback — `rate_normalized` is `false` and a 2× byte change is flagged.
    #[test]
    fn s_11_01_degenerate_window_falls_back_to_raw_ratio() {
        let base = obs_with_flow(1000, None); // no timestamps ⇒ degenerate
        let curr = obs_with_flow(2000, Some(1800.0));
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(
            !diff.rate_normalized,
            "a None window on one side ⇒ rate_normalized must be false"
        );
        assert_eq!(
            diff.flow_shifts.len(),
            1,
            "raw fallback: a 2× byte change must still be flagged"
        );
        assert!(
            (diff.flow_shifts[0].ratio - 2.0).abs() < 1e-9,
            "raw ratio for 2000/1000 should be 2.0, got {}",
            diff.flow_shifts[0].ratio
        );
        assert_eq!(diff.baseline_window_secs, None);
        assert_eq!(diff.current_window_secs, Some(1800.0));
    }

    /// M-1 regression lock: windows differ < 2× (1.5×) so `window_advisory` is
    /// `None` and NO mismatch banner is shown — yet a rate-normalized flow IS
    /// flagged. The heading basis must read "rate" and the rate-note MUST still
    /// be present, so a flagged flow isn't read as a raw "volume change".
    #[test]
    fn s_11_01_within_2x_no_banner_but_rate_note_present() {
        let base = obs_with_flow(600, Some(1800.0)); // rate 600/1800 = 0.333
        let curr = obs_with_flow(800, Some(1200.0)); // rate 800/1200 = 0.667 = 2× base; 1.5× window
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(diff.rate_normalized);
        assert_eq!(
            diff.window_advisory(),
            None,
            "1.5× windows (< 2×) must NOT raise an advisory"
        );
        assert!(
            diff.window_banner().is_none() && diff.window_warning().is_none(),
            "no banner/stderr warning below 2×"
        );
        assert_eq!(diff.flow_shifts.len(), 1, "the ~2× rate change is flagged");
        assert_eq!(diff.flow_shift_basis(), "rate");
        assert!(
            diff.flow_shift_rate_note().is_some(),
            "the rate-note MUST be present even when no banner is shown (within-2× band)"
        );
    }

    /// EC-002 + EC-008 (adversary pass-2 M-1): windows differing EXACTLY 2× (the
    /// motivating 1h-vs-30min case) DO raise a mismatch advisory — `>= 2×` is
    /// inclusive — so the headline scenario warns (stderr + banner).
    #[test]
    fn s_11_01_exactly_2x_window_raises_mismatch() {
        let base = obs_with_flow(1000, Some(3600.0)); // 1 hour
        let curr = obs_with_flow(1000, Some(1800.0)); // 30 minutes
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(diff.rate_normalized);
        match diff.window_advisory() {
            Some(WindowAdvisory::Mismatch { factor }) => {
                assert!(
                    (factor - 2.0).abs() < 1e-9,
                    "factor should be 2.0, got {factor}"
                )
            }
            other => panic!("exactly 2× must raise Mismatch (>= 2×, EC-002), got {other:?}"),
        }
        assert!(diff.window_banner().is_some(), "exactly 2× ⇒ banner shown");
        assert!(
            diff.window_warning()
                .is_some_and(|w| w.contains("windows differ")),
            "exactly 2× ⇒ stderr warning"
        );
    }

    /// MINOR (adversary pass 2): both advisory variants' surfacing text is
    /// asserted — degenerate (raw fallback) and mismatch — for `window_warning`
    /// and `window_banner` (EC-003/EC-004 surfacing claims).
    #[test]
    fn s_11_01_advisory_text_for_both_variants() {
        // Degenerate: one window None ⇒ raw fallback.
        let degen = Diff {
            rate_normalized: false,
            baseline_window_secs: None,
            current_window_secs: Some(1800.0),
            ..Default::default()
        };
        assert_eq!(degen.window_advisory(), Some(WindowAdvisory::Degenerate));
        assert!(degen
            .window_warning()
            .is_some_and(|w| w.contains("missing or sub-second")));
        assert!(degen
            .window_banner()
            .is_some_and(|b| b.contains("missing or sub-second") && b.contains("raw byte counts")));

        // Mismatch: both windows usable, > 2×.
        let mismatch = Diff {
            rate_normalized: true,
            baseline_window_secs: Some(3600.0),
            current_window_secs: Some(900.0),
            ..Default::default()
        };
        assert!(matches!(
            mismatch.window_advisory(),
            Some(WindowAdvisory::Mismatch { .. })
        ));
        assert!(mismatch
            .window_warning()
            .is_some_and(|w| w.contains("windows differ") && w.contains("rate-normalized")));
        assert!(mismatch
            .window_banner()
            .is_some_and(|b| b.contains("windows differ")));
    }

    /// EC-001: equal windows ⇒ rate ratio ≡ byte ratio; a steady flow is not
    /// flagged, `rate_normalized` is true, and there is no advisory.
    #[test]
    fn s_11_01_equal_windows_no_advisory_steady_not_flagged() {
        let base = obs_with_flow(1000, Some(1800.0));
        let curr = obs_with_flow(1000, Some(1800.0));
        let map = map_910();
        let diff = compute(
            DiffInput {
                observations: &base,
                map: &map,
                findings: &[],
                conformance: None,
            },
            DiffInput {
                observations: &curr,
                map: &map,
                findings: &[],
                conformance: None,
            },
        );
        assert!(diff.rate_normalized);
        assert_eq!(diff.window_advisory(), None);
        assert!(diff.flow_shifts.is_empty(), "equal rate ⇒ no shift");
        assert_eq!(diff.flow_shift_basis(), "rate");
    }
}

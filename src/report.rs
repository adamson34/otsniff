//! HTML report rendering.
//!
//! All formatting (severity labels, byte humanization, role labels, etc.) is
//! done in Rust ahead of time so the askama template only does plain
//! substitution and HTML escaping. The `generated_at` timestamp is taken as
//! a parameter so snapshot tests can inject a fixed value.

use askama::Template;
use chrono::{DateTime, Utc};

use crate::capture_source::Classification;
use crate::error::Result;
use crate::findings::{Finding, Severity};
use crate::inventory::Asset;
use crate::observe::Observations;

#[derive(Template)]
#[template(path = "report.html", escape = "html")]
struct ReportView {
    input: String,
    generated: String,
    version: String,
    total_packets: String,
    total_bytes: String,
    span: String,
    capture_source: Option<String>,
    finding_count: usize,
    asset_count: usize,
    ot_asset_count: usize,
    findings: Vec<FindingView>,
    assets: Vec<AssetView>,
    top_flows: Vec<TopFlow>,
}

struct FindingView {
    id: String,
    severity_label: String,
    severity_class: String,
    title: String,
    summary: String,
    evidence: Vec<String>,
    evidence_count: usize,
    recommendation: String,
}

struct AssetView {
    ip: String,
    mac: String,
    vendor: String,
    role: String,
    protocols: String,
    packets: String,
    bytes: String,
    in_ot_zone: bool,
}

struct TopFlow {
    src: String,
    dst: String,
    label: String,
    packets: String,
    bytes: String,
}

pub fn render_html(
    inventory: &[Asset],
    findings: &[Finding],
    obs: &Observations,
    input_label: &str,
    generated_at: DateTime<Utc>,
    capture_source: Option<&Classification>,
) -> Result<String> {
    let span = match (obs.first_ts, obs.last_ts) {
        (Some(a), Some(b)) => format!("{} → {}", fmt_ts(a), fmt_ts(b)),
        _ => "(no timestamps)".to_string(),
    };

    let mut flow_refs: Vec<&crate::observe::FlowObs> = obs.flows.values().collect();
    flow_refs.sort_by_key(|f| std::cmp::Reverse(f.bytes));
    let top_flows: Vec<TopFlow> = flow_refs
        .into_iter()
        .take(25)
        .map(|f| TopFlow {
            src: format!("{}:{}", f.key.src, f.key.src_port),
            dst: format!("{}:{}", f.key.dst, f.key.dst_port),
            label: f.label.clone().unwrap_or_else(|| match f.key.proto {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                _ => format!("ip/{}", f.key.proto),
            }),
            packets: f.packets.to_string(),
            bytes: human_bytes(f.bytes),
        })
        .collect();

    let findings_view: Vec<FindingView> = findings
        .iter()
        .map(|f| FindingView {
            id: f.id.to_string(),
            severity_label: severity_label(f.severity).to_string(),
            severity_class: severity_class(f.severity).to_string(),
            title: f.title.clone(),
            summary: f.summary.clone(),
            evidence_count: f.evidence.len(),
            evidence: f.evidence.clone(),
            recommendation: f.recommendation.to_string(),
        })
        .collect();

    let assets_view: Vec<AssetView> = inventory
        .iter()
        .map(|a| AssetView {
            ip: a.ip.to_string(),
            mac: a.mac.clone().unwrap_or_else(|| "—".to_string()),
            vendor: a.vendor.clone().unwrap_or_else(|| "—".to_string()),
            role: a.role.label().to_string(),
            protocols: if a.protocols.is_empty() {
                "—".to_string()
            } else {
                a.protocols.join(", ")
            },
            packets: a.packets.to_string(),
            bytes: human_bytes(a.bytes),
            in_ot_zone: a.in_ot_zone,
        })
        .collect();

    let view = ReportView {
        input: input_label.to_string(),
        generated: fmt_ts(generated_at),
        version: crate::VERSION.to_string(),
        total_packets: obs.total_packets.to_string(),
        total_bytes: human_bytes(obs.total_bytes),
        span,
        capture_source: capture_source.map(|c| c.report_line()),
        finding_count: findings.len(),
        asset_count: inventory.len(),
        ot_asset_count: inventory.iter().filter(|a| a.in_ot_zone).count(),
        findings: findings_view,
        assets: assets_view,
        top_flows,
    };
    Ok(view.render()?)
}

fn fmt_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Info => "info",
    }
}

fn severity_class(s: Severity) -> &'static str {
    severity_label(s)
}

fn human_bytes(n: u64) -> String {
    let n = n as f64;
    let (val, unit) = if n >= 1e9 {
        (n / 1e9, "GB")
    } else if n >= 1e6 {
        (n / 1e6, "MB")
    } else if n >= 1e3 {
        (n / 1e3, "KB")
    } else {
        (n, "B")
    };
    format!("{val:.1} {unit}")
}

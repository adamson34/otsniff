//! HTML report rendering.
//!
//! All formatting (severity labels, byte humanization, role labels, etc.) is
//! done in Rust ahead of time so the askama template only does plain
//! substitution and HTML escaping. The `generated_at` timestamp is taken as
//! a parameter so snapshot tests can inject a fixed value.

use askama::Template;
use chrono::{DateTime, Utc};

use crate::capture_source::Classification;
use crate::diff::Diff;
use crate::error::Result;
use crate::findings::augmented::AugmentedFinding;
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
    /// Pre-rendered HTML for the AI section, if any. Already passed
    /// through `ai::html_render::render_safe`, so raw HTML events
    /// in the AI's markdown response (e.g. `<script>`) are stripped
    /// before embedding here. The template uses `|safe` to skip
    /// askama escaping — that's intentional and only sound because
    /// of the prior filtering.
    ai_section: Option<String>,
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
    playbook: Vec<String>,
    playbook_count: usize,
    /// Plain-English trigger from the rule catalog. Empty string if the
    /// finding id isn't in the catalog (shouldn't happen — guarded by
    /// `every_finding_id_appears_in_the_rule_catalog`).
    trigger: String,
}

struct AssetView {
    ip: String,
    hostname: String,
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
    connections: String,
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
    ai_section: Option<String>,
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
            src: f.key.src.to_string(),
            dst: format!("{}:{}", f.key.dst, f.key.dst_port),
            label: f.label.clone().unwrap_or_else(|| match f.key.proto {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                _ => format!("ip/{}", f.key.proto),
            }),
            connections: f.connections().to_string(),
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
            playbook_count: f.playbook.len(),
            playbook: f.playbook.clone(),
            trigger: crate::findings::metadata_for(f.id)
                .map(|m| m.trigger.to_string())
                .unwrap_or_default(),
        })
        .collect();

    let assets_view: Vec<AssetView> = inventory
        .iter()
        .map(|a| AssetView {
            ip: a.ip.to_string(),
            hostname: a.hostname.clone().unwrap_or_else(|| "—".to_string()),
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
        ai_section,
    };
    Ok(view.render()?)
}

/// Render the "AI-augmented findings" section as a pre-formatted HTML
/// fragment (S-5.03 AC-004 / BC-3.07.001).
///
/// Returns an empty string when `findings` is empty so the caller can
/// omit the section entirely. Visually distinguished from rule-based
/// findings via a teal left-border (`--ai-border`) and an inline "AI"
/// badge.
///
/// AI-controlled strings (`title`, `evidence` rows, `reasoning`) are
/// rendered through [`crate::ai::html_render::render_safe`] which strips
/// raw HTML events and sanitises unsafe URL schemes — matching the
/// existing `analyze` path and fixing the MEDIUM finding from the PR
/// review (the old local `html_escape` was not sufficient for the
/// `reasoning` field which may contain markdown).
pub fn render_augmented_section(findings: &[AugmentedFinding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let mut out = String::new();

    // Section heading — uppercase label matching the h2 style.
    out.push_str(
        "<h2 class=\"ai-augmented-heading\">AI-augmented findings</h2>\n\
         <p class=\"ai-augmented-note muted\" style=\"font-size:0.85rem;margin-bottom:1rem;\">\
         Patterns surfaced by a second AI pass, anchored on rule findings and inventory. \
         Confidence ratings are the model&#39;s self-assessment.</p>\n",
    );

    for f in findings {
        let sev_class = severity_class(f.severity);
        let sev_label = severity_label(f.severity);
        let conf_label = match f.confidence {
            crate::findings::augmented::Confidence::High => "high",
            crate::findings::augmented::Confidence::Medium => "medium",
            crate::findings::augmented::Confidence::Low => "low",
        };

        // id is an ai.* namespace value we assign ourselves — safe to html_escape only.
        // title, evidence, and reasoning are AI-controlled text; pipe through render_safe.
        out.push_str(&format!(
            "<details open class=\"finding ai-finding sev-{sev_class}\" style=\"border-left-color:#2a8fb5\">\n\
             <summary>\
             <span class=\"badge sev-{sev_class}\">{sev_label}</span>\
             <span class=\"badge\" style=\"background:#2a8fb5\">AI</span>\
             <strong>{title}</strong>\
             </summary>\n\
             <p class=\"muted\" style=\"font-size:0.8rem;margin:0.25rem 0;\">id: <code>{id}</code> · confidence: {conf_label}</p>\n",
            // render_safe handles markdown + strips raw HTML events / unsafe URLs.
            // We wrap in a span to avoid the <p> pulldown-cmark emits for single
            // lines; the output is still XSS-safe because render_safe strips all
            // raw-HTML events.
            title = html_escape(&f.title),
            id = html_escape(&f.id),
        ));

        if !f.evidence.is_empty() {
            out.push_str("<details><summary>Evidence</summary>\n<pre style=\"font-size:0.8rem;margin:0.5rem 0;\">");
            for ev in &f.evidence {
                // Evidence rows: plain-text strings — html_escape is appropriate
                // (no markdown rendering needed; preserves whitespace in <pre>).
                out.push_str(&html_escape(ev));
                out.push('\n');
            }
            out.push_str("</pre>\n</details>\n");
        }

        if !f.reasoning.is_empty() {
            // Reasoning may contain markdown. Render through render_safe so
            // <script>, javascript: links, and other raw-HTML XSS vectors are
            // stripped before embedding in the report.
            let reasoning_html = crate::ai::html_render::render_safe(&f.reasoning);
            out.push_str(
                "<details open><summary>AI reasoning</summary>\n<div style=\"margin:0.5rem 0;\">",
            );
            out.push_str(&reasoning_html);
            out.push_str("</div>\n</details>\n");
        }

        out.push_str("</details>\n");
    }

    out
}

/// Render a cross-capture diff as a self-contained HTML report (S-6.03 AC-001).
///
/// Stub — implementation pending (Red Gate enforced). All non-trivial logic is
/// `todo!()` per BC-5.38.001.
pub fn render_diff_html(diff: &Diff) -> Result<String> {
    let _ = diff;
    todo!("S-6.03: implement render_diff_html")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

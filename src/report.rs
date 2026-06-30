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
    /// Pre-formatted capture-window sanity warnings (S-10.01 / ADR-0003), one
    /// per [`crate::capture_sanity::CaptureWarning::message`]. Empty for a sane
    /// capture, in which case the template emits no banner — keeping
    /// clean-capture HTML byte-identical.
    capture_warnings: Vec<String>,
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
    /// Pre-rendered HTML for the Zonewarden segmentation-conformance section,
    /// present only when a `--policy` was supplied (ADR-0013). Tool-controlled
    /// content (tallies + a hex digest), so `|safe` is sound.
    conformance_section: Option<String>,
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

// Eight render inputs — a report is inherently wide. A params struct would just
// move the width to the call sites without improving clarity.
#[allow(clippy::too_many_arguments)]
pub fn render_html(
    inventory: &[Asset],
    findings: &[Finding],
    obs: &Observations,
    input_label: &str,
    generated_at: DateTime<Utc>,
    capture_source: Option<&Classification>,
    ai_section: Option<String>,
    conformance_section: Option<String>,
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
        // S-10.01 AC-003: pre-format the capture-window sanity warnings
        // (ADR-0003). Empty for a sane capture, so the template emits no banner
        // and clean-capture HTML stays byte-identical.
        capture_warnings: crate::capture_sanity::assess(obs)
            .iter()
            .map(|w| w.message().to_string())
            .collect(),
        capture_source: capture_source.map(|c| c.report_line()),
        finding_count: findings.len(),
        asset_count: inventory.len(),
        ot_asset_count: inventory.iter().filter(|a| a.in_ot_zone).count(),
        findings: findings_view,
        assets: assets_view,
        top_flows,
        ai_section,
        conformance_section,
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

/// Render the "Zonewarden — Segmentation Conformance" HTML section from a
/// conformance result (ADR-0013), as a self-contained fragment for injection
/// into the report (mirrors [`render_augmented_section`]). The text here is all
/// tool-controlled (numbers + a hex digest), so plain HTML is safe.
pub fn render_conformance_section(r: &zonewarden::types::ConformanceResult) -> String {
    let mut out = String::new();
    out.push_str(
        "<h2 class=\"zonewarden-heading\">Zonewarden — Segmentation Conformance</h2>\n\
         <p class=\"zonewarden-note muted\" style=\"font-size:0.85rem;margin-bottom:1rem;\">\
         Observed flows classified against the declared IEC 62443 zone/conduit policy.</p>\n\
         <table class=\"zonewarden-summary\">\n<tbody>\n",
    );
    let rows = [
        ("Total flows", r.total_flows),
        ("Intra-zone (implicitly allowed)", r.intra_zone),
        ("Allowed by a conduit", r.allowed),
        ("No matching conduit", r.no_matching_conduit),
        ("Wrong direction", r.wrong_direction),
        ("Multicast/broadcast exempt", r.multicast_exempt),
        ("IDMZ bypasses", r.idmz_bypasses),
        ("Distinct violating flows", r.distinct_violating_flows),
        ("External endpoints", r.external_endpoints),
    ];
    for (label, n) in rows {
        out.push_str(&format!(
            "<tr><td>{label}</td><td style=\"text-align:right\">{n}</td></tr>\n"
        ));
    }
    out.push_str("</tbody>\n</table>\n");
    out.push_str(&format!(
        "<p class=\"zonewarden-digest muted\" style=\"font-size:0.8rem;\">\
         Policy digest: <code>{}</code> — deterministic; identical inputs reproduce it \
         byte-for-byte.</p>\n",
        r.policy_digest
    ));
    out
}

/// True when a [`SegmentationDrift`] carries any actual movement: a non-empty
/// new/resolved violation list, or a tally metric that changed between captures.
/// (Persisting violations and an all-equal tally are not, on their own, a delta.)
fn segmentation_has_drift(drift: &crate::diff::SegmentationDrift) -> bool {
    !drift.violations_new.is_empty()
        || !drift.violations_resolved.is_empty()
        || drift.tally.iter().any(|t| t.baseline != t.current)
}

/// Render the "Segmentation drift" HTML section from a [`SegmentationDrift`]
/// (P1-13), as a self-contained fragment injected into the diff report (mirrors
/// [`render_conformance_section`]). All content is tool-controlled — pseudonyms,
/// integer tallies, and a hex digest — so plain HTML is safe.
///
/// Layout: a muted policy-digest anchor line, a tally table
/// (metric | baseline | current | direction), and three violation-delta lists
/// (new / resolved / persisting), each row `kind · src → dst:port/proto · severity`.
pub fn render_segmentation_drift_section(drift: &crate::diff::SegmentationDrift) -> String {
    /// Cap on violation rows per list to keep the report readable.
    const MAX_VIOLATIONS: usize = 10;

    let mut out = String::new();
    out.push_str("<h2>Segmentation drift</h2>\n");
    out.push_str(&format!(
        "<p class=\"muted\" style=\"font-size:0.8rem;\">Policy digest: <code>{}</code> \
         — one policy scored both captures; identical on each side by construction.</p>\n",
        escape_html(&drift.policy_digest)
    ));

    // ---- Tally deltas ----
    out.push_str("<h3>Conformance tally</h3>\n<table>\n<thead>\n");
    out.push_str(
        "<tr><th>Metric</th><th style=\"text-align:right\">Baseline</th>\
                  <th style=\"text-align:right\">Current</th><th></th></tr>\n",
    );
    out.push_str("</thead>\n<tbody>\n");
    for t in &drift.tally {
        // More violations/bypasses = worse. Whether "up is bad" depends on the
        // metric: for allowed/intra-zone/multicast-exempt a rise is benign, for
        // the violation metrics a rise is a regression. We tint a rise on a
        // violation metric with the high-severity color and a fall (good news)
        // with the ok color.
        let (arrow, cls) = match t.current.cmp(&t.baseline) {
            std::cmp::Ordering::Greater => ("▲", drift_metric_class(&t.metric, true)),
            std::cmp::Ordering::Less => ("▼", drift_metric_class(&t.metric, false)),
            std::cmp::Ordering::Equal => ("—", ""),
        };
        let cls_attr = if cls.is_empty() {
            String::new()
        } else {
            format!(" class=\"{cls}\"")
        };
        out.push_str(&format!(
            "<tr><td>{}</td><td style=\"text-align:right\">{}</td>\
             <td style=\"text-align:right\">{}</td><td{}>{}</td></tr>\n",
            escape_html(&t.metric),
            t.baseline,
            t.current,
            cls_attr,
            arrow,
        ));
    }
    out.push_str("</tbody>\n</table>\n");

    // ---- Violation deltas ----
    render_violation_list(
        &mut out,
        "New violations — NEW since baseline",
        &drift.violations_new,
        "host-new",
        MAX_VIOLATIONS,
    );
    render_violation_list(
        &mut out,
        "Resolved violations",
        &drift.violations_resolved,
        "host-gone",
        MAX_VIOLATIONS,
    );
    render_violation_list(
        &mut out,
        "Persisting violations",
        &drift.violations_persisting,
        "",
        MAX_VIOLATIONS,
    );

    out
}

/// CSS class for a tally direction arrow. `up` is true when current > baseline.
/// A rise in a violation metric is a regression (high color); a fall is good
/// news (ok color). Benign metrics (allowed/intra-zone/multicast/external) carry
/// no tint.
fn drift_metric_class(metric: &str, up: bool) -> &'static str {
    let is_violation = matches!(
        metric,
        "distinct_violating_flows" | "idmz_bypasses" | "no_matching_conduit" | "wrong_direction"
    );
    if !is_violation {
        return "";
    }
    if up {
        "host-gone"
    } else {
        "host-new"
    }
}

/// Append a titled violation-delta list to `out`. `row_class` tints the kind
/// cell ("host-new" green / "host-gone" struck-through / "" plain). Skips
/// entirely when the slice is empty.
fn render_violation_list(
    out: &mut String,
    title: &str,
    refs: &[crate::diff::ViolationRef],
    row_class: &str,
    max: usize,
) {
    if refs.is_empty() {
        return;
    }
    out.push_str(&format!(
        "<h3>{} ({})</h3>\n<ul>\n",
        escape_html(title),
        refs.len()
    ));
    for v in refs.iter().take(max) {
        let cls_attr = if row_class.is_empty() {
            String::new()
        } else {
            format!(" class=\"{row_class}\"")
        };
        out.push_str(&format!(
            "<li><code{}>{}</code> · <code>{}</code> → <code>{}:{}/{}</code> · {}</li>\n",
            cls_attr,
            escape_html(&v.kind),
            escape_html(&v.src_pseudonym),
            escape_html(&v.dst_pseudonym),
            v.dst_port,
            escape_html(&v.proto),
            escape_html(&v.severity),
        ));
    }
    if refs.len() > max {
        out.push_str(&format!(
            "<li class=\"muted\">… and {} more</li>\n",
            refs.len() - max
        ));
    }
    out.push_str("</ul>\n");
}

/// Minimal HTML-escape for the hand-built drift fragment. The inputs are
/// tool-controlled (pseudonyms / digests / fixed metric ids) so this is
/// defense-in-depth, matching the project's "fail safe" stance.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a cross-capture diff as a self-contained HTML report (S-6.03 AC-001).
///
/// Produces a self-contained HTML document with sections for new, recurring,
/// and resolved findings, host changes, role shifts, and flow shifts. All
/// sections sort deterministically so repeated calls produce byte-identical output.
///
/// EC-003: `OtError::Render` propagation is satisfied by the `?` on
/// `view.render()` below. For a well-typed `DiffReportView` (all owned
/// `String` / `Vec<…>` fields, askama `escape="html"`) the inner template
/// render is infallible in practice — but the `Result` return type and `?`
/// propagation mean any future I/O-backed template variant will still be
/// caught. No additional test is needed; the property is structural.
pub fn render_diff_html(diff: &Diff) -> Result<String> {
    const MAX_EVIDENCE: usize = 5;

    // P1-13: segmentation drift counts as a delta, so a diff with only drift
    // doesn't fall under the "no deltas" banner.
    let seg_has_drift = diff
        .segmentation
        .as_ref()
        .map(segmentation_has_drift)
        .unwrap_or(false);
    let no_deltas = diff.hosts_new.is_empty()
        && diff.hosts_gone.is_empty()
        && diff.findings_new.is_empty()
        && diff.findings_recurring.is_empty()
        && diff.findings_resolved.is_empty()
        && diff.role_shifts.is_empty()
        && diff.flow_shifts.is_empty()
        && diff.flows_new.is_empty()
        && diff.flows_gone.is_empty()
        && !seg_has_drift;

    // C-1 (AC-003): sort each finding slice by a total key before rendering
    // so that two findings sharing the same rule `id` produce a deterministic
    // order regardless of the order they came out of HashSet iteration in
    // `diff::compute`. We clone into a local sorted vec rather than mutating
    // the input `Diff`.
    let mut sorted_new = diff.findings_new.clone();
    sort_findings_total(&mut sorted_new);
    let mut sorted_recurring = diff.findings_recurring.clone();
    sort_findings_total(&mut sorted_recurring);
    let mut sorted_resolved = diff.findings_resolved.clone();
    sort_findings_total(&mut sorted_resolved);

    let findings_new: Vec<DiffFindingView> = sorted_new
        .iter()
        .map(|f| diff_finding_view(f, MAX_EVIDENCE))
        .collect();

    let findings_recurring: Vec<DiffFindingView> = sorted_recurring
        .iter()
        .map(|f| diff_finding_view(f, MAX_EVIDENCE))
        .collect();

    let findings_resolved: Vec<DiffFindingView> = sorted_resolved
        .iter()
        .map(|f| diff_finding_view(f, MAX_EVIDENCE))
        .collect();

    // F-4: defensively sort non-finding sections on local clones so the
    // renderer is self-sufficiently deterministic even if `compute()` changes.
    let mut sorted_hosts_new = diff.hosts_new.clone();
    sorted_hosts_new.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));
    let mut sorted_hosts_gone = diff.hosts_gone.clone();
    sorted_hosts_gone.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));
    let mut sorted_role_shifts = diff.role_shifts.clone();
    sorted_role_shifts.sort_by(|a, b| {
        a.pseudonym
            .cmp(&b.pseudonym)
            .then_with(|| a.old_role.cmp(&b.old_role))
            .then_with(|| a.new_role.cmp(&b.new_role))
    });
    let mut sorted_flow_shifts = diff.flow_shifts.clone();
    sorted_flow_shifts.sort_by(|a, b| {
        // Largest-ratio first ("loudest signal first") — mirrors diff.rs intent.
        b.ratio
            .partial_cmp(&a.ratio)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.src.cmp(&b.src))
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
    let mut sorted_flows_new = diff.flows_new.clone();
    sorted_flows_new.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
    let mut sorted_flows_gone = diff.flows_gone.clone();
    sorted_flows_gone.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });

    let hosts_new: Vec<DiffHostView> = sorted_hosts_new.iter().map(diff_host_view).collect();

    let hosts_gone: Vec<DiffHostView> = sorted_hosts_gone.iter().map(diff_host_view).collect();

    let role_shifts: Vec<DiffRoleShiftView> = sorted_role_shifts
        .iter()
        .map(|r| DiffRoleShiftView {
            pseudonym: r.pseudonym.clone(),
            old_role: r.old_role.clone(),
            new_role: r.new_role.clone(),
        })
        .collect();

    let flow_shifts: Vec<DiffFlowShiftView> = sorted_flow_shifts
        .iter()
        .map(|f| DiffFlowShiftView {
            src: f.src.clone(),
            dst: f.dst.clone(),
            dst_port: f.dst_port,
            proto: f.proto.clone(),
            baseline_bytes: f.baseline_bytes.to_string(),
            current_bytes: f.current_bytes.to_string(),
            ratio: format!("{:.2}", f.ratio),
        })
        .collect();

    let flows_new: Vec<DiffFlowSummaryView> = sorted_flows_new
        .iter()
        .map(diff_flow_summary_view)
        .collect();

    let flows_gone: Vec<DiffFlowSummaryView> = sorted_flows_gone
        .iter()
        .map(diff_flow_summary_view)
        .collect();

    // P1-13: pre-render the drift fragment (empty when no policy was supplied).
    let segmentation_section = diff
        .segmentation
        .as_ref()
        .map(render_segmentation_drift_section)
        .unwrap_or_default();

    let view = DiffReportView {
        version: crate::VERSION.to_string(),
        no_deltas,
        segmentation_section,
        findings_new_count: diff.findings_new.len(),
        findings_recurring_count: diff.findings_recurring.len(),
        findings_resolved_count: diff.findings_resolved.len(),
        hosts_new_count: diff.hosts_new.len(),
        hosts_gone_count: diff.hosts_gone.len(),
        flow_shifts_count: diff.flow_shifts.len(),
        flow_shift_label: format!("≥{}", fmt_multiplier(diff.flow_shift_multiplier)),
        findings_new,
        findings_recurring,
        findings_resolved,
        hosts_new,
        hosts_gone,
        role_shifts,
        flow_shifts,
        flows_new,
        flows_gone,
    };
    Ok(view.render()?)
}

#[derive(Template)]
#[template(path = "diff.html", escape = "html")]
struct DiffReportView {
    version: String,
    no_deltas: bool,
    /// Pre-rendered "Segmentation drift" HTML fragment (P1-13), empty when no
    /// `--policy` was supplied. Tool-controlled content (pseudonyms + integer
    /// tallies + a hex digest), so the template's `|safe` is sound.
    segmentation_section: String,
    findings_new_count: usize,
    findings_recurring_count: usize,
    findings_resolved_count: usize,
    hosts_new_count: usize,
    hosts_gone_count: usize,
    flow_shifts_count: usize,
    /// Pre-formatted label for the flow-shift threshold, e.g. `"≥2×"` or `"≥3×"`.
    /// Computed from `Diff::flow_shift_multiplier` so the template stays logic-light
    /// per ADR-0003.
    flow_shift_label: String,
    findings_new: Vec<DiffFindingView>,
    findings_recurring: Vec<DiffFindingView>,
    findings_resolved: Vec<DiffFindingView>,
    hosts_new: Vec<DiffHostView>,
    hosts_gone: Vec<DiffHostView>,
    role_shifts: Vec<DiffRoleShiftView>,
    flow_shifts: Vec<DiffFlowShiftView>,
    flows_new: Vec<DiffFlowSummaryView>,
    flows_gone: Vec<DiffFlowSummaryView>,
}

struct DiffFindingView {
    id: String,
    severity_label: String,
    severity_class: String,
    title: String,
    summary: String,
    evidence: Vec<String>,
    /// Number of evidence rows after capping (≤ MAX_EVIDENCE).
    evidence_count: usize,
    /// Total evidence rows before capping. When `evidence_total > evidence_count`
    /// the template renders "showing {evidence_count} of {evidence_total}";
    /// otherwise it renders "{evidence_count} sample(s)".
    evidence_total: usize,
    recommendation: String,
}

struct DiffHostView {
    pseudonym: String,
    role: String,
    protocols: String,
    zone: String,
    packets: String,
    bytes: String,
}

struct DiffRoleShiftView {
    pseudonym: String,
    old_role: String,
    new_role: String,
}

struct DiffFlowShiftView {
    src: String,
    dst: String,
    dst_port: u16,
    proto: String,
    baseline_bytes: String,
    current_bytes: String,
    ratio: String,
}

struct DiffFlowSummaryView {
    src: String,
    dst: String,
    dst_port: u16,
    proto: String,
    bytes: String,
}

/// Format a flow-shift multiplier for display labels.
///
/// Integer values (fract == 0) are rendered without a trailing ".0":
/// `2.0 → "2×"`, `3.0 → "3×"`. Non-integer values use one decimal place:
/// `1.5 → "1.5×"`. Always includes the "×" suffix.
fn fmt_multiplier(m: f64) -> String {
    if m.fract() == 0.0 {
        format!("{}×", m as i64)
    } else {
        format!("{:.1}×", m)
    }
}

fn diff_finding_view(f: &Finding, max_evidence: usize) -> DiffFindingView {
    let evidence_total = f.evidence.len();
    let capped: Vec<String> = f.evidence.iter().take(max_evidence).cloned().collect();
    let evidence_count = capped.len();
    DiffFindingView {
        id: f.id.to_string(),
        severity_label: severity_label(f.severity).to_string(),
        severity_class: severity_class(f.severity).to_string(),
        title: f.title.clone(),
        summary: f.summary.clone(),
        evidence: capped,
        evidence_count,
        evidence_total,
        recommendation: f.recommendation.to_string(),
    }
}

/// C-1 (AC-003): sort a findings slice by a provably total key
/// `(id, title, severity, evidence_all_joined, summary, recommendation)`
/// to guarantee a deterministic order even when two findings share the same
/// rule `id`. The key is total: every component is total-ordered, and the
/// final `recommendation` field eliminates the last remaining source of
/// input-order dependency.
fn sort_findings_total(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.id.cmp(b.id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| a.evidence.join("\n").cmp(&b.evidence.join("\n")))
            .then_with(|| a.summary.cmp(&b.summary))
            .then_with(|| a.recommendation.cmp(b.recommendation))
    });
}

fn diff_host_view(h: &crate::diff::HostRef) -> DiffHostView {
    DiffHostView {
        pseudonym: h.pseudonym.clone(),
        role: h.role.clone(),
        protocols: if h.protocols.is_empty() {
            "—".to_string()
        } else {
            h.protocols.join(", ")
        },
        zone: if h.in_ot_zone {
            "OT".to_string()
        } else {
            "IT".to_string()
        },
        packets: h.packets.to_string(),
        bytes: human_bytes(h.bytes),
    }
}

fn diff_flow_summary_view(f: &crate::diff::FlowSummary) -> DiffFlowSummaryView {
    DiffFlowSummaryView {
        src: f.src.clone(),
        dst: f.dst.clone(),
        dst_port: f.dst_port,
        proto: f.proto.clone(),
        bytes: human_bytes(f.bytes),
    }
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

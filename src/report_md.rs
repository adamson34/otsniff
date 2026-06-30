//! Markdown report rendering.
//!
//! Produces an LLM-friendly text report with the same structure as the HTML
//! report. Built as plain string formatting — no template engine — because
//! the markdown is short and the substitution model is straightforward.
//!
//! The output is designed to be paste-able into an LLM chat. Sections, table
//! columns, and severity labels are stable so prompt templates that reference
//! them don't break across runs.

use std::fmt::Write;

use chrono::{DateTime, Utc};

use crate::capture_source::Classification;
use crate::diff::Diff;
use crate::error::Result;
use crate::findings::augmented::AugmentedFinding;
use crate::findings::{Finding, Severity};
use crate::inventory::{Asset, Role};
use crate::observe::Observations;

pub fn render_markdown(
    inventory: &[Asset],
    findings: &[Finding],
    obs: &Observations,
    input_label: &str,
    generated_at: DateTime<Utc>,
    capture_source: Option<&Classification>,
) -> Result<String> {
    let mut out = String::new();

    writeln!(out, "# otsniff report").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_Source: `{}` · Generated: {} · otsniff v{}_",
        input_label,
        fmt_ts(generated_at),
        crate::VERSION
    )
    .unwrap();
    writeln!(out).unwrap();

    // Summary stats
    writeln!(out, "## Summary").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "- **Packets parsed:** {}", obs.total_packets).unwrap();
    writeln!(out, "- **Payload bytes:** {}", human_bytes(obs.total_bytes)).unwrap();
    let ot_count = inventory.iter().filter(|a| a.in_ot_zone).count();
    writeln!(
        out,
        "- **Hosts seen:** {} ({} in OT zones)",
        inventory.len(),
        ot_count
    )
    .unwrap();
    writeln!(out, "- **Findings:** {}", findings.len()).unwrap();
    let span = match (obs.first_ts, obs.last_ts) {
        (Some(a), Some(b)) => format!("{} → {}", fmt_ts(a), fmt_ts(b)),
        _ => "(no timestamps)".to_string(),
    };
    writeln!(out, "- **Capture window:** {}", span).unwrap();
    // S-10.01 AC-003: a degenerate time base gets a warning blockquote right
    // after the capture-window line. When the time base is sane, nothing is
    // written — keeping clean-capture markdown byte-identical (AC-005).
    let capture_warnings = crate::capture_sanity::assess(obs);
    if !capture_warnings.is_empty() {
        let joined = capture_warnings
            .iter()
            .map(|w| w.message())
            .collect::<Vec<_>>()
            .join("; ");
        writeln!(out, "> ⚠ **Capture timestamp warning:** {joined}").unwrap();
    }
    if let Some(c) = capture_source {
        writeln!(out, "- **Capture source:** {}", c.report_line()).unwrap();
    }
    writeln!(out).unwrap();

    // Findings
    writeln!(out, "## Findings").unwrap();
    writeln!(out).unwrap();
    if findings.is_empty() {
        // No editorial / hedging text here. The markdown report is consumed
        // by humans AND by AI providers via `analyze` — including caveat
        // language ("quiet captures sometimes mean...") in the AI's input
        // primes the model to lead with data-quality concerns instead of
        // analyzing what's actually there. Caveat language belongs in the
        // HTML report or as a system-prompt rule, not interpolated into
        // the data the AI reads.
        writeln!(out, "_(none)_").unwrap();
        writeln!(out).unwrap();
    } else {
        for f in findings {
            writeln!(
                out,
                "### [{}] {}",
                severity_label(f.severity).to_uppercase(),
                f.title
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "{}", f.summary).unwrap();
            writeln!(out).unwrap();
            if !f.evidence.is_empty() {
                writeln!(out, "**Evidence ({} sample(s)):**", f.evidence.len()).unwrap();
                writeln!(out, "```").unwrap();
                for e in &f.evidence {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "```").unwrap();
                writeln!(out).unwrap();
            }
            if let Some(meta) = crate::findings::metadata_for(f.id) {
                writeln!(out, "**Detection criteria.** {}", meta.trigger).unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", f.recommendation).unwrap();
            writeln!(out).unwrap();
            if !f.playbook.is_empty() {
                writeln!(out, "**Investigation playbook:**").unwrap();
                writeln!(out).unwrap();
                for (i, step) in f.playbook.iter().enumerate() {
                    writeln!(out, "{}. {}", i + 1, step).unwrap();
                }
                writeln!(out).unwrap();
            }
            writeln!(out, "_id: `{}`_", f.id).unwrap();
            writeln!(out).unwrap();
        }
    }

    // Asset inventory
    writeln!(out, "## Asset inventory").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| IP | Hostname | Zone | MAC | Vendor | Inferred role | Protocols | Packets | Bytes |"
    )
    .unwrap();
    writeln!(
        out,
        "|----|----------|------|-----|--------|---------------|-----------|---------|-------|"
    )
    .unwrap();
    for a in inventory {
        writeln!(
            out,
            "| `{}` | {} | {} | `{}` | {} | {} | {} | {} | {} |",
            a.ip,
            a.hostname
                .as_ref()
                .map(|s| format!("`{s}`"))
                .unwrap_or_else(|| "—".to_string()),
            if a.in_ot_zone { "OT" } else { "IT" },
            a.mac.clone().unwrap_or_else(|| "—".to_string()),
            a.vendor.clone().unwrap_or_else(|| "—".to_string()),
            role_label(a.role),
            if a.protocols.is_empty() {
                "—".to_string()
            } else {
                a.protocols.join(", ")
            },
            a.packets,
            human_bytes(a.bytes),
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // Top flows
    writeln!(out, "## Top flows").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| Source | Destination | Protocol | Conns | Packets | Bytes |"
    )
    .unwrap();
    writeln!(
        out,
        "|--------|-------------|----------|-------|---------|-------|"
    )
    .unwrap();
    let mut flow_refs: Vec<&crate::observe::FlowObs> = obs.flows.values().collect();
    flow_refs.sort_by_key(|f| std::cmp::Reverse(f.bytes));
    for f in flow_refs.into_iter().take(25) {
        let label = f.label.clone().unwrap_or_else(|| match f.key.proto {
            6 => "tcp".to_string(),
            17 => "udp".to_string(),
            _ => format!("ip/{}", f.key.proto),
        });
        writeln!(
            out,
            "| `{}` | `{}:{}` | {} | {} | {} | {} |",
            f.key.src,
            f.key.dst,
            f.key.dst_port,
            label,
            f.connections(),
            f.packets,
            human_bytes(f.bytes),
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // No trailing editorial. See the comment above the empty-findings
    // branch for the reasoning — same applies here.

    Ok(out)
}

/// Render the "AI-augmented findings" section as a Markdown fragment
/// (S-5.03 AC-004 / BC-3.07.001).
///
/// Returns an empty string when `findings` is empty so the caller can
/// omit the section. Marked with a `[AI]` prefix per finding for visual
/// distinction from rule-based findings.
///
/// Unscrub must be applied to `findings[*].reasoning` and `findings[*].evidence`
/// before calling this function.
pub fn render_augmented_section_md(findings: &[AugmentedFinding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let mut out = String::new();

    writeln!(out, "## AI-augmented findings").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_Patterns surfaced by a second AI pass, anchored on rule findings and inventory. \
         Confidence ratings are the model's self-assessment._"
    )
    .unwrap();
    writeln!(out).unwrap();

    for f in findings {
        let conf_label = match f.confidence {
            crate::findings::augmented::Confidence::High => "High",
            crate::findings::augmented::Confidence::Medium => "Medium",
            crate::findings::augmented::Confidence::Low => "Low",
        };

        writeln!(
            out,
            "### [AI][{}] {}",
            severity_label(f.severity).to_uppercase(),
            f.title
        )
        .unwrap();
        writeln!(out).unwrap();
        writeln!(out, "_id: `{}` · confidence: {}_", f.id, conf_label).unwrap();
        writeln!(out).unwrap();

        if !f.evidence.is_empty() {
            writeln!(out, "**Evidence ({} sample(s)):**", f.evidence.len()).unwrap();
            writeln!(out, "```").unwrap();
            for ev in &f.evidence {
                writeln!(out, "{ev}").unwrap();
            }
            writeln!(out, "```").unwrap();
            writeln!(out).unwrap();
        }

        if !f.reasoning.is_empty() {
            writeln!(out, "**AI reasoning:**").unwrap();
            writeln!(out).unwrap();
            writeln!(out, "{}", f.reasoning).unwrap();
            writeln!(out).unwrap();
        }
    }

    out
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

fn role_label(r: Role) -> &'static str {
    r.label()
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

/// Escape a string for safe use in a markdown pipe-table cell.
///
/// I-1: free-form strings that contain `|` would corrupt the table structure
/// (the pipe is the cell delimiter). Newlines would break the row. This helper
/// replaces both so any string is safe to interpolate between `|` delimiters.
fn md_cell(s: &str) -> String {
    s.replace('|', r"\|").replace('\n', " ")
}

/// Sanitise a string for safe use in a markdown heading (`###`).
///
/// In a heading `|` is not a table delimiter, so pipe-escaping would produce
/// literal backslash-pipe in the rendered output. This helper collapses
/// newlines and control characters (which would break the heading line) to a
/// space, but does NOT escape `|`.
fn md_heading(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c.is_control() { ' ' } else { c })
        .collect()
}

/// Compute a CommonMark-safe fence string for a block whose content may
/// include backtick runs.
///
/// F-1: a fenced code block can only be closed by a run of backticks that is
/// at least as long as the opening run (CommonMark §4.5). If any evidence line
/// contains a run of N consecutive backticks, a fence of N backticks would be
/// broken. This function scans `lines` for the longest consecutive-backtick
/// run R and returns a fence of max(R+1, 3) backticks. Using the same string
/// for open and close guarantees the block is always well-formed.
fn make_fence(lines: &[impl AsRef<str>]) -> String {
    let max_run = lines
        .iter()
        .flat_map(|l| {
            // Count runs of consecutive backticks in this line.
            let mut runs = Vec::new();
            let mut count = 0usize;
            for ch in l.as_ref().chars() {
                if ch == '`' {
                    count += 1;
                } else {
                    if count > 0 {
                        runs.push(count);
                    }
                    count = 0;
                }
            }
            if count > 0 {
                runs.push(count);
            }
            runs
        })
        .max()
        .unwrap_or(0);

    let fence_len = max_run.saturating_add(1).max(3);
    "`".repeat(fence_len)
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

/// Render a cross-capture diff as markdown (S-6.03 AC-002).
///
/// Render the "Zonewarden — Segmentation Conformance" markdown section from a
/// conformance result (ADR-0013). Returned as a standalone fragment so the
/// caller injects it only when a `--policy` was supplied.
pub fn render_conformance_section_md(r: &zonewarden::types::ConformanceResult) -> String {
    let mut out = String::new();
    writeln!(out, "## Zonewarden — Segmentation Conformance").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Observed flows classified against the declared IEC 62443 zone/conduit policy."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Metric | Count |").unwrap();
    writeln!(out, "|--------|------:|").unwrap();
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
        writeln!(out, "| {label} | {n} |").unwrap();
    }
    writeln!(out).unwrap();
    writeln!(
        out,
        "Policy digest: `{}` — deterministic; identical inputs reproduce it byte-for-byte.",
        r.policy_digest
    )
    .unwrap();
    writeln!(out).unwrap();
    out
}

/// Render the "Segmentation drift" markdown section from a
/// [`crate::diff::SegmentationDrift`] (P1-13). Mirror of the HTML section: a
/// policy-digest anchor line, a tally table, and three violation-delta lists.
/// Returned as a standalone fragment so the caller injects it positionally.
pub fn render_segmentation_drift_md(drift: &crate::diff::SegmentationDrift) -> String {
    /// Cap on violation rows per list to keep the report readable.
    const MAX_VIOLATIONS: usize = 10;

    let mut out = String::new();
    writeln!(out, "## Segmentation drift").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Policy digest: `{}` — one policy scored both captures; identical on \
         each side by construction.",
        drift.policy_digest
    )
    .unwrap();
    writeln!(out).unwrap();

    // Tally deltas.
    writeln!(out, "### Conformance tally").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| Metric | Baseline | Current | Direction |").unwrap();
    writeln!(out, "|--------|---------:|--------:|:---------:|").unwrap();
    for t in &drift.tally {
        let arrow = match t.current.cmp(&t.baseline) {
            std::cmp::Ordering::Greater => "▲",
            std::cmp::Ordering::Less => "▼",
            std::cmp::Ordering::Equal => "—",
        };
        writeln!(
            out,
            "| {} | {} | {} | {} |",
            md_cell(&t.metric),
            t.baseline,
            t.current,
            arrow
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    let render_list = |out: &mut String, title: &str, refs: &[crate::diff::ViolationRef]| {
        if refs.is_empty() {
            return;
        }
        writeln!(out, "### {} ({})", title, refs.len()).unwrap();
        writeln!(out).unwrap();
        for v in refs.iter().take(MAX_VIOLATIONS) {
            writeln!(
                out,
                "- `{}` · `{}` → `{}:{}/{}` · {}",
                md_cell(&v.kind),
                v.src_pseudonym,
                v.dst_pseudonym,
                v.dst_port,
                md_cell(&v.proto),
                md_cell(&v.severity),
            )
            .unwrap();
        }
        if refs.len() > MAX_VIOLATIONS {
            writeln!(out, "- _… and {} more_", refs.len() - MAX_VIOLATIONS).unwrap();
        }
        writeln!(out).unwrap();
    };
    render_list(
        &mut out,
        "New violations — NEW since baseline",
        &drift.violations_new,
    );
    render_list(&mut out, "Resolved violations", &drift.violations_resolved);
    render_list(
        &mut out,
        "Persisting violations",
        &drift.violations_persisting,
    );

    out
}

/// Produces an LLM-friendly markdown report with the same sections as the HTML
/// diff renderer. All sections sort deterministically; each section defensively
/// re-sorts its local clone before rendering so the output is self-sufficiently
/// deterministic even if `compute()` changes its output order.
pub fn render_diff_markdown(diff: &Diff) -> String {
    const MAX_EVIDENCE: usize = 5;
    let mut out = String::new();

    writeln!(out, "# otsniff diff report").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "_otsniff v{}_", crate::VERSION).unwrap();
    writeln!(out).unwrap();

    // P1-13: pre-render the drift fragment (empty when no policy was supplied)
    // and treat any actual drift as a delta so the "no deltas" banner stays honest.
    let segmentation_md = diff
        .segmentation
        .as_ref()
        .map(render_segmentation_drift_md)
        .unwrap_or_default();
    let seg_has_drift = diff
        .segmentation
        .as_ref()
        .map(segmentation_has_drift_md)
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

    if no_deltas {
        writeln!(
            out,
            "> **No deltas detected** — captures are identical by all tracked metrics."
        )
        .unwrap();
        writeln!(out).unwrap();
        // Still surface the conformance tally when a policy was supplied.
        if !segmentation_md.is_empty() {
            out.push_str(&segmentation_md);
        }
        return out;
    }

    // Summary banner
    writeln!(out, "## Summary").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "- **New findings:** {}", diff.findings_new.len()).unwrap();
    writeln!(
        out,
        "- **Recurring findings:** {}",
        diff.findings_recurring.len()
    )
    .unwrap();
    writeln!(
        out,
        "- **Resolved findings:** {}",
        diff.findings_resolved.len()
    )
    .unwrap();
    writeln!(out, "- **New hosts:** {}", diff.hosts_new.len()).unwrap();
    writeln!(out, "- **Gone hosts:** {}", diff.hosts_gone.len()).unwrap();
    writeln!(
        out,
        "- **Flow shifts (≥{}):** {}",
        fmt_multiplier(diff.flow_shift_multiplier),
        diff.flow_shifts.len()
    )
    .unwrap();
    writeln!(out).unwrap();

    // C-1 (AC-003): sort each slice by a total key before rendering so two
    // findings with the same rule id produce deterministic output.
    let mut sorted_new = diff.findings_new.clone();
    sort_findings_total_md(&mut sorted_new);
    let mut sorted_recurring = diff.findings_recurring.clone();
    sort_findings_total_md(&mut sorted_recurring);
    let mut sorted_resolved = diff.findings_resolved.clone();
    sort_findings_total_md(&mut sorted_resolved);

    // New findings
    if !sorted_new.is_empty() {
        writeln!(out, "## New findings — NEW since baseline").unwrap();
        writeln!(out).unwrap();
        for f in &sorted_new {
            writeln!(
                out,
                "### [NEW][{}] {}",
                severity_label(f.severity).to_uppercase(),
                md_heading(&f.title),
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "{}", md_cell(&f.summary)).unwrap();
            writeln!(out).unwrap();
            let evidence_total = f.evidence.len();
            let capped: Vec<&String> = f.evidence.iter().take(MAX_EVIDENCE).collect();
            if !capped.is_empty() {
                let cap = capped.len();
                if evidence_total > cap {
                    writeln!(out, "**Evidence (showing {cap} of {evidence_total}):**").unwrap();
                } else {
                    writeln!(out, "**Evidence ({cap} sample(s)):**").unwrap();
                }
                let fence = make_fence(&capped);
                writeln!(out, "{fence}").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "{fence}").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", md_cell(f.recommendation)).unwrap();
            writeln!(out).unwrap();
            writeln!(out, "_id: `{}`_", f.id).unwrap();
            writeln!(out).unwrap();
        }
    }

    // Recurring findings
    if !sorted_recurring.is_empty() {
        writeln!(out, "## Recurring findings").unwrap();
        writeln!(out).unwrap();
        for f in &sorted_recurring {
            writeln!(
                out,
                "### [RECURRING][{}] {}",
                severity_label(f.severity).to_uppercase(),
                md_heading(&f.title),
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "{}", md_cell(&f.summary)).unwrap();
            writeln!(out).unwrap();
            let evidence_total = f.evidence.len();
            let capped: Vec<&String> = f.evidence.iter().take(MAX_EVIDENCE).collect();
            if !capped.is_empty() {
                let cap = capped.len();
                if evidence_total > cap {
                    writeln!(out, "**Evidence (showing {cap} of {evidence_total}):**").unwrap();
                } else {
                    writeln!(out, "**Evidence ({cap} sample(s)):**").unwrap();
                }
                let fence = make_fence(&capped);
                writeln!(out, "{fence}").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "{fence}").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", md_cell(f.recommendation)).unwrap();
            writeln!(out).unwrap();
            writeln!(out, "_id: `{}`_", f.id).unwrap();
            writeln!(out).unwrap();
        }
    }

    // Resolved findings
    if !sorted_resolved.is_empty() {
        writeln!(out, "## Resolved findings").unwrap();
        writeln!(out).unwrap();
        for f in &sorted_resolved {
            writeln!(
                out,
                "### [RESOLVED][{}] {}",
                severity_label(f.severity).to_uppercase(),
                md_heading(&f.title),
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "{}", md_cell(&f.summary)).unwrap();
            writeln!(out).unwrap();
            let evidence_total = f.evidence.len();
            let capped: Vec<&String> = f.evidence.iter().take(MAX_EVIDENCE).collect();
            if !capped.is_empty() {
                let cap = capped.len();
                if evidence_total > cap {
                    writeln!(out, "**Evidence (showing {cap} of {evidence_total}):**").unwrap();
                } else {
                    writeln!(out, "**Evidence ({cap} sample(s)):**").unwrap();
                }
                let fence = make_fence(&capped);
                writeln!(out, "{fence}").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "{fence}").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", md_cell(f.recommendation)).unwrap();
            writeln!(out).unwrap();
            writeln!(out, "_id: `{}`_", f.id).unwrap();
            writeln!(out).unwrap();
        }
    }

    // F-4: defensively sort non-finding sections on local clones so the
    // renderer is self-sufficiently deterministic even if `compute()` changes.
    let mut hosts_new = diff.hosts_new.clone();
    hosts_new.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));
    let mut hosts_gone = diff.hosts_gone.clone();
    hosts_gone.sort_by(|a, b| a.pseudonym.cmp(&b.pseudonym));
    let mut role_shifts = diff.role_shifts.clone();
    role_shifts.sort_by(|a, b| {
        a.pseudonym
            .cmp(&b.pseudonym)
            .then_with(|| a.old_role.cmp(&b.old_role))
            .then_with(|| a.new_role.cmp(&b.new_role))
    });
    let mut flow_shifts = diff.flow_shifts.clone();
    flow_shifts.sort_by(|a, b| {
        // Largest-ratio first ("loudest signal first") — mirrors diff.rs intent.
        b.ratio
            .partial_cmp(&a.ratio)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.src.cmp(&b.src))
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
    let mut flows_new = diff.flows_new.clone();
    flows_new.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });
    let mut flows_gone = diff.flows_gone.clone();
    flows_gone.sort_by(|a, b| {
        a.src
            .cmp(&b.src)
            .then_with(|| a.dst.cmp(&b.dst))
            .then_with(|| a.dst_port.cmp(&b.dst_port))
            .then_with(|| a.proto.cmp(&b.proto))
    });

    // Host changes
    if !hosts_new.is_empty() || !hosts_gone.is_empty() {
        writeln!(out, "## Host changes").unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "| Pseudonym | Status | Role | Protocols | Zone | Packets | Bytes |"
        )
        .unwrap();
        writeln!(
            out,
            "|-----------|--------|------|-----------|------|---------|-------|"
        )
        .unwrap();
        for h in &hosts_new {
            writeln!(
                out,
                "| `{}` | **New** | {} | {} | {} | {} | {} |",
                h.pseudonym,
                md_cell(&h.role),
                if h.protocols.is_empty() {
                    "—".to_string()
                } else {
                    md_cell(&h.protocols.join(", "))
                },
                if h.in_ot_zone { "OT" } else { "IT" },
                h.packets,
                human_bytes(h.bytes),
            )
            .unwrap();
        }
        for h in &hosts_gone {
            writeln!(
                out,
                "| `{}` | ~~Gone~~ | {} | {} | {} | {} | {} |",
                h.pseudonym,
                md_cell(&h.role),
                if h.protocols.is_empty() {
                    "—".to_string()
                } else {
                    md_cell(&h.protocols.join(", "))
                },
                if h.in_ot_zone { "OT" } else { "IT" },
                h.packets,
                human_bytes(h.bytes),
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // Role shifts
    if !role_shifts.is_empty() {
        writeln!(out, "## Role shifts").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Pseudonym | Old role | → | New role |").unwrap();
        writeln!(out, "|-----------|----------|---|----------|").unwrap();
        for r in &role_shifts {
            writeln!(
                out,
                "| `{}` | {} | → | {} |",
                r.pseudonym,
                md_cell(&r.old_role),
                md_cell(&r.new_role),
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // Flow shifts
    if !flow_shifts.is_empty() {
        writeln!(
            out,
            "## Flow shifts (≥{} volume change)",
            fmt_multiplier(diff.flow_shift_multiplier)
        )
        .unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "| Source | Destination | Port | Proto | Baseline bytes | Current bytes | Ratio |"
        )
        .unwrap();
        writeln!(
            out,
            "|--------|-------------|------|-------|----------------|---------------|-------|"
        )
        .unwrap();
        for f in &flow_shifts {
            writeln!(
                out,
                "| `{}` | `{}` | {} | {} | {} | {} | {:.2}× |",
                f.src,
                f.dst,
                f.dst_port,
                md_cell(&f.proto),
                f.baseline_bytes,
                f.current_bytes,
                f.ratio,
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // Flow inventory changes
    if !flows_new.is_empty() || !flows_gone.is_empty() {
        writeln!(out, "## Flow inventory changes").unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "| Source | Destination | Port | Proto | Status | Bytes |"
        )
        .unwrap();
        writeln!(
            out,
            "|--------|-------------|------|-------|--------|-------|"
        )
        .unwrap();
        for f in &flows_new {
            writeln!(
                out,
                "| `{}` | `{}` | {} | {} | **New** | {} |",
                f.src,
                f.dst,
                f.dst_port,
                md_cell(&f.proto),
                human_bytes(f.bytes),
            )
            .unwrap();
        }
        for f in &flows_gone {
            writeln!(
                out,
                "| `{}` | `{}` | {} | {} | ~~Gone~~ | {} |",
                f.src,
                f.dst,
                f.dst_port,
                md_cell(&f.proto),
                human_bytes(f.bytes),
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // P1-13: segmentation drift section (empty when no policy was supplied).
    if !segmentation_md.is_empty() {
        out.push_str(&segmentation_md);
    }

    out
}

/// True when a [`crate::diff::SegmentationDrift`] carries any actual movement
/// (new/resolved violations, or a changed tally metric). Mirrors the HTML
/// renderer's `segmentation_has_drift`.
fn segmentation_has_drift_md(drift: &crate::diff::SegmentationDrift) -> bool {
    !drift.violations_new.is_empty()
        || !drift.violations_resolved.is_empty()
        || drift.tally.iter().any(|t| t.baseline != t.current)
}

/// C-1 (AC-003): sort a findings slice by a provably total key
/// `(id, title, severity discriminant, evidence_all_joined, summary, recommendation)`
/// so two findings with the same rule id produce a deterministic order
/// regardless of the order they came out of HashSet iteration in
/// `diff::compute`. The key is total: every tiebreak component is a
/// total-ordered type (`&str` / `String` / `i32`), and the final
/// `recommendation` field eliminates the last remaining source of
/// input-order dependency.
fn sort_findings_total_md(findings: &mut [crate::findings::Finding]) {
    findings.sort_by(|a, b| {
        a.id.cmp(b.id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| a.evidence.join("\n").cmp(&b.evidence.join("\n")))
            .then_with(|| a.summary.cmp(&b.summary))
            .then_with(|| a.recommendation.cmp(b.recommendation))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_conformance() -> zonewarden::types::ConformanceResult {
        zonewarden::types::ConformanceResult {
            total_flows: 3,
            no_matching_conduit: 2,
            idmz_bypasses: 1,
            distinct_violating_flows: 2,
            policy_digest: "deadbeef".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn conformance_md_section_has_tallies_and_digest() {
        let md = render_conformance_section_md(&sample_conformance());
        assert!(md.contains("Zonewarden — Segmentation Conformance"));
        assert!(md.contains("| IDMZ bypasses | 1 |"));
        assert!(md.contains("`deadbeef`"));
    }

    #[test]
    fn conformance_html_section_has_heading_and_digest() {
        let html = crate::report::render_conformance_section(&sample_conformance());
        assert!(html.contains("Zonewarden — Segmentation Conformance"));
        assert!(html.contains("<code>deadbeef</code>"));
        assert!(html.contains("IDMZ bypasses"));
    }

    // ── F-1: make_fence produces a fence longer than embedded backtick runs ──

    /// `make_fence` must return a fence whose backtick-run length is strictly
    /// greater than the longest consecutive-backtick run appearing in the
    /// evidence lines it scans (and at least 3).
    ///
    /// Regression guard: a fence of ``` would break out of itself if any
    /// evidence line contains exactly "```". This test covers both
    /// 3-backtick and 4-backtick embedded runs and verifies that:
    ///   1. The fence length exceeds the max run.
    ///   2. The rendered markdown block is not broken (the next section
    ///      heading is still present after the closing fence).
    #[test]
    fn make_fence_longer_than_embedded_backtick_runs() {
        // Lines that contain a 3-backtick run and a 4-backtick run.
        let lines = vec![
            "normal line".to_string(),
            "```".to_string(),                 // exactly 3 backticks
            "````inline code````".to_string(), // longest run is 4
        ];

        let fence = make_fence(&lines);

        // The fence must be strictly longer than the 4-backtick run.
        assert!(
            fence.len() > 4,
            "fence length {} must be > 4 (longest embedded run)",
            fence.len()
        );
        // Every char in the fence must be a backtick.
        assert!(
            fence.chars().all(|c| c == '`'),
            "fence must consist entirely of backtick characters"
        );

        // Render a minimal diff markdown containing one evidence line that
        // is exactly "```" and another that is "````". Verify the block is
        // not broken: the section heading that follows the evidence block
        // must still be present in the output.
        use crate::diff::{Diff, FlowSummary};
        use crate::findings::{Finding, Severity};

        let finding = Finding {
            id: "test.backtick",
            severity: Severity::Medium,
            title: "Backtick test finding".to_string(),
            summary: "Summary".to_string(),
            evidence: vec!["```".to_string(), "````".to_string()],
            recommendation: "No action.",
            playbook: vec![],
        };

        // Put a flow_new in so there is a "## Flow inventory changes" section
        // after the finding block — if the fence is broken the heading gets
        // swallowed into the code block.
        let flow_new = FlowSummary {
            src: "host_001".to_string(),
            dst: "host_002".to_string(),
            dst_port: 502,
            proto: "tcp".to_string(),
            bytes: 1_000,
        };

        let diff = Diff {
            findings_new: vec![finding],
            flows_new: vec![flow_new],
            ..Diff::default()
        };

        let md = render_diff_markdown(&diff);

        // The closing fence of the evidence block must appear in the output.
        assert!(
            md.contains(&fence),
            "rendered markdown must contain the computed fence ({fence})"
        );

        // The flow-inventory-changes section heading must survive (not be
        // swallowed into the code block by a broken fence).
        assert!(
            md.contains("## Flow inventory changes"),
            "section heading after the evidence block must not be swallowed by \
             a broken fence; rendered output:\n{md}"
        );
    }

    // ── make_fence: minimum length is 3 even with no backticks in evidence ──

    #[test]
    fn make_fence_minimum_length_three_when_no_backticks() {
        let lines: Vec<String> = vec!["plain text".to_string(), "no backticks here".to_string()];
        let fence = make_fence(&lines);
        assert_eq!(
            fence.len(),
            3,
            "fence must be at least 3 backticks when evidence has no backtick runs"
        );
    }
}

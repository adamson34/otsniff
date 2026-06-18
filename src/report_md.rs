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

/// Render a cross-capture diff as markdown (S-6.03 AC-002).
///
/// Produces an LLM-friendly markdown report with the same sections as the HTML
/// diff renderer. All sections sort deterministically (the `Diff` struct already
/// sorts its vecs on construction; this function iterates them in order).
pub fn render_diff_markdown(diff: &Diff) -> String {
    const MAX_EVIDENCE: usize = 5;
    let mut out = String::new();

    writeln!(out, "# otsniff diff report").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "_otsniff v{}_", crate::VERSION).unwrap();
    writeln!(out).unwrap();

    let no_deltas = diff.hosts_new.is_empty()
        && diff.hosts_gone.is_empty()
        && diff.findings_new.is_empty()
        && diff.findings_recurring.is_empty()
        && diff.findings_resolved.is_empty()
        && diff.role_shifts.is_empty()
        && diff.flow_shifts.is_empty()
        && diff.flows_new.is_empty()
        && diff.flows_gone.is_empty();

    if no_deltas {
        writeln!(
            out,
            "> **No deltas detected** — captures are identical by all tracked metrics."
        )
        .unwrap();
        writeln!(out).unwrap();
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
    writeln!(out, "- **Flow shifts (≥2×):** {}", diff.flow_shifts.len()).unwrap();
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
                md_cell(&f.title),
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
                writeln!(out, "```").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "```").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", f.recommendation).unwrap();
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
                md_cell(&f.title),
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
                writeln!(out, "```").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "```").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", f.recommendation).unwrap();
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
                md_cell(&f.title),
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
                writeln!(out, "```").unwrap();
                for e in &capped {
                    writeln!(out, "{}", e).unwrap();
                }
                writeln!(out, "```").unwrap();
                writeln!(out).unwrap();
            }
            writeln!(out, "**Recommendation:** {}", f.recommendation).unwrap();
            writeln!(out).unwrap();
            writeln!(out, "_id: `{}`_", f.id).unwrap();
            writeln!(out).unwrap();
        }
    }

    // Host changes
    if !diff.hosts_new.is_empty() || !diff.hosts_gone.is_empty() {
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
        for h in &diff.hosts_new {
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
        for h in &diff.hosts_gone {
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
    if !diff.role_shifts.is_empty() {
        writeln!(out, "## Role shifts").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Pseudonym | Old role | → | New role |").unwrap();
        writeln!(out, "|-----------|----------|---|----------|").unwrap();
        for r in &diff.role_shifts {
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
    if !diff.flow_shifts.is_empty() {
        writeln!(out, "## Flow shifts (≥2× volume change)").unwrap();
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
        for f in &diff.flow_shifts {
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
    if !diff.flows_new.is_empty() || !diff.flows_gone.is_empty() {
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
        for f in &diff.flows_new {
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
        for f in &diff.flows_gone {
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

    out
}

/// C-1 (AC-003): sort a findings slice by a total key
/// `(id, title, evidence_first, summary)` so two findings with the same
/// rule id produce deterministic output across repeated compute → render
/// calls.
fn sort_findings_total_md(findings: &mut [crate::findings::Finding]) {
    findings.sort_by(|a, b| {
        a.id.cmp(b.id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| {
                a.evidence
                    .first()
                    .cloned()
                    .unwrap_or_default()
                    .cmp(&b.evidence.first().cloned().unwrap_or_default())
            })
            .then_with(|| a.summary.cmp(&b.summary))
    });
}

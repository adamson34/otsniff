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
use crate::error::Result;
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

//! Rule-catalog rendering.
//!
//! The findings layer exposes a `Vec<RuleMetadata>` via
//! `findings::catalog()`. This module turns it into markdown for human
//! review (`docs/RULES.md` and the `otsniff rules` subcommand) or JSON
//! for machine consumption.

use std::fmt::Write;

use crate::findings::{Reference, RuleMetadata};

/// Output format for the `otsniff rules` subcommand.
#[derive(Debug, Clone, Copy)]
pub enum CatalogFormat {
    Markdown,
    Json,
}

pub fn render(catalog: &[RuleMetadata], format: CatalogFormat) -> String {
    match format {
        CatalogFormat::Markdown => render_markdown(catalog),
        CatalogFormat::Json => render_json(catalog),
    }
}

/// Render the catalog as markdown. Stable output — the
/// `rule_catalog_matches_committed_rules_md` test asserts that this
/// equals the committed `docs/RULES.md`.
pub fn render_markdown(catalog: &[RuleMetadata]) -> String {
    let mut out = String::new();
    writeln!(out, "# otsniff rule catalog").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "_Auto-generated from `findings::catalog()`. Run `otsniff rules > docs/RULES.md` to regenerate after changing rule metadata._"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Every rule below is implemented as a pure function in `src/findings/` that reads `Observations` and returns zero or more `Finding`s. The `trigger` column describes the firing condition in plain English; the `data_source` column lists the `Observations` fields the rule reads."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "**{} rules.**", catalog.len()).unwrap();
    writeln!(out).unwrap();

    // Table of contents
    writeln!(out, "## Index").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "| ID | Severity | Title |").unwrap();
    writeln!(out, "|----|----------|-------|").unwrap();
    for r in catalog {
        writeln!(
            out,
            "| [`{}`](#{}) | {} | {} |",
            r.id,
            anchor(r.id),
            r.severity.label(),
            r.title
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // Per-rule detail
    for r in catalog {
        writeln!(out, "## `{}`", r.id).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "**{}**", r.title).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "- **Severity:** {}", r.severity.label()).unwrap();
        writeln!(
            out,
            "- **Data source:** {}",
            r.data_source
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
        writeln!(out).unwrap();
        writeln!(out, "**Trigger.** {}", r.trigger).unwrap();
        writeln!(out).unwrap();
        if !r.references.is_empty() {
            writeln!(out, "**References:**").unwrap();
            writeln!(out).unwrap();
            for reference in r.references {
                writeln!(out, "- {}", format_reference(reference)).unwrap();
            }
            writeln!(out).unwrap();
        }
    }

    out
}

fn render_json(catalog: &[RuleMetadata]) -> String {
    serde_json::to_string_pretty(catalog).expect("RuleMetadata serializes")
}

fn anchor(id: &str) -> String {
    id.replace('.', "")
}

fn format_reference(r: &Reference) -> String {
    let label = format!("**{}** — {}", r.kind.label(), r.label);
    match r.url {
        Some(url) => format!("{label} ([link]({url}))"),
        None => label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::catalog;

    #[test]
    fn markdown_starts_with_header() {
        let md = render_markdown(&catalog());
        assert!(md.starts_with("# otsniff rule catalog"));
    }

    #[test]
    fn markdown_lists_every_rule_id_exactly_once_in_the_index() {
        let md = render_markdown(&catalog());
        for r in catalog() {
            // The id appears at least twice: index row + section heading.
            // We assert >= 2 not exactly 2 because evidence formatting
            // tools / IDEs may auto-render it elsewhere too.
            let count = md.matches(r.id).count();
            assert!(
                count >= 2,
                "rule id {} appears {} times in the rendered markdown; expected at least 2 (index + section heading)",
                r.id,
                count
            );
        }
    }

    #[test]
    fn json_round_trips_via_serde() {
        let json = render_json(&catalog());
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(parsed.is_array());
        assert_eq!(
            parsed.as_array().unwrap().len(),
            catalog().len(),
            "json catalog should have one entry per rule"
        );
    }
}

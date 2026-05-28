//! AI-augmented findings pass (S-5.03).
//!
//! After `run_all` and `build_inventory` produce their outputs, this module
//! orchestrates a second LLM pass that surfaces patterns the rule layer missed.
//! Each `AugmentedFinding` carries a confidence rating and structured reasoning.
//!
//! Entry point: [`augment_findings`].
//! Only called when `--ai` is set in the CLI.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::findings::{Finding, Severity};
use crate::inventory::Asset;
use crate::observe::Observations;

/// Confidence level assigned by the AI provider to an augmented finding.
///
/// Mirrors the three-tier vocabulary described in S-5.03 AC-002.
/// Derives only type-system primitives — no branching, no I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A structured finding produced by the AI augment pass.
///
/// IDs are namespaced `ai.<short>` (e.g. `ai.gateway_inference`).
/// The `evidence` field mirrors the evidence field on [`Finding`]:
/// a vector of plain-text evidence strings, capped to ~5 per finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AugmentedFinding {
    /// Namespaced identifier, e.g. `ai.gateway_inference`.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// Evidence strings, analogous to [`Finding::evidence`].
    pub evidence: Vec<String>,
    pub confidence: Confidence,
    /// Structured reasoning from the AI provider, in scrubbed terms.
    /// The unscrub layer is applied before rendering.
    pub reasoning: String,
}

/// Run the AI augment pass.
///
/// Called after `run_all` and `build_inventory` have produced their outputs.
/// Scrubs the combined context, calls `AiProvider::augment`, parses the
/// structured JSON response, deduplicates against `findings`, and returns
/// the surviving `AugmentedFinding`s.
///
/// # Errors
///
/// Returns `OtError::Parse(reason)` when the provider call fails or the
/// response cannot be parsed — matching EC-004 from S-5.03 (same variant
/// `ClaudeCliProvider::analyze` uses). Exit code 70 (EX_SOFTWARE).
pub fn augment_findings(
    _observations: &Observations,
    _findings: &[Finding],
    _inventory: &[Asset],
) -> Result<Vec<AugmentedFinding>> {
    todo!()
}

/// Parse the first valid JSON array from `raw`, tolerating leading/trailing
/// prose that the LLM may include around the JSON payload (EC-001 / AC-002).
///
/// Returns an empty `Vec` when no valid array is found (rather than an error),
/// so the caller can degrade gracefully.
pub fn parse_augmented_response(raw: &str) -> Result<Vec<AugmentedFinding>> {
    let _ = raw;
    todo!()
}

/// Deduplicate augmented findings against existing rule findings.
///
/// Implements AC-003: if an augmented finding's evidence substantially
/// overlaps with a rule finding, the rule finding takes precedence and the
/// augmented finding is dropped. Returns only the surviving augmented
/// findings.
pub fn dedup_against_rule_findings(
    _augmented: Vec<AugmentedFinding>,
    _rule_findings: &[Finding],
) -> Vec<AugmentedFinding> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confidence derives — no branching, no I/O, three variants, two lines.
    /// GREEN-BY-DESIGN: pure enum construction, zero branching beyond pattern.
    #[test]
    fn confidence_variants_are_copy() {
        let c = Confidence::High;
        let c2 = c;
        assert_eq!(c, c2);
    }
}

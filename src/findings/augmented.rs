//! AI-augmented findings pass (S-5.03).
//!
//! After `run_all` and `build_inventory` produce their outputs, this module
//! orchestrates a second LLM pass that surfaces patterns the rule layer missed.
//! Each `AugmentedFinding` carries a confidence rating and structured reasoning.
//!
//! Entry point: [`augment_findings`].
//! Only called when `--ai` is set in the CLI.

use serde::{Deserialize, Serialize};

use crate::ai::prompts::AUGMENT_PROMPT;
use crate::ai::AiProvider;
use crate::audit::AugmentInvocationSummary;
use crate::error::{OtError, Result};
use crate::findings::{Finding, Severity};
use crate::inventory::Asset;
use crate::observe::Observations;
use crate::report_md::render_markdown;
use crate::scrub::{build_map, scrub_text, unscrub_text};

/// Cap on the number of augmented findings returned after confidence-based
/// sort. Matches EC-002 / the test assertion in `augment_caps_findings_at_top_25`.
const AUGMENT_CAP: usize = 25;

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
/// the surviving `AugmentedFinding`s together with an invocation summary
/// for the audit log (AC-006).
///
/// The `provider` parameter accepts any `AiProvider` implementation —
/// production callers pass `&ClaudeCliProvider`, test callers pass a mock.
///
/// # Errors
///
/// Returns `OtError::Parse(reason)` when the provider call fails or the
/// response cannot be parsed — matching EC-004 from S-5.03 (same variant
/// `ClaudeCliProvider::analyze` uses). Exit code 70 (EX_SOFTWARE).
pub fn augment_findings(
    observations: &Observations,
    findings: &[Finding],
    inventory: &[Asset],
    provider: &dyn AiProvider,
) -> Result<(Vec<AugmentedFinding>, AugmentInvocationSummary)> {
    use crate::cli::AI_INPUT_LABEL;

    // 1. Render a scrub-safe markdown representation of the combined context.
    let raw_md = render_markdown(
        inventory,
        findings,
        observations,
        AI_INPUT_LABEL,
        chrono::Utc::now(),
        None,
    )
    .map_err(|e| OtError::Parse(format!("augment_findings: render failed: {e}")))?;

    // 2. Build the scrub map and scrub the markdown.
    let map = build_map(observations);
    let scrubbed_md = scrub_text(&raw_md, &map);

    // 3. Fail-closed leak check on the scrubbed markdown only — the user
    //    message is the scrubbed_md; AUGMENT_PROMPT is the system prompt,
    //    passed separately to the provider. Running the check once on the
    //    bytes that actually travel over the wire (the user message = the
    //    scrubbed context) is sufficient and avoids double-checking content
    //    that contains no identifiers (the prompt itself is a constant with
    //    no real-looking values, enforced by its own snapshot test).
    crate::ai::leak_detector::ensure_clean(&scrubbed_md)?;
    crate::ai::leak_detector::ensure_no_map_values(&scrubbed_md, &map)?;

    // 4. Compose the user message. AUGMENT_PROMPT is the *system* prompt
    //    (passed as the first argument to provider.augment); the user message
    //    is just the scrubbed context. We do NOT duplicate AUGMENT_PROMPT in
    //    the user message — that was a MEDIUM finding (redundant double prompt).
    let user_message = scrubbed_md.clone();

    // 5. Invoke the provider. Any provider error propagates as OtError::Parse
    //    (EC-004). Exit code 70 (EX_SOFTWARE) — same as the analyze path.
    let invoke_start = std::time::Instant::now();
    let raw_response = provider.augment(AUGMENT_PROMPT, &user_message)?;
    let elapsed = invoke_start.elapsed();

    // 6. Parse the JSON response. Malformed input → Ok(vec![]) (EC-001).
    let mut augmented = parse_augmented_response(&raw_response)?;
    let raw_finding_count = augmented.len();

    // 7. EC-003 (CRITICAL fix): check for hallucinated pseudonyms BEFORE
    //    unscrub. After unscrub, host_NNN/name_NNN tokens have been replaced
    //    with real values, so the filter cannot fire on legitimate findings.
    //
    //    The valid pseudonyms are all keys in the scrub map across all families:
    //    ip pseudonyms (host_NNN), mac pseudonyms (mac_NNN), and hostname
    //    pseudonyms (name_NNN). A pseudonym-shaped token in the AI response
    //    that does not appear in the map was never assigned to any observed
    //    identifier — it is hallucinated.
    //
    //    We check evidence, reasoning, AND title to catch hallucinations
    //    anywhere in the finding (CRITICAL fix: original only checked evidence).
    //
    //    When a finding has NO pseudonym-shaped tokens at all, there is nothing
    //    to validate → keep.

    // Collect all known pseudonyms across all scrub map families.
    let known_pseudonyms: std::collections::HashSet<&str> = map
        .ips
        .keys()
        .chain(map.macs.keys())
        .chain(map.names.keys())
        .map(|s| s.as_str())
        .collect();

    augmented.retain(|af| {
        // Gather all pseudonym-shaped tokens from evidence, reasoning, AND title.
        let mut refs: Vec<&str> = Vec::new();
        for ev in &af.evidence {
            refs.extend(ev.split_whitespace().filter(|t| is_otsniff_pseudonym(t)));
        }
        refs.extend(
            af.reasoning
                .split_whitespace()
                .filter(|t| is_otsniff_pseudonym(t)),
        );
        refs.extend(
            af.title
                .split_whitespace()
                .filter(|t| is_otsniff_pseudonym(t)),
        );

        if refs.is_empty() {
            // No pseudonym references — nothing to validate → keep.
            return true;
        }

        // All referenced pseudonyms must appear in the scrub map.
        refs.iter().all(|p| known_pseudonyms.contains(p))
        // Silently drop hallucinated findings — no eprintln here.
        // Callers that need diagnostics can compare raw vs surviving counts
        // via the AugmentInvocationSummary.
    });

    // 8. Cap at top-AUGMENT_CAP by confidence (High > Medium > Low) — EC-002.
    //
    // Stable sort by (confidence_rank, id) for full determinism, then
    // truncate to AUGMENT_CAP. This is the correct "top-N" semantics:
    // every Low finding survives when total count <= AUGMENT_CAP regardless
    // of whether High/Medium findings also exist (fixes HIGH finding: the
    // old branchy logic dropped all Low items whenever any H/M existed,
    // even below the cap).
    augmented.sort_by(|a, b| {
        let rank_a = confidence_rank(a.confidence);
        let rank_b = confidence_rank(b.confidence);
        rank_a.cmp(&rank_b).then_with(|| a.id.cmp(&b.id))
    });
    if augmented.len() > AUGMENT_CAP {
        augmented.truncate(AUGMENT_CAP);
    }

    // 9. Dedup against rule findings (AC-003).
    //
    // Both the augmented findings (still in scrubbed pseudonym form) and the
    // rule findings (in real-value form) need a common vocabulary for the host-
    // pseudonym comparison. We scrub the rule findings' evidence strings with
    // the same map so both sides speak pseudonyms at dedup time.
    let scrubbed_rule_findings: Vec<crate::findings::Finding> = findings
        .iter()
        .map(|f| crate::findings::Finding {
            id: f.id,
            severity: f.severity,
            title: f.title.clone(),
            summary: f.summary.clone(),
            evidence: f.evidence.iter().map(|ev| scrub_text(ev, &map)).collect(),
            recommendation: f.recommendation,
            playbook: f.playbook.clone(),
        })
        .collect();
    let augmented = dedup_against_rule_findings(augmented, &scrubbed_rule_findings);

    // 10. Unscrub evidence, reasoning, and title fields so the caller sees real
    //     values. Done AFTER EC-003 filter and dedup per CRITICAL fix #2.
    let mut augmented = augmented;
    for f in &mut augmented {
        for ev in &mut f.evidence {
            let (unscrubbed, _, _) = unscrub_text(ev, &map);
            *ev = unscrubbed;
        }
        let (unscrubbed_reason, _, _) = unscrub_text(&f.reasoning, &map);
        f.reasoning = unscrubbed_reason;
        let (unscrubbed_title, _, _) = unscrub_text(&f.title, &map);
        f.title = unscrubbed_title;
    }

    let surviving_finding_count = augmented.len();

    // 11. Build the invocation summary for AC-006 / audit log.
    let summary = AugmentInvocationSummary {
        system_prompt_bytes: AUGMENT_PROMPT.len(),
        system_prompt_sha256: crate::audit::sha256_hex(AUGMENT_PROMPT),
        user_message_bytes: user_message.len(),
        user_message_sha256: crate::audit::sha256_hex(&user_message),
        response_bytes: raw_response.len(),
        response_sha256: crate::audit::sha256_hex(&raw_response),
        elapsed_seconds: elapsed.as_secs_f64(),
        raw_finding_count,
        surviving_finding_count,
    };

    Ok((augmented, summary))
}

/// Confidence ranking for sorting: lower value = higher confidence.
/// High (0) < Medium (1) < Low (2).
fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

/// Parse the first valid JSON array from `raw` using a balanced-bracket scan,
/// tolerating leading/trailing prose that the LLM may include around the JSON
/// payload (EC-001 / AC-002).
///
/// Finds the first `[`, scans forward tracking bracket depth (respecting JSON
/// string quoting so a `]` inside a string value doesn't close the array), finds
/// the matching `]`, then attempts `serde_json::from_str` on that single slice.
/// No O(n²) scan; no boolean sentinel.
///
/// Returns an empty `Vec` when no valid array is found (rather than an error),
/// so the caller can degrade gracefully.
pub fn parse_augmented_response(raw: &str) -> Result<Vec<AugmentedFinding>> {
    let bytes = raw.as_bytes();
    let Some(start) = bytes.iter().position(|&b| b == b'[') else {
        return Ok(vec![]);
    };

    // Balanced-bracket scan from `start`. Track depth and whether we are
    // inside a JSON string (to skip `[`/`]` that appear inside string values).
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut end: Option<usize> = None;

    for (i, &b) in bytes[start..].iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match b {
            b'\\' if in_string => {
                escape_next = true;
            }
            b'"' => {
                in_string = !in_string;
            }
            b'[' if !in_string => {
                depth += 1;
            }
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + i);
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(end_pos) = end else {
        // No matching `]` found — unbalanced or truncated JSON.
        return Ok(vec![]);
    };

    let slice = &raw[start..=end_pos];
    match serde_json::from_str::<Vec<AugmentedFinding>>(slice) {
        Ok(findings) => Ok(findings),
        Err(_) => Ok(vec![]),
    }
}

/// Deduplicate augmented findings against existing rule findings (AC-003).
///
/// Drops an augmented finding when the *pseudonym set* of its evidence
/// is a subset of (or equal to) the pseudonym set of any rule finding.
/// "Pseudonym" here means any `host_NNN`, `mac_NNN`, or `name_NNN` token
/// that `scrub_text` assigns to observed network identifiers.
///
/// This replaces the old whitespace-token-set overlap which was too aggressive:
/// common words like "Modbus", "port", or vendor names in rule evidence were
/// silently deleting disjoint augmented findings.
///
/// An augmented finding with NO pseudonyms in its evidence is kept
/// unconditionally (conservative baseline — no identity to overlap on).
///
/// Both `augmented` and `rule_findings` must be in the SAME vocabulary
/// (scrubbed pseudonyms or real values) for comparison to work.
pub fn dedup_against_rule_findings(
    augmented: Vec<AugmentedFinding>,
    rule_findings: &[Finding],
) -> Vec<AugmentedFinding> {
    // Build one pseudonym set per rule finding.
    let rule_pseudo_sets: Vec<std::collections::HashSet<String>> = rule_findings
        .iter()
        .map(|rule| {
            rule.evidence
                .iter()
                .flat_map(|ev| ev.split_whitespace())
                .filter(|t| is_otsniff_pseudonym(t))
                .map(String::from)
                .collect()
        })
        .collect();

    augmented
        .into_iter()
        .filter(|af| {
            // Collect pseudonyms from the augmented finding's evidence.
            let af_pseudos: std::collections::HashSet<String> = af
                .evidence
                .iter()
                .flat_map(|ev| ev.split_whitespace())
                .filter(|t| is_otsniff_pseudonym(t))
                .map(String::from)
                .collect();

            if af_pseudos.is_empty() {
                // No pseudonyms to compare — keep (conservative baseline).
                return true;
            }

            // Drop the augmented finding if its pseudonym set is a subset of
            // (or equal to) any single rule finding's pseudonym set.
            let overlaps_rule = rule_pseudo_sets
                .iter()
                .any(|rule_pseudos| !rule_pseudos.is_empty() && af_pseudos.is_subset(rule_pseudos));

            !overlaps_rule
        })
        .collect()
}

/// True if `token` looks like an otsniff-assigned pseudonym:
/// - `host_NNN` (IP address pseudonym)
/// - `mac_NNN` (MAC address pseudonym)
/// - `name_NNN` (hostname pseudonym)
///
/// All pseudonyms use the pattern `<prefix>_<digits>` where digits are
/// zero-padded to 3 places (e.g. `host_001`, `mac_042`, `name_007`).
fn is_otsniff_pseudonym(token: &str) -> bool {
    for prefix in ["host_", "mac_", "name_"] {
        if let Some(rest) = token.strip_prefix(prefix) {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// A minimal valid JSON array of two augmented findings, as the AI
    /// provider would return — all values use scrubbed pseudonyms.
    fn two_finding_response() -> &'static str {
        r#"[
  {
    "id": "ai.gateway_inference",
    "severity": "High",
    "title": "Inferred gateway role mismatch",
    "evidence": ["host_001 acted as default gateway but is not inventoried as a router"],
    "confidence": "High",
    "reasoning": "host_001 appears as the L3 hop for all OT egress; vendor OUI is an HMI vendor."
  },
  {
    "id": "ai.role_misclass",
    "severity": "Medium",
    "title": "Possible role misclassification",
    "evidence": ["host_002 sends engineering-class commands but is inventoried as a workstation"],
    "confidence": "Medium",
    "reasoning": "host_002 generates Write-Single-Coil and Direct-Operate commands, which are engineering-class."
  }
]"#
    }

    fn minimal_rule_finding(id: &'static str, evidence: Vec<String>) -> Finding {
        Finding {
            id,
            severity: Severity::High,
            title: format!("Test finding {id}"),
            summary: "test".to_string(),
            evidence,
            recommendation: "investigate",
            playbook: vec!["step 1".to_string()],
        }
    }

    // ── BC-6.05.002 — Response shape ─────────────────────────────────────────

    // BC-6.05.002 — parser returns Vec<AugmentedFinding> of length 2 with
    // correct id/severity/confidence from a well-formed JSON array.
    #[test]
    fn augment_parses_well_formed_json_array() {
        let result = parse_augmented_response(two_finding_response());
        let findings = result.expect("parse_augmented_response must succeed on valid JSON");
        assert_eq!(
            findings.len(),
            2,
            "BC-6.05.002: parser must return exactly 2 findings from the two-element fixture"
        );
        assert_eq!(findings[0].id, "ai.gateway_inference");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[1].id, "ai.role_misclass");
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[1].confidence, Confidence::Medium);
    }

    // BC-6.05.002 — every returned id must start with "ai." per the namespace
    // contract.
    #[test]
    fn augment_id_namespace_prefix() {
        let findings = parse_augmented_response(two_finding_response())
            .expect("parse must succeed on valid JSON");
        for f in &findings {
            assert!(
                f.id.starts_with("ai."),
                "BC-6.05.002: augmented finding id '{}' must be namespaced 'ai.<short>'",
                f.id
            );
        }
    }

    // BC-6.05.002 — parser must extract the JSON array even when the model
    // wraps it in prose before and/or after.
    #[test]
    fn augment_tolerates_preamble_and_postamble() {
        let raw = format!(
            "Sure, here you go:\n{}\nLet me know if you need more detail.",
            two_finding_response()
        );
        let findings =
            parse_augmented_response(&raw).expect("parser must tolerate prose preamble/postamble");
        assert_eq!(
            findings.len(),
            2,
            "BC-6.05.002: parser must extract both findings even with prose preamble/postamble"
        );
    }

    // ── BC-6.05.003 — Dedup against rule findings ────────────────────────────

    // BC-6.05.003 — when an augmented finding's evidence overlaps with a rule
    // finding on the SAME HOST PSEUDONYM, the rule finding takes precedence and
    // the augmented finding is dropped.
    #[test]
    fn dedup_drops_overlapping_augmented() {
        // Rule finding covers host_001; augmented finding also references host_001.
        let rule = minimal_rule_finding(
            "ics.engineering_commands",
            vec!["host_001 sent Write-Single-Coil".to_string()],
        );
        let augmented = AugmentedFinding {
            id: "ai.gateway_inference".to_string(),
            severity: Severity::High,
            title: "Inferred gateway role".to_string(),
            evidence: vec!["host_001 acted as default gateway".to_string()],
            confidence: Confidence::High,
            reasoning: "host_001 appears as the L3 hop".to_string(),
        };
        let result = dedup_against_rule_findings(vec![augmented], &[rule]);
        // Either dropped entirely or merged as a note — either way the
        // augmented finding with an overlapping id must NOT appear as an
        // independent AugmentedFinding in the output.
        let standalone_ai = result.iter().find(|f| f.id == "ai.gateway_inference");
        assert!(
            standalone_ai.is_none(),
            "BC-6.05.003: augmented finding whose evidence overlaps a rule finding \
             must be dropped; found it in output: {:?}",
            standalone_ai
        );
    }

    // BC-6.05.003 — a disjoint augmented finding (different host) must survive
    // dedup.
    #[test]
    fn dedup_preserves_disjoint_augmented() {
        let rule = minimal_rule_finding(
            "ics.engineering_commands",
            vec!["host_001 sent Write-Single-Coil".to_string()],
        );
        let augmented = AugmentedFinding {
            id: "ai.role_misclass".to_string(),
            severity: Severity::Medium,
            title: "Role misclassification".to_string(),
            evidence: vec!["host_002 sends engineering commands".to_string()],
            confidence: Confidence::Medium,
            reasoning: "host_002 is inventoried as a workstation".to_string(),
        };
        let result = dedup_against_rule_findings(vec![augmented], &[rule]);
        assert_eq!(
            result.len(),
            1,
            "BC-6.05.003: augmented finding with disjoint evidence must survive dedup"
        );
        assert_eq!(result[0].id, "ai.role_misclass");
    }

    // HIGH finding fix: an augmented finding that shares only a non-pseudonym
    // word (e.g. "Modbus") with rule evidence must survive dedup. The old
    // token-set overlap would have dropped it.
    #[test]
    fn dedup_preserves_finding_sharing_only_common_words() {
        // Rule finding mentions "Modbus" but host_001; augmented finding
        // mentions "Modbus" but references host_002 only.
        let rule = minimal_rule_finding(
            "ics.engineering_commands",
            vec!["host_001 sent Modbus Write-Single-Coil".to_string()],
        );
        let augmented = AugmentedFinding {
            id: "ai.modbus_anomaly".to_string(),
            severity: Severity::Medium,
            title: "Modbus anomaly on different host".to_string(),
            evidence: vec!["host_002 sent unusual Modbus traffic".to_string()],
            confidence: Confidence::Medium,
            reasoning: "host_002 sent Modbus frames to an unexpected dest".to_string(),
        };
        let result = dedup_against_rule_findings(vec![augmented], &[rule]);
        assert_eq!(
            result.len(),
            1,
            "HIGH: augmented finding that shares only 'Modbus' (not a pseudonym) with a rule \
             finding must survive dedup; got: {:?}",
            result
        );
    }

    // ── EC-001 — Malformed JSON falls back to empty vec ───────────────────────

    // EC-001 — when the provider returns unparseable JSON, the parser returns
    // Ok(vec![]) rather than an error, allowing the report to render without
    // the augment section.
    #[test]
    fn augment_returns_empty_on_malformed_json() {
        let result = parse_augmented_response("not json at all");
        let findings = result.expect("EC-001: malformed JSON must return Ok(vec![]) not Err");
        assert!(
            findings.is_empty(),
            "EC-001: malformed JSON must produce an empty vec, not findings; got: {findings:?}"
        );
    }

    // ── EC-002 — Cap at top-N by confidence ──────────────────────────────────

    // EC-002 / BC-6.05.002 — parse_augmented_response preserves the full set
    // of findings in confidence-sortable form.  The fixture uses 15 High +
    // 10 Medium + 5 Low = 30 items, ensuring the top-25 by confidence-rank
    // are entirely High or Medium (15 + 10 = 25 exactly).  This exercises
    // the parser's shape-preservation contract, not the orchestration cap —
    // the integration test `augment_caps_findings_at_top_25_by_confidence`
    // in `tests/snapshot.rs` pins the cap-25 behaviour at the
    // `augment_findings` level.
    #[test]
    fn augment_caps_at_top_n_by_confidence() {
        // Build 30 findings: 5 Low, 10 Medium, 15 High (order: Low first).
        // 15 High + 10 Medium = 25 items ≥ cap; top-25 sorted by confidence
        // are therefore all High or Medium — no Low item reaches the top-25.
        let mut raw: Vec<AugmentedFinding> = Vec::new();
        for i in 0..5 {
            raw.push(AugmentedFinding {
                id: format!("ai.low_{i}"),
                severity: Severity::Info,
                title: format!("Low confidence {i}"),
                evidence: vec![],
                confidence: Confidence::Low,
                reasoning: String::new(),
            });
        }
        for i in 0..10 {
            raw.push(AugmentedFinding {
                id: format!("ai.medium_{i}"),
                severity: Severity::Medium,
                title: format!("Medium confidence {i}"),
                evidence: vec![],
                confidence: Confidence::Medium,
                reasoning: String::new(),
            });
        }
        for i in 0..15 {
            raw.push(AugmentedFinding {
                id: format!("ai.high_{i}"),
                severity: Severity::High,
                title: format!("High confidence {i}"),
                evidence: vec![],
                confidence: Confidence::High,
                reasoning: String::new(),
            });
        }
        // 30 total — above the cap of 25, with 25 High+Medium items.
        assert_eq!(raw.len(), 30);

        let response_30 = {
            let mut items: Vec<String> = Vec::new();
            for f in &raw {
                let conf = match f.confidence {
                    Confidence::High => "High",
                    Confidence::Medium => "Medium",
                    Confidence::Low => "Low",
                };
                items.push(format!(
                    r#"{{"id":"{}", "severity":"Info", "title":"{}", "evidence":[], "confidence":"{}", "reasoning":""}}"#,
                    f.id, f.title, conf
                ));
            }
            format!("[{}]", items.join(","))
        };

        let findings = parse_augmented_response(&response_30)
            .expect("EC-002: 30-finding response must parse without error");
        // BC-6.05.002 (parser contract): parse_augmented_response returns all
        // findings without truncation; capping is an augment_findings concern.
        assert_eq!(
            findings.len(),
            30,
            "BC-6.05.002 (parser): parse_augmented_response must return all 30 findings; \
             cap is applied by augment_findings downstream"
        );
        // Verify confidence ordering: the top-25 items from a confidence-sorted
        // slice must be entirely High or Medium.  With 15H + 10M + 5L, the
        // sorted order is [15H, 10M, 5L]; positions 1-25 are all H or M.
        let mut sorted = findings.clone();
        sorted.sort_by(|a, b| {
            let rank = |c: Confidence| match c {
                Confidence::High => 0u8,
                Confidence::Medium => 1,
                Confidence::Low => 2,
            };
            rank(a.confidence).cmp(&rank(b.confidence))
        });
        let top_25: Vec<_> = sorted.iter().take(25).collect();
        let all_high_or_medium = top_25
            .iter()
            .all(|f| f.confidence == Confidence::High || f.confidence == Confidence::Medium);
        assert!(
            all_high_or_medium,
            "EC-002: top-25 by confidence must be High or Medium, not Low; \
             fixture has 15H + 10M = 25 H/M items so no Low item should appear \
             in the top-25 slice"
        );
    }

    // HIGH finding fix: below-cap inputs preserve ALL findings including Low.
    // With 5H+5M+5L (15 total < 25 cap), all 15 must be returned.
    #[test]
    fn cap_preserves_all_findings_when_below_cap() {
        let mut items: Vec<String> = Vec::new();
        for i in 0..5u32 {
            items.push(format!(
                r#"{{"id":"ai.low_{i}","severity":"Info","title":"Low {i}","evidence":[],"confidence":"Low","reasoning":""}}"#
            ));
        }
        for i in 0..5u32 {
            items.push(format!(
                r#"{{"id":"ai.med_{i}","severity":"Medium","title":"Med {i}","evidence":[],"confidence":"Medium","reasoning":""}}"#
            ));
        }
        for i in 0..5u32 {
            items.push(format!(
                r#"{{"id":"ai.high_{i}","severity":"High","title":"High {i}","evidence":[],"confidence":"High","reasoning":""}}"#
            ));
        }
        let response = format!("[{}]", items.join(","));
        let parsed = parse_augmented_response(&response).expect("must parse 15-finding response");
        // Simulate the augment_findings cap logic on the parsed results
        // (without a full pipeline): stable sort + truncate to AUGMENT_CAP.
        let mut sorted = parsed;
        sorted.sort_by(|a, b| {
            confidence_rank(a.confidence)
                .cmp(&confidence_rank(b.confidence))
                .then_with(|| a.id.cmp(&b.id))
        });
        if sorted.len() > AUGMENT_CAP {
            sorted.truncate(AUGMENT_CAP);
        }
        assert_eq!(
            sorted.len(),
            15,
            "HIGH cap fix: 5H+5M+5L (15 total, below cap of {AUGMENT_CAP}) must all be returned"
        );
    }

    // HIGH finding fix: 30H input truncates to exactly 25.
    #[test]
    fn cap_truncates_to_25_when_above_cap() {
        let items: Vec<String> = (0..30u32)
            .map(|i| {
                format!(
                    r#"{{"id":"ai.high_{i}","severity":"High","title":"High {i}","evidence":[],"confidence":"High","reasoning":""}}"#
                )
            })
            .collect();
        let response = format!("[{}]", items.join(","));
        let parsed = parse_augmented_response(&response).expect("must parse 30-finding response");
        let mut sorted = parsed;
        sorted.sort_by(|a, b| {
            confidence_rank(a.confidence)
                .cmp(&confidence_rank(b.confidence))
                .then_with(|| a.id.cmp(&b.id))
        });
        if sorted.len() > AUGMENT_CAP {
            sorted.truncate(AUGMENT_CAP);
        }
        assert_eq!(
            sorted.len(),
            AUGMENT_CAP,
            "HIGH cap fix: 30H input must be truncated to {AUGMENT_CAP}"
        );
    }

    // ── EC-003 — Unknown host dropped ────────────────────────────────────────

    // EC-003 — an augmented finding whose evidence references a host not in
    // the inventory must be dropped.
    //
    // This is enforced inside augment_findings (not parse_augmented_response).
    // The unit test verifies the dedup step's interaction: since the inventory
    // check is part of the full pipeline, we note that dedup_against_rule_findings
    // alone cannot test this (it has no inventory param). The snapshot.rs
    // integration test covers the full path (EC-003 there).
    //
    // Here we assert that a finding with no evidence (empty evidence vec) survives
    // dedup — which is the conservative baseline. The unknown-host check is
    // an ADDITIONAL filter applied inside augment_findings.
    #[test]
    fn dedup_preserves_finding_with_empty_evidence() {
        // This is a structural baseline — dedup alone doesn't know about inventory.
        let augmented = AugmentedFinding {
            id: "ai.unknown_host_ref".to_string(),
            severity: Severity::Info,
            title: "References unknown host".to_string(),
            evidence: vec![],
            confidence: Confidence::Low,
            reasoning: "host_999 was observed doing suspicious things".to_string(),
        };
        let result = dedup_against_rule_findings(vec![augmented], &[]);
        // dedup with no rule findings and empty evidence cannot overlap — so it
        // must survive. The unknown-host filter is in augment_findings.
        assert_eq!(
            result.len(),
            1,
            "EC-003 (dedup baseline): finding with empty evidence and no rule conflicts survives dedup"
        );
    }
}

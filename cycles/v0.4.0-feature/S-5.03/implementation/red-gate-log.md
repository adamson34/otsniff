---
document_type: red-gate-log
level: ops
version: "1.0"
status: complete
producer: test-writer
timestamp: 2026-05-28T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-5.03-ai-augmented-findings.md
  - src/findings/augmented.rs (stub, commit 2193dfa)
  - src/findings/mod.rs (stub, commit 2193dfa)
  - src/ai/mod.rs (AiProvider::augment, stub, commit 2193dfa)
  - src/ai/claude_cli.rs (ClaudeCliProvider::augment, stub, commit 2193dfa)
  - src/ai/prompts.rs (AUGMENT_PROMPT placeholder, stub, commit 2193dfa)
  - src/report.rs (render_augmented_section, stub, commit 2193dfa)
  - src/report_md.rs (render_augmented_section_md, stub, commit 2193dfa)
  - src/audit.rs (AuditLog.augment_pass, stub, commit 2193dfa)
  - tests/snapshot.rs (mock provider + 15 failing tests, commit ee52590)
traces_to: BC-6.05.001, BC-6.05.002, BC-6.05.003, BC-3.07.001
stub_architect_agent: "[af300e66087d78e75]"
stub_compile_verified: true
test_writer_agent: "[aaadc3705f33b5983]"
red_gate_verified: true
---

# Red Gate Log: S-5.03 — AI-augmented findings

## Summary

| Story | Tests Written | All Fail (Red)? | Gate |
|-------|--------------|-----------------|------|
| S-5.03 | 23 (8 lib + 15 integration) | YES | PASSED (correctly red) |

## Stubs Created (commit 2193dfa)

- `src/findings/augmented.rs` — new module:
  - `pub struct AugmentedFinding { id, severity, title, evidence, confidence, reasoning }`
  - `pub enum Confidence { High, Medium, Low }`
  - `pub fn augment_findings(observations, findings, inventory, provider) -> Result<Vec<AugmentedFinding>, OtError>` — `todo!()`
  - `pub fn parse_augmented_response(raw: &str) -> Result<Vec<AugmentedFinding>, OtError>` — `todo!()`
  - `pub fn dedup_against_rule_findings(augmented, rule_findings) -> Vec<AugmentedFinding>` — `todo!()`
- `src/ai/mod.rs` — `AiProvider::augment` trait method added (mirrors `analyze` shape)
- `src/ai/claude_cli.rs` — `ClaudeCliProvider::augment` — `todo!()`
- `src/ai/prompts.rs` — `pub const AUGMENT_PROMPT: &str = "TODO";` placeholder
- `src/report.rs` — `pub fn render_augmented_section(...)` — `todo!()` with `#[allow(dead_code)]`
- `src/report_md.rs` — `pub fn render_augmented_section_md(...)` — `todo!()` with `#[allow(dead_code)]`
- `src/audit.rs` — `AuditLog.augment_pass: Option<...>` field added; threaded through `src/cli.rs`, `src/audit.rs` unit test, `tests/snapshot.rs` (all three call sites carry `augment_pass: None` until the implementer wires the real pass)

## Green-by-Design Status

NONE. The augment pass is NOT wired into the production `--ai` flow yet — it's an additive module. No pre-existing test triggers a `todo!()` stub on its current path. All 271 pre-existing tests pass.

## Red Gate Verification (commit ee52590)

### S-5.03: Parser / dedup unit tests (`src/findings/augmented.rs` `#[cfg(test)]`)

- AC-002 (BC-6.05.002): `augment_parses_well_formed_json_array` — FAIL via `todo!()` at `src/findings/augmented.rs:79` (`parse_augmented_response`)
- AC-002 (BC-6.05.002): `augment_id_namespace_prefix` — FAIL via `todo!()` at `src/findings/augmented.rs:79`
- AC-002 (BC-6.05.002): `augment_tolerates_preamble_and_postamble` — FAIL via `todo!()` at `src/findings/augmented.rs:79`
- AC-003 (BC-6.05.003): `dedup_drops_overlapping_augmented` — FAIL via `todo!()` at `src/findings/augmented.rs:92` (`dedup_against_rule_findings`)
- AC-003 (BC-6.05.003): `dedup_preserves_disjoint_augmented` — FAIL via `todo!()` at `src/findings/augmented.rs:92`
- AC-003 (BC-6.05.003) baseline: `dedup_preserves_finding_with_empty_evidence` — FAIL via `todo!()` at `src/findings/augmented.rs:92`
- EC-001: `augment_returns_empty_on_malformed_json` — FAIL via `todo!()` at `src/findings/augmented.rs:79`
- EC-002 (unit portion): `augment_caps_at_top_n_by_confidence` — FAIL via `todo!()` at `src/findings/augmented.rs:79`

### S-5.03: Integration tests (`tests/snapshot.rs`)

- AC-001 (BC-6.05.001): `augment_request_invokes_provider_with_scrubbed_payload` — FAIL via `todo!()` in `augment_findings`
- AC-002 (BC-6.05.002): `augment_mock_returns_known_response_assert_shape` — FAIL via `todo!()` in `augment_findings`
- AC-003 (BC-6.05.003): `augment_dedup_rule_finding_takes_precedence` — FAIL via `todo!()` in `augment_findings`
- AC-003 (BC-6.05.003): `augment_dedup_disjoint_finding_survives` — FAIL via `todo!()` in `augment_findings`
- AC-004 (BC-3.07.001): `html_report_contains_augmented_section_when_present` — FAIL via `todo!()` in `render_augmented_section`
- AC-004 (BC-3.07.001): `html_report_omits_augmented_section_when_empty` — FAIL via `todo!()` in `render_augmented_section`
- AC-004 (BC-3.07.001): `markdown_report_contains_augmented_section_when_present` — FAIL via `todo!()` in `render_augmented_section_md`
- AC-004 (BC-3.07.001): `augmented_findings_html_section_snapshot` — FAIL via `todo!()` (insta snapshot, accept on first green via `cargo insta review`)
- AC-004 (BC-3.07.001): `augmented_findings_markdown_section_snapshot` — FAIL via `todo!()` (insta snapshot, accept on first green via `cargo insta review`)
- AC-005 (privacy invariant): `invariant_no_real_values_reach_ai_provider_augment` — FAIL via `todo!()` in `augment_findings`. Canary injected: host `172.31.200.99` + hostname `CANARY-HOST-AUGMENT-DO-NOT-LEAK`.
- AC-006: `audit_log_records_augment_pass_hashes_separately` — FAIL via `todo!()` in `augment_findings`
- EC-001: `augment_returns_empty_vec_on_malformed_json_from_provider` — FAIL via `todo!()` in `augment_findings`
- EC-002: `augment_caps_findings_at_top_25_by_confidence` — FAIL via `todo!()` in `augment_findings`. **Cap = 25** picked by test-writer; implementer may revise but must update assertion.
- EC-003: `augment_drops_finding_referencing_unknown_host` — FAIL via `todo!()` in `augment_findings`
- EC-004: `augment_failure_after_analyze_success_renders_without_augment` — FAIL via `todo!()` in `augment_findings`

## Regression Check

| Existing Tests | Status |
|---------------|--------|
| 212 lib unit tests (pre-S-5.03) | all pass |
| 59 integration tests (snapshot + cli_smoke + ldap_creds + memory_bound, pre-S-5.03) | all pass |

**All 271 pre-existing tests pass.** Zero build errors. Zero clippy warnings.

## Hand-Off to Implementer

- Story ready for implementation: S-5.03
- Implementation order (suggested — each step unblocks a chunk of failing tests):
  1. `parse_augmented_response` — handles well-formed JSON, preamble/postamble tolerance, and malformed-input fallback to `Ok(vec![])`. Unblocks 4 unit tests + 2 integration tests.
  2. `dedup_against_rule_findings` — overlap = augmented evidence ⊆ rule evidence (or substantial intersection — implementer chooses). Drop the augmented finding when overlap. Unblocks 3 unit tests + 2 integration tests.
  3. `augment_findings` orchestration — scrub → call `provider.augment` → unscrub → parse → dedup → cap@25 (or chosen N) → inventory-host filter. Unblocks 9 integration tests including privacy + audit + EC-002/003/004.
  4. `ClaudeCliProvider::augment` — mirror `analyze` shell-out shape with the augment prompt.
  5. `AUGMENT_PROMPT` constant — committed real prompt; add a snapshot test analogous to `system_prompt_snapshot`.
  6. `render_augmented_section` (HTML) + `render_augmented_section_md` (markdown). Unblocks 4 integration tests + 2 snapshot tests (accept via `cargo insta review`).
  7. Wire `augment_findings` into `cli.rs` `--ai` path, populating `AuditLog.augment_pass`. The three `augment_pass: None` literals (cli.rs, audit.rs test, tests/snapshot.rs) become real.

- Implementer interpretation calls deferred from test-writer (already encoded in failing tests):
  - `augment_findings` signature: `(observations, findings, inventory, provider: &dyn AiProvider)` — locked in by tests.
  - EC-002 cap = 25 (top-by-confidence). Revise + update test assertion if changing.
  - AC-003 dedup strategy = DROP (not attach-as-note). Locked by test assertions.
  - AC-006 audit-log surface: either `&mut AuditLog` parameter or returning `(Vec<AugmentedFinding>, AugmentInvocationSummary)`. Tests accept either shape — pick what fits the call-site.

- Existing scrub → leak-detector → provider flow is the model for AC-001/AC-005. Reuse `MockAiProvider` defined above the S-5.03 test block in `tests/snapshot.rs` for any further coverage rather than introducing a parallel mock.

- New BCs (BC-6.05.001..003 + BC-3.07.001) are NOT yet registered in `.factory/specs/behavioral-contracts/BC-INDEX.md` — they will be appended at Step 9 (factory-artifacts commit), following the wave-2 pattern. The story's AC text is the authoritative contract definition for now.

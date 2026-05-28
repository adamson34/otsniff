# S-5.03 Evidence Report: AI-augmented findings

**Story ID:** S-5.03
**Branch:** feature/S-5.03-ai-augmented-findings
**Commit SHA:** (see git log after demo commit)
**Timestamp:** 2026-05-28

---

## Executive Summary

Story S-5.03 delivers the AI-augmented findings second pass for `otsniff analyze --ai`.
After `run_all_findings` and `build_inventory` produce their outputs, a new
`augment_findings()` function invokes the AI provider with a scrubbed context,
parses the structured JSON response, deduplicates against rule findings, and
renders a dedicated section in both HTML and markdown reports.

All six acceptance criteria are verified through **15 dedicated integration tests**
(100% pass rate on a 423-test suite) and **5 VHS recordings** covering success and
error paths.

**Mock provider substitution:** The `--ai` flag requires a live `claude` CLI and
a network-available LLM, which is not reproducible in a recording. All demos use
a `MockAiProvider` that implements the `AiProvider` trait and returns deterministic
canned responses. This is the standard test pattern for the project (see
`tests/snapshot.rs`) and covers the full pipeline — scrub, leak-check, parse, dedup,
render — without external dependencies.

---

## Acceptance Criteria Coverage

| AC | Title | Type | Evidence | Status |
|----|-------|------|----------|--------|
| AC-001 | Augment request — CLI surface + provider invocation | Demo + Test | `ac-001-augment-cli-invocation.gif` + `augment_request_invokes_provider_with_scrubbed_payload` | PASS |
| AC-002 | Response shape + preamble tolerance | Demo + Test | `ac-002-003-shape-and-dedup.gif` + `augment_mock_returns_known_response_assert_shape` | PASS |
| AC-003 | Dedup against rule findings | Demo + Test | `ac-002-003-shape-and-dedup.gif` + `augment_dedup_rule_finding_takes_precedence` | PASS |
| AC-004 | HTML + Markdown render section | Demo + Snapshot | `ac-004-render-section.gif` + insta snapshots | PASS |
| AC-005 | Privacy invariant extends to augment path | Demo + Test | `ac-005-privacy-invariant.gif` + `invariant_no_real_values_reach_ai_provider_augment` | PASS |
| AC-006 | Audit log records augment-pass hashes separately | Demo + Test | `ac-006-audit-log.gif` + `audit_log_records_augment_pass_hashes_separately` | PASS |

---

## Demo Inventory

```
docs/demo-evidence/S-5.03/
├── ac-001-augment-cli-invocation.gif     (238 KB, GIF89a, 1280x720)
├── ac-001-augment-cli-invocation.webm    (220 KB, WebM)
├── ac-001-augment-cli-invocation.tape    (source script, VHS)
├── ac-002-003-shape-and-dedup.gif        (173 KB, GIF89a, 1280x720)
├── ac-002-003-shape-and-dedup.webm       (182 KB, WebM)
├── ac-002-003-shape-and-dedup.tape       (source script, VHS)
├── ac-004-render-section.gif             (187 KB, GIF89a, 1280x720)
├── ac-004-render-section.webm            (231 KB, WebM)
├── ac-004-render-section.tape            (source script, VHS)
├── ac-005-privacy-invariant.gif          (92 KB, GIF89a, 1280x720)
├── ac-005-privacy-invariant.webm         (110 KB, WebM)
├── ac-005-privacy-invariant.tape         (source script, VHS)
├── ac-006-audit-log.gif                  (98 KB, GIF89a, 1280x720)
├── ac-006-audit-log.webm                 (119 KB, WebM)
├── ac-006-audit-log.tape                 (source script, VHS)
└── evidence-report.md                    (this file)
```

---

## Test Evidence

### S-5.03 Specific Tests (15 tests, all PASS)

All run from `tests/snapshot.rs` unless noted as `--lib` (unit tests in `src/findings/augmented.rs`).

#### AC-001 Tests
- `augment_request_invokes_provider_with_scrubbed_payload` — mock records its input; leak detector runs on bytes sent; asserts provider was called exactly once

#### AC-002 Tests
- `augment_parses_well_formed_json_array` (lib) — Vec<AugmentedFinding> of length 2 with correct id/severity/confidence
- `augment_id_namespace_prefix` (lib) — all IDs start with `ai.`
- `augment_tolerates_preamble_and_postamble` (lib) — parser extracts JSON array with prose before/after
- `augment_mock_returns_known_response_assert_shape` — full pipeline shape via mock provider
- `augment_caps_findings_at_top_25_by_confidence` — EC-002: 30-item fixture, top-25 all High/Medium

#### AC-003 Tests
- `augment_dedup_rule_finding_takes_precedence` — overlapping evidence token → augmented finding dropped
- `augment_dedup_disjoint_finding_survives` — disjoint hosts → augmented finding survives
- `dedup_drops_overlapping_augmented` (lib) — unit-level dedup_against_rule_findings
- `dedup_preserves_disjoint_augmented` (lib) — unit-level disjoint preservation
- `augment_drops_finding_referencing_unknown_host` — EC-003: hallucinated host_999 dropped

#### AC-004 Tests
- `html_report_contains_augmented_section_when_present` — heading + title present in HTML
- `html_report_omits_augmented_section_when_empty` — no heading when empty
- `markdown_report_contains_augmented_section_when_present` — heading + reasoning in markdown
- `augmented_findings_html_section_snapshot` — insta snapshot pins HTML render shape
- `augmented_findings_markdown_section_snapshot` — insta snapshot pins markdown render shape

#### AC-005 Tests
- `invariant_no_real_values_reach_ai_provider_augment` — canary IP 172.31.200.99, MAC CA:FE:BA:BE:DE:AD, and hostname CANARY-HOST-AUGMENT-DO-NOT-LEAK all absent from bytes sent to provider

#### AC-006 Tests
- `audit_log_records_augment_pass_hashes_separately` — AuditLog.augment_pass field populated with 64-char SHA-256 hashes; augment system_prompt_sha256 differs from analyze system_prompt_sha256

#### Error Path Tests
- `augment_returns_empty_vec_on_malformed_json_from_provider` — EC-001: malformed JSON → Ok(vec![])
- `augment_failure_after_analyze_success_renders_without_augment` — EC-004: provider error → report renders without augment section; exit 70

---

## Demo Detail

### Demo 1: AC-001 — CLI Surface

**File:** `ac-001-augment-cli-invocation.gif` (238 KB) + `.webm` (220 KB)
**Tape:** `ac-001-augment-cli-invocation.tape`

Content:
1. `otsniff analyze --help 2>&1 | grep -A2 'Also run the AI'` — shows `--ai` description text
2. `otsniff analyze --help 2>&1 | grep -E '^\s+--ai|^\s+--audit-log'` — shows both augment flags
3. `otsniff --help 2>&1 | grep -i analyze` — confirms analyze subcommand is surfaced

Substitution: `--ai` requires a live `claude` CLI. This demo records the documented interface.
The augment pipeline is demonstrated via mock-provider tests in demos 2–4.

---

### Demo 2: AC-002 + AC-003 — Shape and Dedup

**File:** `ac-002-003-shape-and-dedup.gif` (173 KB) + `.webm` (182 KB)
**Tape:** `ac-002-003-shape-and-dedup.tape`

Content:
1. `cargo test --lib augment_parses_well_formed_json_array augment_id_namespace` — shape contract
2. `cargo test --lib augment_tolerates_preamble_and_postamble` — preamble tolerance
3. `cargo test --test snapshot augment_dedup_rule_finding_takes_precedence` — rule wins
4. `cargo test --test snapshot augment_dedup_disjoint_finding_survives` — disjoint survives

---

### Demo 3: AC-004 — HTML and Markdown Render Section

**File:** `ac-004-render-section.gif` (187 KB) + `.webm` (231 KB)
**Tape:** `ac-004-render-section.tape`

Content:
1. `html_report_contains_augmented_section_when_present` — heading + title in HTML
2. `html_report_omits_augmented_section_when_empty` — no heading when empty (omit behavior)
3. `markdown_report_contains_augmented_section_when_present` — heading + reasoning in markdown
4. `augmented_findings_html_section_snapshot augmented_findings_markdown` — snapshot pins

Rendered HTML section shape (from insta snapshot `snapshot__augmented_section_html.snap`):
```html
<h2 class="ai-augmented-heading">AI-augmented findings</h2>
<p class="ai-augmented-note muted" ...>Patterns surfaced by a second AI pass ...</p>
<details open class="finding ai-finding sev-high" ...>
  <summary><span class="badge sev-high">high</span>
           <span class="badge" style="background:#2a8fb5">AI</span>
           <strong>Inferred gateway role mismatch</strong></summary>
  ...
</details>
```

Rendered markdown section shape (from insta snapshot `snapshot__augmented_section_md.snap`):
```markdown
## AI-augmented findings

_Patterns surfaced by a second AI pass, anchored on rule findings and inventory._

### [AI][HIGH] Inferred gateway role mismatch

_id: `ai.gateway_inference` · confidence: High_

**Evidence (1 sample(s)):**
...
**AI reasoning:**
host_001 appears as the L3 hop for all OT egress.
```

---

### Demo 4: AC-005 — Privacy Invariant

**File:** `ac-005-privacy-invariant.gif` (92 KB) + `.webm` (110 KB)
**Tape:** `ac-005-privacy-invariant.tape`

Content:
1. `invariant_no_real_values_reach_ai_provider_augment` — canary IPs/MACs/hostnames absent
2. `invariant_no_real_values_reach_ai_provider` — analyze-path invariant (both enforced)

---

### Demo 5: AC-006 — Audit Log

**File:** `ac-006-audit-log.gif` (98 KB) + `.webm` (119 KB)
**Tape:** `ac-006-audit-log.tape`

Content:
1. `audit_log_records_augment_pass_hashes_separately` — AuditLog.augment_pass holds 64-char SHA-256 hashes distinct from analyze-pass
2. `augment_failure_after_analyze_success_renders_without_augment` — EC-004 error path

---

## Edge Case Coverage

| EC | Scenario | Test | Status |
|----|----------|------|--------|
| EC-001 | Malformed JSON → empty vec | `augment_returns_empty_vec_on_malformed_json_from_provider` | PASS |
| EC-002 | Cap at top-N by confidence | `augment_caps_findings_at_top_25_by_confidence` | PASS |
| EC-003 | Unknown host dropped | `augment_drops_finding_referencing_unknown_host` | PASS |
| EC-004 | Augment failure → report without section | `augment_failure_after_analyze_success_renders_without_augment` | PASS |

---

## Policy Compliance

### POL-12: No User Paths in Demo Files
- **Check:** `grep -r "/Users/" docs/demo-evidence/S-5.03/*.tape`
- **Result:** CLEAN (0 matches)
- All tape files use relative paths (`./target/release/otsniff`, `cargo test ...`)

### Font Selection
- JetBrains Mono and Menlo not present on this machine
- Font used: `Andale Mono` (available via `/System/Library/Fonts/Supplemental/Andale Mono.ttf`)

### Dimensions
- All recordings: 1280x720 (factory standard)

---

## Full Suite Test Summary

**Total Tests Run:** 423
**All Passed:** YES
**S-5.03 Specific:** 15/15 PASSED (100%)

Test breakdown:
- Unit tests (lib): 220 passed (includes augmented.rs unit tests)
- Integration tests: 203 passed (includes snapshot.rs S-5.03 tests)

---

## Sign-Off

| Role | Verification | Status |
|------|--------------|--------|
| Test Recorder | 15/15 S-5.03 tests pass; 423/423 suite pass | PASS |
| Demo Recorder | 5 VHS gifs valid; POL-12 compliant; no absolute paths | PASS |

**Approved for Code Delivery:** Yes
**CI Status:** 423/423 tests pass
**Ready for PR:** Yes

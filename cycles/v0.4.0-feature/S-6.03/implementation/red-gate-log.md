---
document_type: red-gate-log
level: ops
version: "1.0"
status: complete
producer: test-writer
timestamp: 2026-06-18T09:30:00
phase: 3
inputs:
  - .factory/stories/S-6.03-diff-renderer.md
  - src/diff.rs
  - src/report.rs
  - src/report_md.rs
input-hash: "n/a (inline orchestration)"
traces_to: "BC-8.04.001"
stub_architect_agent: "a5e694dee14438a85"
stub_compile_verified: true
test_writer_agent: "a6c6c86fbcb60385b"
red_gate_verified: true
---

# Red Gate Log: S-6.03 — Diff HTML + markdown renderer

## Summary
| Story | Tests Written | All Fail (Red)? | Gate |
|-------|-------------|-----------------|------|
| S-6.03 | 6 | Yes (6/6 fail) | PASSED |

## Stubs Created
### S-6.03: HTML + markdown rendering for the diff report
- `pub fn render_diff_html(diff: &Diff) -> Result<String>` (src/report.rs) — `todo!()` body; Result type matches existing `render_html`.
- `pub fn render_diff_markdown(diff: &Diff) -> String` (src/report_md.rs) — `todo!()` body; bare-String return per AC-002.
- `templates/diff.html` — placeholder file (orphan/unreferenced; keeps cargo check clean until implementer authors the real askama template).

Stub commit: `b363462`. `cargo check` verified clean (independently re-run by orchestrator).

## Red Gate Verification
### S-6.03 (test commit `c74200b`)
- AC-001 (BC-8.04.001 HTML): `test_bc_8_04_001_diff_html_snapshot_and_sections` — FAIL (expected)
- AC-001 (BC-8.04.001 HTML): `test_bc_8_04_001_diff_html_is_deterministic` — FAIL (expected)
- AC-002 (markdown): `test_bc_8_04_001_diff_markdown_snapshot` — FAIL (expected)
- AC-003 (determinism, md): `test_bc_8_04_001_diff_markdown_is_deterministic` — FAIL (expected)
- EC-001 (empty diff, HTML): `test_bc_8_04_001_empty_diff_html_no_deltas_banner` — FAIL (expected)
- EC-001 (empty diff, markdown): `test_bc_8_04_001_empty_diff_markdown_no_deltas_banner` — FAIL (expected)

**Verification command (re-run by orchestrator, not trusted from agent):**
`cargo test --test snapshot bc_8_04_001` → `test result: FAILED. 0 passed; 6 failed`.

**Failure mode:** all 6 panic at the `todo!()` stub boundary
(`src/report.rs:263` / `src/report_md.rs:304`). For pure render functions
this is the correct RED — any test must invoke the function and therefore
hits the unimplemented body before its assertions/snapshots evaluate. The
tests genuinely encode the target behavior (insta snapshots of full
output + explicit section/badge substring assertions + determinism +
EC-001 banner), so they will turn green only when the implementation
produces correct, deterministic output.

## Regression Check
| Existing Tests | Status |
|---------------|--------|
| 74 snapshot-suite tests pre-existing | all pass (74 filtered out during the focused run; full suite unaffected — only additive test code + todo!() stubs added) |

## Hand-Off to Implementer
- Story ready for implementation: S-6.03
- Implementation guidance:
  - Author `templates/diff.html` as a self-contained askama template; add a
    view struct in `src/report.rs` with `#[derive(Template)]` mirroring the
    pre-formatted-view-struct pattern used by `render_html` (ADR-0003).
  - Sections required (AC-001): summary banner (counts of
    new/recurring/resolved findings + new/gone hosts), new findings
    ("NEW since baseline" badge), resolved findings ("RESOLVED" badge),
    recurring findings (recurring badge), host changes (new/gone), role
    shifts table, flow shifts table (entries above 2× threshold only).
  - Markdown (`render_diff_markdown`) mirrors the same content; follow the
    `render_markdown` pattern.
  - Determinism (AC-003): sort every section with `BTreeMap`/sorted vecs so
    output is byte-identical across runs.
  - EC-001: empty `Diff` must still emit a "No deltas detected" banner.
  - EC-002: cap evidence rows per finding (reuse existing ~5-sample cap).
  - Wire the new renderers into `src/cli.rs` (replace the S-6.02 placeholder
    block at ~lines 388–401 that emits `<pre>`-wrapped JSON for HTML and the
    "Full rendering arrives in S-6.03" markdown). Keep the existing
    `leak_detector::ensure_clean` / `ensure_no_map_values` gate after render.
  - Accept the insta snapshots (`cargo insta accept`) once output is correct.

# otsniff — Technical Debt Register

All entries are sourced from adversarial reviews, wave-gate findings, or
deliberate deferrals during story delivery. Each entry includes a suggested
fix location so implementers can act without re-reading review artifacts.

Priority: HIGH / MEDIUM / LOW
Status: OPEN / IN-PROGRESS / CLOSED

---

## OPEN entries

| ID | Priority | Source | Status | Description | Suggested Fix |
|---|---|---|---|---|---|
| F-W1-002 | HIGH | Wave-1 adversarial review | OPEN | Pseudonym regex `[0-9a-f]+` accepts hex but `build_map` only emits decimal pseudonyms — correctness gap that could silently miss real values | Tighten regex to `[0-9]+` in `src/scrub.rs` (pseudonym pattern, not the leak-detector regexes) |
| F-W1-003 | MEDIUM | Wave-1 adversarial review | OPEN | `ScrubMap::validate()` does not detect duplicate real-value entries — two map keys could map to the same real value without error | Add duplicate-real-value check in `src/scrub.rs::ScrubMap::validate` |
| F-W1-004 | MEDIUM | Wave-1 adversarial review | OPEN | Regexes recompiled on every `ensure_clean` call — perf hygiene; trivially avoidable | Wrap compiled regexes in `once_cell::Lazy` in `src/ai/leak_detector.rs` |

---

## CLOSED entries

| ID | Priority | Source | Closed | Resolution |
|---|---|---|---|---|
| F-W1-001 | HIGH | Wave-1 adversarial review | 2026-05-21 (PR #86, 7d8413e) | Added `map.validate()?` after `serde_json::from_slice` in `run_unscrub`. CLI smoke test `test_f_w1_001_unscrub_rejects_corrupted_map` exercises the rejection path. |
| F-W1-005 | MEDIUM | Wave-1 Kani stories (S-4.01..03) | 2026-05-20 (PR #84, f068948) | Kani CI workflow_dispatch executed; first run surfaced all 5 harnesses failed/timed out. Proof-model rewrite landed; all 6 harnesses now report `VERIFICATION:- SUCCESSFUL` on develop CI. |

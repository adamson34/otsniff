# Evidence Report — S-2.08

| Field | Value |
|-------|-------|
| Story ID | S-2.08 |
| Title | `creds.rdp_no_nla` — RDP without Network Level Authentication |
| Behavioral Contracts | BC-1.04.004, BC-3.04.006 |
| Worktree HEAD SHA | 573729057c531fbc01f01ffa02260e0de236a5b2 |
| Date | 2026-05-19 |
| Branch | feature/S-2.08-creds-rdp-no-nla |

## Pattern Note

This is a detector story with no new CLI surface. Evidence consists of `cargo
test` output and rule-catalog fragments rather than VHS/Playwright recordings.
The same pattern was used for S-2.05, S-2.06, and S-2.07.

## Coverage Table

| Evidence File | Criterion | Path | Result |
|---------------|-----------|------|--------|
| AC-001-parser.md | AC-001 / BC-1.04.004 — parser round-trip (9 unit tests) | success | PASS |
| AC-002-detector.md | AC-002 / BC-3.04.006 — detector integration (5 tests) | success | PASS |
| AC-002-detector.md | AC-002 — rule catalog listing (`rules` subcommand) | success | PASS |
| AC-002-detector.md | AC-002 — wired into `run_all_findings` (snapshot test) | success | PASS |
| EC-001-EC-002-EC-003-parser-defenses.md | EC-001 — RDP_NEG_RSP missing returns None | error-path | PASS |
| EC-001-EC-002-EC-003-parser-defenses.md | EC-002 — TPKT length mismatch rejected | error-path | PASS |
| EC-001-EC-002-EC-003-parser-defenses.md | EC-003 — non-3389 port ignored | error-path | PASS |
| AC-002-bit-test-correction.md | AC-002 — bit-test correction (3 negative tests) | error-path | PASS |
| BC-INDEX-registration.md | BC-INDEX — BC-1.04.004 + BC-3.04.006 registered | success | PASS |

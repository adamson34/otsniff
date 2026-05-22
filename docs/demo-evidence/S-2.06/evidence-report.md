# Evidence Report — S-2.06: `compat.ntlmv1`

| Field | Value |
|-------|-------|
| Story ID | S-2.06 |
| Behavioral contracts | BC-1.03.006, BC-3.04.004 |
| Worktree HEAD SHA | ef1adc2 |
| Evidence date | 2026-05-18 |
| Branch | feature/S-2.06-compat-ntlmv1 |

## Coverage table

| Criterion | File | Status |
|-----------|------|--------|
| AC-001 (BC-1.03.006) — parser: 6 unit tests pass; observer ingests NTLMv1 on port 445 | `AC-001-parser.md` | PASS |
| AC-002 (BC-3.04.004) — detector: 3 integration tests pass; rule appears in catalog; snapshot wiring test passes | `AC-002-detector.md` | PASS |
| EC-001 — NTLMv2 (NTLM2_KEY flag set) not flagged by `compat.ntlmv1` | `EC-001-ntlmv2-not-flagged.md` | PASS |
| EC-002 — MessageType validation: CHALLENGE, AUTHENTICATE, random bytes, and truncated payloads all rejected | `EC-002-messagetype-validation.md` | PASS |
| BC-INDEX registration — BC-1.03.006 + BC-3.04.004 registered; total_bcs 87 → 89 | `BC-INDEX-registration.md` | PASS |

## Non-standard evidence pattern note

S-2.06 adds no new user-facing CLI surface. The `compat.ntlmv1` rule appears
in the existing `otsniff rules` catalog (unchanged subcommand) and the HTML
report output (unchanged rendering path). Demo evidence is therefore captured
`cargo test` output confirming all acceptance criteria plus the rule-listing
fragment from `otsniff rules` confirming the rule is registered in the catalog
at severity High.

No VHS recordings or Playwright scripts are produced because there is no new
interactive CLI surface or web UI to demonstrate. The `cargo test` outputs
above are the authoritative evidence that the BCs are satisfied.

## Snapshot regression check

All 50 existing snapshot tests continue to pass, confirming no regression to
previously shipped detectors (see AC-002 for the snapshot test output).

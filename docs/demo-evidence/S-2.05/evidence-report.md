# Evidence Report — S-2.05: `creds.ldap_simple_bind`

| Field | Value |
|-------|-------|
| Story ID | S-2.05 |
| Behavioral contracts | BC-1.03.005, BC-3.01.005 |
| Worktree HEAD SHA | b4a3912 |
| Evidence date | 2026-05-18 |
| Branch | feature/S-2.05-creds-ldap-simple-bind |

## Coverage table

| Criterion | File | Status |
|-----------|------|--------|
| AC-001 (BC-1.03.005) — parser: 5 unit tests pass | `AC-001-parser.md` | PASS |
| AC-002 (BC-3.01.005) — detector: 3 integration tests pass; rule appears in catalog | `AC-002-detector.md` | PASS |
| AC-003 — STARTTLS suppression: negative test passes; structural pairing ensures non-vacuous | `AC-003-starttls-suppression.md` | PASS |
| EC-001 — port 3268 (Global Catalog): observer test passes | `EC-001-port-3268.md` | PASS |
| EC-003 — anonymous bind suppression: integration test passes | `EC-003-anonymous-bind.md` | PASS |
| BC-INDEX registration — BC-1.03.005 + BC-3.01.005 registered; total_bcs 85 → 87 | `BC-INDEX-registration.md` | PASS |

## Non-standard evidence pattern note

S-2.05 adds no new user-facing CLI surface. The `creds.ldap_simple_bind` rule
appears in the existing `otsniff rules` catalog (unchanged subcommand) and the
HTML report output (unchanged rendering path). Demo evidence is therefore
captured `cargo test` output confirming all acceptance criteria plus the
rule-listing fragment from `otsniff rules` confirming the rule is registered in
the catalog at severity Critical.

No VHS recordings or Playwright scripts are produced because there is no new
interactive CLI surface or web UI to demonstrate. The `cargo test` outputs
above are the authoritative evidence that the BCs are satisfied.

## Snapshot regression check

All 50 existing snapshot tests continue to pass, confirming no regression to
previously shipped detectors (see AC-002 for the snapshot test output).

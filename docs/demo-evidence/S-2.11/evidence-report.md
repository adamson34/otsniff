# Evidence Report — S-2.11: `ics.modbus_unit_id_sweep`

| Field | Value |
|-------|-------|
| Story ID | S-2.11 |
| Behavioral Contracts | BC-1.02.009, BC-3.03.006 |
| Worktree HEAD | d3dfa37dec4699c39dde9ada7b24b811ec378569 |
| Date | 2026-05-19 |

## Coverage Table

| Evidence File | Criterion | Result |
|---------------|-----------|--------|
| AC-001-observer-aggregation.md | AC-001 (BC-1.02.009): 5 observer unit-id accumulation tests | PASS |
| AC-002-detector.md | AC-002 (BC-3.03.006): 7 detector tests + rule catalog entry + wiring test | PASS |
| EC-001-EC-002-broadcast-and-gateway.md | EC-001: unit ID 0 counted; EC-002: unit ID 0xFF counted | PASS |
| BC-1.02.006-collision-correction.md | Pre-flight BC renumber: 006 → 009 (DHCP collision avoided) | PASS |
| BC-INDEX-registration.md | BC-INDEX entries present; total_bcs 93 → 95 | PASS |

## Non-Standard Pattern Note

S-2.11 adds no new CLI surface. Evidence is captured test output and rule-catalog
fragments rather than VHS/Playwright recordings. This matches the established
pattern for pure detector stories (S-2.05, S-2.06, S-2.07, S-2.08, S-2.09,
S-2.10, S-2.12): the acceptance criteria are fully exercised by the test suite,
and the visible user-facing output is the `rules` subcommand catalog entry confirmed
in AC-002-detector.md.

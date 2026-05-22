# Evidence Report — S-2.07: `compat.weak_tls_cipher`

| Field | Value |
|-------|-------|
| Story ID | S-2.07 |
| Behavioral Contracts | BC-1.04.003, BC-3.04.005 |
| Worktree HEAD | e02e741 |
| Date | 2026-05-18 |

## Coverage

| Item | File | Result |
|------|------|--------|
| AC-001 — TLS cipher_suites parser (3 unit tests) | AC-001-parser.md | PASS |
| AC-002 — detector emission + rule catalog + snapshot wiring (6 tests) | AC-002-detector.md | PASS |
| AC-003 — sibling firing alongside stale_tls | AC-003-sibling-with-stale-tls.md | PASS |
| EC-001 — GREASE values skipped | EC-001-grease-skipped.md | PASS |
| BC-INDEX — registration of BC-1.04.003 + BC-3.04.005 | BC-INDEX-registration.md | PASS |

## Non-standard pattern note

This is a detector story with no new CLI surface area. Evidence is captured
`cargo test` output and rule-catalog fragment rather than a VHS terminal
recording, following the same pattern established by S-2.05 and S-2.06.

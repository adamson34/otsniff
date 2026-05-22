# Evidence Report — S-5.01: Periodic parse-loop progress in `-v` mode

| Field | Value |
|-------|-------|
| Story ID | S-5.01 |
| Behavioral Contract | BC-9.04.001 |
| Worktree HEAD SHA | c14642fb0e9dcb2e581945c3652d07faad7b3771 |
| Date | 2026-05-19 |

## Coverage Table

| Item | File | Result |
|------|------|--------|
| AC-001: cadence and format | `AC-001-cadence-and-format.md` | PASS |
| AC-002: no output without `-v` | `AC-002-no-output-without-verbose.md` | PASS |
| AC-003: rate-limited to 2s | `AC-003-rate-limit.md` | PASS |
| Verbose mode live run | `verbose-mode-live.md` | PASS |
| BC-9.04.001 registration | `BC-9.04.001-registration.md` | PASS |

## Notes

This is an effectful-shell story — the observable behavior is stderr
emission during the parse loop when `-v` is set. Evidence combines:

- **Unit-test output** — 6 tests in `progress::tests` exercise the
  cadence thresholds, format, rate-limit, `finish()` summary, and
  suppression when `verbose = false`, all via MockClock injection (no
  real sleep).
- **Smoke-test output** — `test_bc_9_04_001_no_verbose_no_progress_lines`
  in `tests/cli_smoke.rs` confirms the binary emits nothing on stderr
  without `-v`.
- **Live `cargo run` output** — two runs against `tests/fixtures/Modbus.pcap`
  (with and without `-v`) confirm the real binary behaves correctly.

For large captures (multi-GB), the periodic emission line
(`[parse] processed N packets / X MB`) would appear at runtime; that
path is covered exclusively by unit tests using MockClock since no
large fixture is committed to the repo.

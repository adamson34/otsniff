# Evidence Report — S-6.01: Stable pseudonym maps across captures

| Field | Value |
|-------|-------|
| Story ID | S-6.01 |
| Behavioral Contract | BC-5.03.001 |
| Worktree HEAD SHA | 5c56e1ca83b156b84c09e3b03618a24b2be3fe32 |
| Date | 2026-05-19 |
| Branch | feature/S-6.01-scrub-map-merge |

## Coverage Table

| Evidence | AC / EC | Status | Notes |
|----------|---------|--------|-------|
| AC-001-merge-map-laws.md | AC-001 | PASS | 8 unit tests; all merge-law properties verified |
| AC-002-round-trip-exactness.md | AC-002 | PASS | Round-trip test with baseline + current identifiers |
| AC-003-cli-flag.md | AC-003 | PASS | Help text confirms flag exists; CLI integration test passes |
| AC-004-leak-detector-survives.md | AC-004 | PASS | Both `ensure_clean` and `ensure_no_map_values` pass after merge |
| EC-001-corrupted-map-rejected.md | EC-001 | PASS | `ScrubMap::validate()` rejects empty pseudonym/real values |
| EC-003-baseline-only-preserved.md | EC-003 | PASS | Assertion confirms `host_002 -> 10.0.0.2` survives when absent from current |
| BC-5.03.001-registration.md | BC registration | PASS | `total_bcs` 98 -> 99; BC-INDEX line 114 confirms full contract |

All 7 evidence items: PASS.

## Non-standard pattern note

This is a scrub/unscrub library story rather than a user-facing CLI workflow story.
Evidence is captured `cargo test` output and a CLI help fragment rather than VHS
recordings or Playwright sessions — there is no interactive terminal session to film
that would be more informative than the test output itself. The AC-003 CLI integration
test (`test_bc_5_03_001_baseline_map_flag_extends_pseudonyms`) passes using a
synthetic fixture embedded in the test suite; it does not require `tests/fixtures/Modbus.pcap`.
A live two-capture demonstration showing pseudonym stability across real OT captures
is deferred to S-6.02, which adds the `diff` subcommand and provides the natural
end-to-end demo surface for this feature.

---
document_type: red-gate-log
story_id: S-2.01
cycle: v0.4.0-feature
timestamp: 2026-05-14T10:30:00Z
verdict: REGRESSION-LOCKDOWN (not classic red-gate)
---

# Red Gate Log — S-2.01

## Discipline note

S-2.01 is a **regression-lockdown** story, not a classic red-gate-then-green TDD story. The `unexpected_label` function in `src/findings/unexpected_protocols.rs` was already implemented correctly (S-1.04 fixed the trigger string drift in v0.4 cycle). This story adds tests that:
- PASS on first commit (the implementation is already correct)
- FAIL in the future if a refactor accidentally drops a table row, renames a label, narrows a port range, or changes protocol-number handling

The "Red Gate" concept here means **"the tests are meaningful and exercise the contract"**, not "the tests fail before implementation." A future implementer can confirm the regression-guard semantics by deliberately breaking the table (try renaming `"sip"` to `"voip"` and watch the test fire), but that exercise is not part of this story's scope.

## Step 2 — Stub Architect

**Action:** Skipped. The target file (`src/findings/unexpected_protocols.rs`) already exists. No new module.

## Step 3 — Test Writer

**Commit:** `a0dfcbb` test(S-2.01): lock port-to-label table (BC-AUDIT-009)
**File:** `src/findings/unexpected_protocols.rs` (+151 lines, all in `#[cfg(test)] mod tests`)

**Tests added (4):**
- `unexpected_label_lookups_match_canonical_table` — positive assertions, one per row in the 11-label table
- `unexpected_label_returns_none_for_unmapped_ports` — sentinel: telnet (23), http (80), https (443), ssh (22), modbus (502), 0, 65535 all return None
- `unexpected_label_returns_none_for_non_tcp_udp` — protocol-number sentinel: ICMP (1), GRE (47), ESP (50), SCTP (132) all return None
- `unexpected_label_distinct_label_set_is_exactly_eleven` — sweeps the table and asserts exactly 11 distinct labels (smtp, bittorrent, rtmp, apns, gcm, stun, sip, irc, openvpn, teamviewer, anydesk)

## Verification (independent)

```
cargo test → 160 passed; 0 failed (98 lib + 16 cli_smoke + 46 snapshot)
cargo clippy --all-targets -- -D warnings → clean
cargo fmt --all --check → clean
scripts/lint-no-user-paths.sh → 145 files, 0 violations
```

All 4 new tests pass on first commit, as expected for a regression-lockdown story. No pre-existing tests regressed.

## Step 4 — Implementer

**Action:** Skipped. No implementation work required — the existing code already satisfies the locked-down contract. The PR ships test additions only.

## Verdict

**Regression lockdown achieved.** The port-to-label table is now protected against silent drift by 4 tests covering: row-level positive assertions, port-out-of-table sentinels, protocol-number sentinels, and a label-set-cardinality invariant.

Future story (not in this story's scope): if anyone wants to refactor `unexpected_label` (e.g., extract into a `const TABLE: &[(...)]` static table), these tests guarantee the contract survives the refactor.

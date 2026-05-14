---
document_type: red-gate-log
story_id: S-1.03
cycle: v0.4.0-feature
timestamp: 2026-05-14T13:30:00Z
verdict: PASSED (hybrid story; one Red Gate, one regression-lockdown)
---

# Red Gate Log — S-1.03 (code half)

## Discipline note

S-1.03 is a 5-point **hybrid story**. The docs half (PRD edits AC-001..AC-005 plus AC-006 PRD cross-ref) landed on `factory-artifacts` SHA `1563848` and does not exercise test infrastructure. The code half — this Red Gate log — covers two new unit tests:

- **AC-005 (`ot_or_default_empty_input_returns_only_ipv4_rfc1918`)** is a regression-lockdown test, similar in semantics to S-2.01. The current `src/cli.rs::ot_or_default` implementation already satisfies the contract (returns exactly 3 IPv4 RFC1918 CIDRs, no IPv6). This test PASSES on first commit and exists to lock that contract against future drift.
- **AC-006 (`s7_metadata_trigger_does_not_mention_password`)** is a classic Red Gate. The current `S7_METADATA.trigger` in `src/findings/engineering_commands.rs` contains the substring "password operations", which AC-006 mandates be removed. This test FAILS on first commit; the implementer's job is to satisfy it.

## Step 2 — Stub Architect

**Action:** Skipped. Both target files exist on `develop`. No new modules.

## Step 3 — Test Writer

**Worktree:** `.worktrees/S-1.03/` on `feature/S-1.03-s7-trigger-and-cli-defaults` (branched from develop @ `2caa283`).

**Commits:**
- `3a96bf8` test(S-1.03): lock ot_or_default IPv4-only RFC1918 default (AC-005)
- `706ba46` test(S-1.03): assert S7_METADATA.trigger does not mention "password" (AC-006)

**Tests added (2):**

1. `cli::tests::ot_or_default_empty_input_returns_only_ipv4_rfc1918` — locks AC-005 invariant
2. `findings::engineering_commands::tests::s7_metadata_trigger_does_not_mention_password` — drives AC-006 fix

## Red Gate verification (independent)

```
cd /Users/lukeadamson/1898/otsniff/.worktrees/S-1.03
cargo test --lib

99 passed; 1 failed; 0 ignored

failures:
    findings::engineering_commands::tests::s7_metadata_trigger_does_not_mention_password

assertion: S7_METADATA.trigger still mentions 'password':
  "Fires when S7Comm (Siemens S7-300/400/1200/1500 over tcp/102) traffic
   contains a function code we classify as engineering — PLC stop / start,
   block download / upload, password operations. S7Comm has no native
   authentication; S7-1500 adds Secure Communication only when explicitly
   enabled."
```

The failure references the contract under test ("S7_METADATA.trigger still mentions 'password'") — not a build error, not a "not yet implemented" placeholder. This is the desired Red Gate state.

## Step 4 — Implementer (pending)

The implementer's task is **single-line**: edit `src/findings/engineering_commands.rs` line 77-78 (the `password operations` clause in `S7_METADATA.trigger`) to remove the inaccurate "password" wording. After the edit, the snapshot test `rule_catalog_matches_committed_rules_md` will break because `docs/RULES.md` derives from `S7_METADATA.trigger`. The implementer must regenerate `docs/RULES.md` (via `cargo run -- rules --format md > docs/RULES.md` from the worktree root) and verify all snapshots are green.

## Verdict

**Red Gate PASSED.** Implementer is unblocked. Expected delta:
- 1 edit to `src/findings/engineering_commands.rs` (trigger string)
- 1 update to `docs/RULES.md` (cascading from the above)
- Possible 1 snapshot accept via `cargo insta review` if the trigger string appears anywhere in HTML/markdown snapshots

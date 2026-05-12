---
document_type: red-gate-log
story_id: S-2.03
cycle: v0.4.0-feature
timestamp: 2026-05-12T16:45:00Z
verdict: PASSED
---

# Red Gate Log — S-2.03

## Step 2 — Stub Architect

**Action:** Skipped. The existing `src/oui.rs` compiles and the
story is a pure data expansion (replace TABLE contents, no new
types/functions). Exit condition for Step 2 (`cargo check` clean)
was already satisfied at worktree creation.

## Step 3 — Test Writer

**Commit:** `1284283` test(S-2.03): add failing tests for OUI table expansion
**File:** `src/oui.rs` +91 lines (new test cases in existing `#[cfg(test)] mod tests`)

**Tests added:**
- `oui::tests::table_has_at_least_3000_entries` — asserts `TABLE.len() >= 3000`
- `oui::tests::table_is_sorted_by_prefix` — asserts sorted-by-prefix invariant for `binary_search`
- `oui::tests::table_resolves_named_industrial_vendors` — Beckhoff/Moxa/Phoenix/Yokogawa/Hilscher/WAGO/Mitsubishi/Omron/GE/Emerson must each resolve
- `oui::tests::table_resolves_common_it_vendors` — Cisco/Dell/HP/VMware/Microsoft/Intel must each resolve
- `oui::tests::lookup_uses_binary_search` — soft perf gate (currently passing on 43-entry linear scan; activates as table grows)

## Red Gate verification (independent)

```
test oui::tests::table_resolves_common_it_vendors      ... FAILED
test oui::tests::table_resolves_named_industrial_vendors ... FAILED
test oui::tests::table_has_at_least_3000_entries       ... FAILED
test oui::tests::table_is_sorted_by_prefix             ... FAILED
test result: FAILED. 90 passed; 4 failed
```

4 of 5 new tests fail as expected, all with `assert!()` panics — not build errors. The 5th (`lookup_uses_binary_search`) is a soft perf gate that passes today on the 43-entry table; it becomes meaningful once the 3000+ entry table lands.

90 pre-existing tests still pass.

## Verdict

**Red Gate PASSED.** Ready for implementer.

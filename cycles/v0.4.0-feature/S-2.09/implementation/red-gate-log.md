---
document_type: red-gate-log
story_id: S-2.09
cycle: v0.4.0-feature
timestamp: 2026-05-14T18:00:00Z
verdict: PASSED
---

# Red Gate Log — S-2.09

## Step 2 — Stub Architect

**Commit:** `64e64d0` feat(S-2.09): add ntp_external module stubs

Files:
- `src/findings/ntp_external.rs` created — full `METADATA` const (real values; const can't be `todo!()`); `pub fn detect(_obs, _ot_subnets) -> Vec<Finding> { todo!("S-2.09 implementer fills this in") }`
- `src/findings/mod.rs` wired: `mod ntp_external;`, `ntp_external::METADATA,` in catalog, `out.extend(ntp_external::detect(...))` in run_all

`cargo check --all-features` — 0 warnings, 0 errors.

## Step 3 — Test Writer

**Commit:** `35d4385` test(S-2.09): add failing tests for boundary.ntp_external (BC-1.05.003, BC-3.05.004)

Files: `tests/snapshot.rs` (+212 lines, 4 new tests)

**Tests added (4, all in `tests/snapshot.rs`):**
- `ntp_external_fires_on_cross_zone_ntp_flow` — AC-001 positive case (10.0.0.1 → 8.8.8.8:123)
- `ntp_external_does_not_fire_for_non_ot_source` — EC-001 (172.99.0.1 outside RFC1918)
- `ntp_external_does_not_fire_for_intra_ot_traffic` — EC-002 (10.0.0.1 → 10.0.0.2:123)
- `ntp_external_flags_multicast_destination` — EC-003 (10.0.0.1 → 224.0.1.1:123)

## Red Gate verification (independent)

```
cd /Users/lukeadamson/1898/otsniff/.worktrees/S-2.09
cargo test

lib:       100 passed; 0 failed
cli_smoke: 16 passed; 0 failed
snapshot:  22 passed; 28 failed
```

**Failure analysis:**

The 4 dedicated ntp_external tests fail with:
```
panicked at src/findings/ntp_external.rs:34:5:
not yet implemented: S-2.09 implementer fills this in
```

The other 24 snapshot tests also fail with the same `todo!()` panic — they call `findings::run_all()` (directly or transitively via `render_html` / `render_md` / etc.), and `run_all` now invokes `ntp_external::detect()` which panics. This is **expected cascading behavior**, not a separate set of failures:

- Tests like `every_finding_has_a_non_empty_playbook`, `every_finding_id_appears_in_the_rule_catalog`, `html_report_snapshot`, `findings_json_snapshot` all exercise `run_all()` end-to-end.
- Once the implementer fills in `detect()` with a working body that doesn't panic, the cascade clears and these tests resume passing (assuming snapshots only diff on the new `boundary.ntp_external` rule appearing in the report — that will need `cargo insta accept`).

The test-writer's initial report mischaracterized these as "pre-existing Red Gates from other unimplemented stories". They are not. develop @ `ee25ba5` is fully green at the start of this worktree; the 24 failures all stem from this story's `todo!()`.

## Verdict

**Red Gate PASSED.** Implementer is unblocked. Expected delta:

- `src/findings/ntp_external.rs` — fill in `detect()` mirroring `dns_resolver.rs` (port 123 instead of 53, same shape otherwise)
- `docs/RULES.md` regen via `cargo run -- rules --format md > docs/RULES.md`
- Up to ~5 snapshot accepts via `cargo insta review` (only the new `boundary.ntp_external` rule appearing in rendered output)
- Confirm all 4 dedicated tests + the cascading 24 all turn green

Final cargo test must be: 100 + 16 + 50 = **166 passed; 0 failed** (50 snapshot tests = original 46 + 4 new).

---
pipeline: PHASE-2-COMPLETE
phase: phase-2
product: otsniff
mode: brownfield
timestamp: 2026-05-12T00:30:00Z
phase_0_status: complete
phase_1_status: complete-converged
phase_2_status: complete-approved
phase_2_approval: human-approved 2026-05-11
phase_2_adversarial_passes: 2
phase_2_adversarial_verdict_pass1: BLOCKING (7B/11S/4N) — fixes applied for 7B + 6S
phase_2_adversarial_verdict_pass2: BLOCKING (4B/9S/5N) — fixes applied for 4B + 2S
phase_2_convergence: All 11 BLOCKING resolved across two passes; 8/20 SUBSTANTIVE addressed; remaining 12 SUBSTANTIVE + 9 NITPICK logged in ADV-P1.md + ADV-P2.md for follow-up
next_phase: phase-3-tdd-implementation (Wave 1 dispatch)
---

# otsniff factory state

Phase 0 + Phase 1 + Phase 2 complete via Option B (abbreviated). Phase 2
ran inline (Steps A–E) plus one adversarial-review pass. The adversary
verdict was BLOCKING on Pass 1 with 7 BLOCKING + 11 SUBSTANTIVE + 4
NITPICK findings; the team applied fixes covering all 7 BLOCKING + 6 of
11 SUBSTANTIVE. A Pass-2 adversary spawn was deferred at user request.
The remaining 5 SUBSTANTIVE + 4 NITPICK items are recorded in
ADV-P1.md and should be addressed before story-writer dispatch.

## Artifacts produced

### Phase 0 (brownfield ingest)
(see prior STATE.md — unchanged)

### Phase 1 (spec crystallization)
(see prior STATE.md — unchanged)

### Phase 2 (story decomposition)

Located in `.factory/stories/`:

- `epics.md` — 6 epics covering Phase 0 lessons + Phase 1 ASR findings + ROADMAP unshipped items
- `STORY-INDEX.md` — 31 stories with wave / points / dependencies / subsystems
- `dependency-graph.md` — story-level deps + acyclicity walk + Serialization Plan
- `sprint-state.yaml` — initial pending/blocked state for orchestrator
- `S-1.01..S-6.03` — 31 story files (one per file)
- `adversarial-reviews/ADV-P1.md` — Pass-1 adversary findings + fix log

Located in `.factory/cycles/v0.4.0-feature/`:

- `wave-schedule.md` — 3-wave plan with serialization callouts

Located in `.factory/holdout-scenarios/`:

- `HS-INDEX.md` — 9 scenarios (8 must-pass, 1 should-pass)
- `wave-scenarios/HS-001..HS-009.md` — per-scenario detail files,
  walled off from implementers/test-writers/adversary

## Gate criteria

| Criterion | Status | Notes |
|---|---|---|
| Every BC in PRD traces to at least one story | PASS-with-caveats | Pre-existing 60 BCs are NOT decomposed (brownfield: code IS implementation). 8 net-new BCs introduced by E-2 stories. 15 BC-AUDIT formalized by S-1.05. STORY-INDEX BC-coverage map enumerates the trace |
| No story contains TBD / TODO / placeholder ACs | PASS | grep clean across 31 stories |
| Dependency graph has no cycles | PASS | dependency-graph.md walk shows topological sort completes |
| Wave assignments respect dependency ordering | PASS | sprint-state.yaml `blocked_by` lists honour Wave 1 < Wave 2 < Wave 3 |
| STORY-INDEX matches individual story files | PASS-with-caveat | Frontmatter `wave:` values now consistent with index after ADV-P1-001 fix. Story-count and point totals reconciled (31 stories, 106 points) |
| At least one holdout scenario per wave | PASS | Wave 1: 5, Wave 2: 2, Wave 3: 2 |
| Input-hash drift check | DEFERRED | check-input-drift skill not run in this inline orchestration; deferred to story-writer dispatch |
| Adversarial review converged | NOT_CONVERGED_BUT_BLOCKING_RESOLVED | 1 pass run; all BLOCKING addressed; 5 SUBSTANTIVE + 4 NITPICK remain in ADV-P1.md |
| Human approval | PENDING | This file's pipeline state asks for it |

## Outstanding items from Pass-1 adversarial review

These were classified SUBSTANTIVE but not fixed inline (the user
interrupted before Pass 2 could re-validate). They should be addressed
before story-writer dispatch:

- **ADV-P1-009** — S-3.04 lists `scrub_text` fuzz target but the
  subsystems list was extended to include S.5 (partial fix). Coordination
  with S-4.01..04 still informal.
- **ADV-P1-011** — Story bodies lack a `## Behavioral Contracts` table.
  Frontmatter is single source of truth but bodies don't mirror it.
- **ADV-P1-013** — S-3.02 `traces_to` / `behavioral_contracts`
  field-semantics inconsistency.
- **ADV-P1-017** — `tests/snapshot.rs` hot-file serialization now
  captured in Serialization Plan, but the per-detector split alternative
  is not promoted to a story.
- **ADV-P1-021** — S-1.03 AC-005 IPv6 default direction now pre-declared
  (option b, IPv4-only) after reading `src/cli.rs:195–204`. Confirmed.

NITPICK-class items (ADV-P1-013, 014, 018, 019, 020, 022) are deferred
to maintenance sweep.

## Real-world action backlog (independent of whether we continue VSDD)

(carried forward from Phase 1 STATE.md — unchanged)

## Next step in the methodology

Human approval gate. After approval:

1. Consider running a second adversarial pass to validate the BLOCKING
   fixes and surface anything Pass 1 missed (recommended before
   story-writer dispatch).
2. `/vsdd-factory:phase-3-tdd-implementation` — begin Wave 1 dispatch.
   Honour the Serialization Plan in `.factory/stories/dependency-graph.md`
   for the 4 hot files.

## Phase 3 delivery log

| Story | PR | Merge SHA | Merged At | AC Status |
|---|---|---|---|---|
| S-3.06 macOS CI flake fix | #66 | e425733 | 2026-05-15T17:12:47Z | AC-001/003 PASS; AC-002 1/5 (deferred) |
| S-2.02 Cap cred_events dedup (BC-1.03.007) | #67 | 19ee8b0 | 2026-05-15T18:41:00Z | 170/170 tests pass; 3 NITPICKs deferred (cosmetic) |
| S-2.05 `creds.ldap_simple_bind` (BC-1.03.005 + BC-3.01.005) | #68 | 31e827b | 2026-05-18T20:58:12Z | 5 NITPICKs logged (non-blocking); BCs registered at 03226af |
| S-2.06 `compat.ntlmv1` (BC-1.03.006 + BC-3.04.004) | #69 | 317a575 | 2026-05-18T21:31:15Z | APPROVE cycle 1, NITPICK_ONLY; F-002/F-003/F-005 deferred; BCs registered at 0c5bcd6; red-gate at df40937 |
| S-2.07 `compat.weak_tls_cipher` (BC-1.04.003 + BC-3.04.005) | #70 | a866578 | 2026-05-18T23:58:12Z | APPROVE cycle 1, 1 NITPICK (trigger text wording, non-blocking); BCs registered at 4a0150c; red-gate at 8b19f57 |
| S-2.08 `creds.rdp_no_nla` (BC-1.04.004 + BC-3.04.006) | #71 | 387b239 | 2026-05-19T15:02:50Z | APPROVE cycle 1, 2 COSMETIC (stale doc comments rdp_legacy.rs:4,:62 ref AC-002 bit-test, non-blocking); BCs registered at ad7a5a2; red-gate at 48f81e8 |
| S-2.11 `ics.modbus_unit_id_sweep` (BC-1.02.009 + BC-3.03.006) | #72 | 238466b | 2026-05-19T15:39:57Z | APPROVE cycle 1, 1 NITPICK (stale internal doc comment on ModbusFlowSummary, non-blocking); BCs registered at 54d547d + ordering-fix c650b15; red-gate at 9f3edaa. BC renumbered BC-1.02.006→BC-1.02.009 (collision with DHCP option walk). **Wave 1 complete — 32/32 stories done. Next: `/wave-gate wave-1`.** |
| S-5.01 parse-loop progress feedback (BC-9.04.001) | #73 | 7556939 | 2026-05-19T16:17:44Z | APPROVE cycle 1, 2 NITPICKs deferred (stale `#[allow(unused_imports)]` in src/pcap.rs; doc-comment nit on analyze() type-parameter genericity); BC registered at 053edef; red-gate at 2dbb7d5 |
| S-5.02 Claude invocation heartbeat (BC-6.04.001) | #74 | 62c937d | 2026-05-19T16:44:25Z | APPROVE cycle 2; cycle 1 had 2 findings fixed in 7f80af0 (stale scaffold doc removal, narrowed verbose field visibility), 1 accepted, 1 F-004 retracted as false-positive; BC registered at 60b79c8; red-gate at d60beed |
| S-5.07 per-finding card collapsibility (BC-8.01.005) | #75 | 84b0489 | 2026-05-19T17:42:02Z | APPROVE cycle 1, 0 findings; template-only HTML change (<div> → <details open>); BC registered at a74d846; red-gate at f850cc1 |
| S-6.01 scrub map merge (BC-5.03.001) | #76 | 896c9e2 | 2026-05-19T18:12:08Z | CLEAN security verdict; converged in 1 cycle; BC registered at b4586f1; red-gate at eb050f7. One mid-PR fmt fix (f049191) — rustfmt 1.9.0 single-line collapse vs CI two-line expectation. |
| S-3.05 codecov coverage reporting (BC-build.001 informal) | #77 | 51a3faf | 2026-05-19T18:32:29Z | APPROVE cycle 1, 0 findings, CLEAN security verdict; red-gate at 8789cd1. AC-006 (badge URL resolves) deferred to post-merge manual verification. |

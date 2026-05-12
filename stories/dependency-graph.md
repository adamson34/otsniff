---
document_type: dependency-graph
project: otsniff
phase: 2
generated: 2026-05-11T20:30:00Z
producer: phase-2-story-decomposition (inline)
total_stories: 34
status: draft
---

# Story Dependency Graph

Derived by inspecting the `depends_on` / `blocks` frontmatter field on
each `.factory/stories/S-*.md` file. Verified by hand for acyclicity:
no story depends (transitively) on a story it blocks.

## Dependency edges (story → prerequisite)

```
S-1.04 → ∅                                  (fix trigger string)
S-1.01 → ∅                                  (reconcile BC-AUDIT labels)
S-1.02 → ∅                                  (recount confidence summary)
S-1.03 → ∅                                  (PRD ASR fixes)
S-1.06 → ∅                                  (ADR backfill)
S-1.05 → S-1.01, S-1.02                     (formalize BC-AUDIT needs reconciled labels + clean counts)

S-2.01 → S-1.04                             (port-to-label test depends on the trigger fix landing first to avoid drift)
S-2.02 → ∅                                  (cred_events cap)
S-2.03 → ∅                                  (OUI table refresh)
S-2.04 → ∅                                  (DNP3 parser)
S-2.05 → ∅                                  (creds.ldap_simple_bind)
S-2.06 → ∅                                  (compat.ntlmv1)
S-2.07 → ∅                                  (compat.weak_tls_cipher)
S-2.08 → ∅                                  (creds.rdp_no_nla)
S-2.09 → ∅                                  (boundary.ntp_external)
S-2.10 → ∅                                  (recon.port_scan)
S-2.11 → ∅                                  (ics.modbus_unit_id_sweep)

S-3.01 → ∅                                  (criterion benches + perf CI — depends on no other story)
S-3.02 → ∅                                  (prompt eval harness)
S-3.03 → S-3.01                             (mutation testing prefers a measured baseline so the slow CI's signal isn't lost in perf noise)
S-3.04 → S-2.04                             (fuzz harness includes DNP3; lands after DNP3 parser)

S-4.01 → ∅                                  (Kani scrub round-trip)
S-4.02 → ∅                                  (Kani leak-detector regex)
S-4.03 → ∅                                  (Kani map-value substring)
S-4.04 → S-4.01, S-4.02, S-4.03             (composed proof)

S-5.01 → ∅                                  (parse progress)
S-5.02 → ∅                                  (claude heartbeat)
S-5.03 → S-2.05, S-2.06, S-2.07             (AI-augmented findings anchors on richer rule set — only the three named detectors are hard prerequisites; S-2.08..2.11 are soft preferences not graph edges)
S-5.04 → ∅                                  (harden --ai invocation: --disallowed-tools + --review-scrub; defense-in-depth, no deps)
S-5.05 → ∅                                  (report HTML visual polish; touches only templates/report.html + tests/snapshots/*.snap)
S-5.06 → S-5.05                             (apply brand handoff; supersedes S-5.05's freehand SVG + token names; touches templates/report.html + media/*.svg + README.md + tests/snapshots/*.snap)

S-6.01 → ∅                                  (scrub map merge)
S-6.02 → S-6.01                             (diff core needs merged maps)
S-6.03 → S-6.02                             (diff renderer needs diff core)
```

## Acyclicity check

Topological sort: every story with `depends_on: []` is a source. After
removing sources, the remaining graph still has sources (verified by
tabletop walk below). No story appears in any cycle.

**Walk:**

- Sources (depends_on=∅, level 0):
  S-1.01, S-1.02, S-1.03, S-1.04, S-1.06,
  S-2.02, S-2.03, S-2.04, S-2.05, S-2.06, S-2.07, S-2.08,
  S-2.09, S-2.10, S-2.11,
  S-3.01, S-3.02, S-4.01, S-4.02, S-4.03,
  S-5.01, S-5.02, S-6.01
  (23 stories)

- Level 1 (depend only on level 0):
  S-1.05 (deps: S-1.01, S-1.02)
  S-2.01 (deps: S-1.04)
  S-3.03 (deps: S-3.01)
  S-3.04 (deps: S-2.04)
  S-4.04 (deps: S-4.01, S-4.02, S-4.03)
  S-6.02 (deps: S-6.01)
  (6 stories)

- Level 2 (depend on level ≤ 1):
  S-5.03 (deps: S-2.05..2.11 — all level 0)
  S-6.03 (deps: S-6.02 — level 1)
  (2 stories — but S-5.03 is actually level 1 since all S-2.x deps are level 0; we place S-5.03 in Wave 3 anyway for a separate reason: it consumes the most context and benefits from waiting until the detection layer is fully shipped, including snapshot-tested integration)

Total: 26 + 6 + 2 = 34 stories — all uniquely placed. (S-5.04, S-5.05, S-5.06 all added 2026-05-12 mid-cycle.)

**Result: no cycle.**

## Independent execution groups (wave inputs)

These are the candidate parallelism units that Step D uses to assign
waves. Each group is a maximal set of stories with no inter-group edge.

### Group α — spec hygiene (E-1)
- S-1.01, S-1.02, S-1.03, S-1.04, S-1.06 (parallel within group)
- S-1.05 (after S-1.01 + S-1.02)

### Group β — detection rules (E-2)
- All of S-2.02..S-2.11 (parallel within group; mostly independent files)
- S-2.01 (after S-1.04)

### Group γ — perf/robustness (E-3)
- S-3.01, S-3.02 (parallel)
- S-3.03 (after S-3.01)
- S-3.04 (after S-2.04)

### Group δ — Kani proofs (E-4)
- S-4.01, S-4.02, S-4.03 (parallel)
- S-4.04 (after all three)

### Group ε — UX + augmented findings (E-5)
- S-5.01, S-5.02 (parallel, independent of everything)
- S-5.03 (after S-2.05..S-2.11)

### Group ζ — diff (E-6)
- S-6.01 → S-6.02 → S-6.03 (strict chain)

## Cross-group light couplings (not hard deps)

- S-1.05 (formalize BC-AUDIT) soft-affects most E-2 stories — they
  reference BC-AUDIT-* IDs that will be renamed. Mitigation: E-2
  stories cite both `BC-AUDIT-NNN` and the proposed new IDs in
  comments; story-writer updates after S-1.05 lands.
- S-2.04 (DNP3 parser) is referenced by S-3.04 (fuzz). Hard dep
  expressed.
- S-3.01 (criterion benches) baseline is referenced by S-3.03 (mutants
  triage). Hard dep expressed.
- S-6.01..S-6.03 share no files with other epics. Cleanest decoupling.

## Subsystem touch matrix

| Story | S.0 | S.1 | S.2 | S.3 | S.4 | S.5 | S.6 | S.7 | S.8 | S.9 | docs/build |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| S-1.01 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-1.02 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-1.03 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-1.04 |  |  |  | ✓ |  |  |  |  |  |  | ✓ |
| S-1.05 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-1.06 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-2.01 |  |  |  | ✓ |  |  |  |  |  |  |  |
| S-2.02 |  | ✓ |  |  |  |  |  |  |  |  |  |
| S-2.03 |  |  | ✓ |  |  |  |  |  |  |  |  |
| S-2.04 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-2.05 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-2.06 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-2.07 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-2.08 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-2.09 |  |  |  | ✓ |  |  |  |  |  |  |  |
| S-2.10 |  |  |  | ✓ |  |  |  |  |  |  |  |
| S-2.11 |  | ✓ |  | ✓ |  |  |  |  |  |  |  |
| S-3.01 | ✓ | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |
| S-3.02 |  |  |  |  |  |  | ✓ |  |  |  |  |
| S-3.03 |  |  |  |  |  |  |  |  |  |  | ✓ |
| S-3.04 |  | ✓ |  |  |  | ✓ |  |  |  |  |  |
| S-4.01 |  |  |  |  |  | ✓ |  |  |  |  |  |
| S-4.02 |  |  |  |  |  | ✓ |  |  |  |  |  |
| S-4.03 |  |  |  |  |  | ✓ |  |  |  |  |  |
| S-4.04 |  |  |  |  |  | ✓ |  |  |  |  |  |
| S-5.01 | ✓ |  |  |  |  |  |  |  |  | ✓ |  |
| S-5.02 |  |  |  |  |  |  | ✓ |  |  |  |  |
| S-5.03 |  |  |  | ✓ |  |  | ✓ |  | ✓ |  |  |
| S-6.01 |  |  |  |  |  | ✓ |  |  |  | ✓ |  |
| S-6.02 |  |  |  | ✓ |  |  |  |  |  | ✓ |  |
| S-6.03 |  |  |  |  |  |  |  |  | ✓ |  |  |

Concurrent merges of two stories that both touch the same subsystem
share `src/<file>.rs` files. The wave scheduler should serialize within
a subsystem when possible.

## Risk callouts

- **S-2.x detector wave (10 stories) is very wide.** Each touches
  `src/findings/mod.rs` and `src/rule_catalog.rs`, and 8+ touch
  `tests/snapshot.rs`. Sequential serialization required on these
  three files. The orchestrator MUST run detector stories single-file
  for these three modules; see the explicit Serialization Plan below.
- **S-5.03 hard-depends on 3 stories (S-2.05..2.07).** Soft preference
  for S-2.08..2.11 to land too, but not a graph edge. Schedule in
  Wave 3 to let the E-2 wave settle.
- **Kani install (S-4.01..04) is a one-time toolchain hurdle.** First
  story in this group will eat that setup cost; subsequent ones benefit.

## Serialization Plan (binding)

The wave-scheduling implementation MUST honour these invariants:

1. **Wave ordering:** a story whose dependency is in a later wave is
   a configuration error and refuses to ship.
2. **Per-file serialization within a wave** — the following files are
   "hot": only one in-flight story may have an open edit at a time.
   Stories in the same wave that all touch a hot file are funneled
   through a single agent (one-after-another), not parallel agents.
   - `src/findings/mod.rs` (10 wave-1 stories)
   - `src/rule_catalog.rs` (10 wave-1 stories)
   - `src/observe.rs` (7 wave-1 stories)
   - `tests/snapshot.rs` (8+ wave-1 stories)
   - `docs/RULES.md` (auto-regenerated by 12 wave-1 stories: S-1.03,
     S-1.04, S-2.04..S-2.11)
   - `src/findings/engineering_commands.rs` (S-1.03 + S-1.04 both edit
     this file; S-2.04 may add a DNP3 sibling but not modify this one)
   - `src/audit.rs` (S-5.03 only — single-writer, listed for completeness)
3. **Snapshot-file split alternative:** if per-file serialization
   bottlenecks the wave, an implementer may split `tests/snapshot.rs`
   into per-detector files (e.g., `tests/snapshot_ldap.rs`) as a
   refactor first. This is allowed but not required.

The Step D scheduler enforces these.

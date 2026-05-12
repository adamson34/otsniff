---
document_type: wave-schedule
project: otsniff
cycle: v0.4.0-feature
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition (inline)
timestamp: 2026-05-11T20:40:00Z
phase: 2
inputs:
  - .factory/stories/STORY-INDEX.md
  - .factory/stories/dependency-graph.md
traces_to: .factory/stories/STORY-INDEX.md
---

# Wave Schedule — otsniff v0.4.0-feature cycle

Three waves total. Wave 1 carries the unblocked-from-the-start work
(23 stories). Wave 2 carries the level-1 dependents (6 stories).
Wave 3 carries the two stories deliberately delayed for richness
(S-5.03 augmented findings + S-6.03 diff renderer).

## Summary

| Metric | Value |
|--------|-------|
| Total stories | 33 |
| Total points | 111 |
| Total waves | 3 |
| Max parallelism (groups per wave) | 6 |
| Estimated agent spawns | ~30 (one per story + a few re-spins) |
| Critical path | S-6.01 → S-6.02 → S-6.03 (3 sequential stories, ~9 days wall). Comparable: S-2.05/06/07 → S-5.03 (3-fan-in then 1 story, ~8 days wall). |

## Wave Plan

### Wave 1 — foundation (no dependencies, depth-0 work)

| Group | Stories | Points | Complexity | Subsystems | Agent Scope |
|-------|---------|--------|-----------|----------|-------------|
| 1-A spec-cleanup | S-1.01, S-1.02, S-1.03, S-1.04, S-1.06 | 1+1+5+1+3 = 11 | S–M | docs/findings | 5 stories — 1 agent per |
| 1-B detection-rules | S-2.02, S-2.03, S-2.04, S-2.05, S-2.06, S-2.07, S-2.08, S-2.09, S-2.10, S-2.11 | 2+2+5+3+3+2+3+2+3+3 = 28 | M-L | parse + findings | 10 stories — must serialize edits to `findings/mod.rs` + `rule_catalog.rs` |
| 1-C perf-bootstrap | S-3.01, S-3.02 | 3+5 = 8 | M | benches + ai | 2 stories |
| 1-D kani | S-4.01, S-4.02, S-4.03 | 5+5+3 = 13 | L | scrub + ai | 3 stories (one-time Kani install in first one) |
| 1-E ux | S-5.01, S-5.02, S-5.04, S-5.05 | 2+2+3+2 = 9 | S–M | pcap + ai + cli + render | 4 stories (S-5.04, S-5.05 added mid-cycle 2026-05-12) |
| 1-F diff-foundation | S-6.01 | 5 | M | scrub | 1 story |

Wave 1 total: 24 stories, ~72 points. Maximum sensible parallelism
limited by:

- **Hot-file serialization** within group 1-B — single-agent in-flight
  edits required on `src/findings/mod.rs`, `src/rule_catalog.rs`,
  `src/observe.rs`, and `tests/snapshot.rs`. See dependency-graph.md
  Serialization Plan.
- Kani toolchain install once before group 1-D fans out
- Otherwise groups are independent

### Wave 2 — level-1 dependents

| Group | Stories | Points | Complexity | Subsystems | Agent Scope |
|-------|---------|--------|-----------|----------|-------------|
| 2-A spec-formalize | S-1.05 (after 1.01 + 1.02) | 3 | M | docs | 1 story |
| 2-B detection-test | S-2.01 (after 1.04) | 1 | S | findings | 1 story |
| 2-C robust-after-perf | S-3.03 (after 3.01) | 5 | L | tooling | 1 story |
| 2-D fuzz-after-dnp3 | S-3.04 (after 2.04) | 5 | L | parse | 1 story |
| 2-E kani-composed | S-4.04 (after 4.01 + 4.02 + 4.03) | 5 | L | scrub | 1 story |
| 2-F diff-core | S-6.02 (after 6.01) | 5 | M | diff + cli | 1 story |

Wave 2 total: 6 stories, ~24 points. All independent of each other within
this wave (different files / different epics). Full parallelism possible.

### Wave 3 — high-context dependents

| Group | Stories | Points | Complexity | Subsystems | Agent Scope |
|-------|---------|--------|-----------|----------|-------------|
| 3-A augmented-ai | S-5.03 (after all S-2.05..2.11) | 8 | XL | findings + ai + render | 1 story |
| 3-B diff-render | S-6.03 (after 6.02) | 5 | L | render | 1 story |

Wave 3 total: 2 stories, ~13 points. Independent of each other.

## Pipeline Overlap Plan

| Parallel Activity | When |
|------------------|------|
| Wave 2 spec-formalize (S-1.05) | Can start the moment S-1.01 + S-1.02 merge — does not need Wave 1 to fully complete |
| Wave 2 fuzz (S-3.04) | Can start the moment S-2.04 (DNP3) merges, even while other Wave 1 detector stories are mid-flight |
| Wave 3 augmented-ai (S-5.03) | Can start as soon as the *majority* of S-2.x merges; not all seven are strictly required, but a strong context anchor is |
| Wave 3 diff-render (S-6.03) | Can start when S-6.02 merges |

## Critical Path

The longest dependency chain is the diff feature:

```
S-6.01 (5 pts) → S-6.02 (5 pts) → S-6.03 (5 pts)
                 ── 15 points, ~9 days wall ──
```

No other chain in this backlog has more than 2 hops. The
adversarial-review iterations may extend this in practice, but the
dependency graph itself has only this 3-hop chain.

## Wave-gate criteria

A wave is "shippable" when:

- Every story in the wave has merged to develop
- Full test suite (`cargo test --all-features`) is green
- All snapshot tests are accepted (no pending insta diffs)
- For Wave 1: `cargo run -- rules > docs/RULES.md` produces no diff
  (sanity check that detector-wave stories regenerated RULES.md)
- For Wave 2: Kani composed proof (S-4.04) passes on a tagged commit
- For Wave 3: AI-augmented findings produces non-empty output on a
  reference fixture (smoke); diff renders without panic on a synthetic
  pair

## Risks

- **Wave 1 group 1-B serialization** — 10 stories all touching
  `src/findings/mod.rs` and `src/rule_catalog.rs`, 7 touching
  `src/observe.rs`, 8+ touching `tests/snapshot.rs`. Hot-file
  serialization is enforced via the dependency-graph.md Serialization
  Plan; the orchestrator MUST route these stories single-agent-per-file
  to avoid conflicts.
- **Kani install time** — first Kani story (group 1-D) will spend hours
  on the install + first proof iteration. Schedule it early.
- **S-5.03 context budget** — the AI-augmented findings story touches
  4 subsystems and 3 hard-dep prerequisite stories (S-2.05..2.07). May
  need to be split if the implementer agent exceeds its budget.
  Pre-flight check recommended after Wave 1 lands.

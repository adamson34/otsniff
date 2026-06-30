---
document_type: holdout-scenario-index
project: otsniff
cycle: v0.4.0-feature
phase: 2
generated: 2026-05-11T20:50:00Z
producer: phase-2-story-decomposition (inline)
total_scenarios: 11
status: draft
---

# Holdout Scenario Index — otsniff v0.4.0-feature

> **WARNING:** This index points at files in
> `.factory/holdout-scenarios/` that must NEVER be shown to the
> implementer or test-writer agents. Information asymmetry between
> builder and evaluator is the core quality mechanism.

## Coverage

| HS ID | Wave | Epic | Category | Must-Pass | Title |
|-------|:---:|:---:|---|:---:|---|
| HS-001 | 1 | E-1 | behavioral-subtleties | yes | Unexpected-protocols rule fires on every documented label |
| HS-002 | 1 | E-2 | integration-boundaries | yes | Every new Wave-1 detector appears in catalog and fires once |
| HS-003 | 1 | E-2 | security-probes | yes | Privacy invariant survives all new Wave-1 extractor surfaces |
| HS-004 | 1 | E-1 | ci-integration | yes | Spec hygiene leaves no broken BC reference |
| HS-005 | 2 | E-4 | security-probes | yes | Kani composed privacy-invariant proof actually converges |
| HS-006 | 2 | E-3 | edge-case-combinations | yes | 60-second fuzz of every parser produces no panics |
| HS-007 | 3 | E-5 | behavioral-subtleties | yes | AI-augmented findings dedupe against rule findings |
| HS-008 | 3 | E-6 | behavioral-subtleties | yes | `otsniff diff` reports an unchanged host as unchanged |
| HS-009 | 1 | E-5 | edge-case-combinations | should | Progress + heartbeat output never contains real identifiers |
| HS-010 | 2 | E-9 | integration-boundaries | yes | Multi-PCAP analyze unions captures, guards link types, attributes per file (v0.6.0) |
| HS-011 | 3 | E-10 | edge-case-combinations | yes | Capture-sanity warning fires on degenerate timestamps, silent on sane (v0.6.0) |

## Per-wave summary

| Wave | Scenarios | Must-pass | Should-pass |
|:---:|:---:|:---:|:---:|
| 1 | 5 (HS-001..004 + 009) | 4 | 1 |
| 2 | 2 (HS-005, HS-006) | 2 | 0 |
| 3 | 2 (HS-007, HS-008) | 2 | 0 |
| **Total** | **9** | **8** | **1** |

## Critical-path BC coverage

| Critical BC | Holdout scenario(s) |
|---|---|
| BC-3.05.002 (unexpected_protocols trigger) | HS-001 |
| BC-3.06.002/003 (catalog completeness + playbook) | HS-002 |
| BC-5.02.003 (privacy invariant — composed) | HS-003, HS-005 |
| BC-6.05.003 (augmented-finding dedup) | HS-007 |
| BC-5.03.001 (stable pseudonyms) | HS-008 |
| BC-9.04.001 / BC-6.04.001 (progress + heartbeat) | HS-009 |
| BC-0.01.002 (reject non-PCAP) | HS-006 |
| BC-1.01.003/004 + BC-7.01.005 (multi-PCAP ingest, link guard, audit attribution) | HS-010 |
| BC-4.01.004/005 (capture-window sanity detection + surfacing) | HS-011 |

## Categorical distribution

| Category | Scenarios |
|---|:---:|
| behavioral-subtleties | 3 (HS-001, HS-007, HS-008) |
| security-probes | 2 (HS-003, HS-005) |
| edge-case-combinations | 2 (HS-006, HS-009) |
| integration-boundaries | 2 (HS-002, HS-010) |
| ci-integration | 1 (HS-004) |

## Implementation walls

| Wall enforced by | What it hides |
|---|---|
| Lobster `exclude: .factory/holdout-scenarios/**` rule | Implementer + test-writer never see this directory |
| `git update-index --skip-worktree` on holdout files | Optional belt-and-suspenders for local agents |
| Adversary review `exclude: .factory/holdout-scenarios/**` | Adversary also blind to holdouts |

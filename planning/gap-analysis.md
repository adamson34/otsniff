---
artifact: gap-analysis
phase: pre-1
generated: 2026-05-11T18:55:00Z
mode: brownfield
---

# Gap analysis — otsniff against VSDD artifact hierarchy

## Readiness classification

**L0 — strictly, by VSDD format.** Zero VSDD-format artifacts exist.

**L1+ — functionally, ignoring format.** The project has substantive
documentation that maps to most VSDD artifact roles, but in otsniff's
own format (ADRs + per-feature specs + audit) rather than VSDD's
`BC-S.SS.NNN` hierarchy.

This is the brownfield-ingestion situation the methodology
contemplates: a shipped product with its own documentation lineage
that needs to be retrofitted into the VSDD artifact chain — not
because the existing docs are bad, but because the methodology's
agents need their canonical inputs to operate.

## Gap table

| Artifact | Status | Gap |
|---|---|---|
| Product Brief (L1) | INCOMPLETE | CLAUDE.md covers product vision, scope, conventions, and design contract in narrative form. Missing: explicit "users" section, success criteria with measurable targets, structured constraint list. Would synthesize cleanly from CLAUDE.md + README. |
| Domain Spec (L2) | MISSING | No formal domain model. Implicit in `src/observe.rs::Observations` (the typed accumulator that carries hosts, flows, events, etc.) and `src/findings/mod.rs` (the Finding / Severity / RuleMetadata types). Would extract from the type graph. |
| PRD | INCOMPLETE | docs/ROADMAP.md contains shipped + planned scope but uses P0/P1/P2 priority bands rather than numbered FR-NNN / NFR-NNN. No edge-case catalog. No bloat — well under context budget. Migration: re-shape roadmap items as numbered functional requirements. |
| Behavioral Contracts (L3) | PARTIAL | docs/RULES.md is the de-facto BC list for detection — 12 detectors each with trigger condition, data source, references. Maps cleanly to BC-S.SS.NNN if we treat findings as the L3 surface. Other code paths (scrub, leak detector, observer, parsers) have no formal BC. |
| Verification Properties (L4) | PARTIAL | The privacy invariant is the project's biggest verification claim. It's enforced by `src/ai/leak_detector.rs` and tested by `invariant_no_real_values_reach_ai_provider`. The CIP-011 audit (`docs/audits/scrub-audit-cip011.md`) is a formal verification artifact in spirit. No VP-NNN numbering, no Kani proofs (Phase 6 work). |
| Architecture | PARTIAL | 7 ADRs cover key decisions. CLAUDE.md has a component map (`src/` tree with one-line descriptions per module). Missing: sharded `ARCH-INDEX.md`, machine-readable architecture map, purity-boundary map (informally documented in CLAUDE.md but not as a separate artifact), verification coverage matrix. |
| Architecture Feasibility | MISSING | No formal feasibility report. Implicit: the code exists and ships, which is the strongest possible feasibility evidence. |
| UX Spec | N/A | CLI tool, no UI. UX surface is the help text + report formatting. |
| Epics / Stories | MISSING | Roadmap items are at epic level. No story decomposition with acceptance criteria. The shipped PRs (#26–#42) function as historical stories with embedded acceptance criteria (test plans). |
| Holdout scenarios | MISSING | Test suite has sentinel tests (every-finding-has-a-playbook, audit-log-no-real-identifiers, AI-section-strips-script) that are conceptually adjacent. No information-asymmetric holdout evaluation set. |
| Adversarial reviews | MISSING | Have done informal pressure-testing in-session (the "is this legit or dumb?" analyses) but no formal multi-pass review with novelty decay. |

## Severity summary

- **Format-only gaps (most of the table).** Content exists; format
  doesn't match VSDD. Fixing is mostly mechanical re-shaping.
- **Structural gaps (Holdout scenarios, formal adversarial review).**
  Real new work — the project doesn't have these in any form.
- **Phase-6 prerequisites (Kani proofs, mutation, fuzz).** Not yet
  installed; deferred until Phase 6 is actually invoked.

## What's NOT a gap

- **Test coverage.** 100 tests across unit + CLI + snapshot. Already
  exceeds what most projects entering VSDD have.
- **Public release artifacts.** Two stable releases (v0.3.0, v0.3.1)
  with curl-pipe-sh installer. Cross-platform binaries built in CI.
- **Privacy contract.** Fail-closed leak detector with two layers
  (regex + map-value), sentinel-tested, audit-logged. The project's
  load-bearing security claim is enforced by code, not convention.
- **CI quality gates.** Format, clippy, test (Linux + macOS), MSRV,
  cargo-deny. Branch protection on main + develop. Required PRs.

These are typically Phase-6/Phase-3 outputs in VSDD's sequencing;
otsniff already has them.

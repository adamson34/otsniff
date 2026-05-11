---
artifact: routing-decision
phase: pre-1
generated: 2026-05-11T18:55:00Z
mode: brownfield
selected_entry: phase-0-codebase-ingestion
---

# Routing decision — otsniff

## Recommended entry point

**Phase 0: Brownfield codebase ingestion.**

`/vsdd-factory:phase-0-codebase-ingestion` (or the lower-level
`/vsdd-factory:brownfield-ingest .`).

## Why this is the right route

The strict VSDD readiness ladder puts us at **L0** because zero
VSDD-format artifacts exist. The literal L0 route is "Collaborative
Discovery — brainstorming or guided brief creation." That route
assumes the project doesn't exist yet.

That doesn't fit otsniff. The project is shipped (v0.3.1 publicly
released), has substantial non-VSDD documentation (7 ADRs, 9
per-feature specs, formal CIP-011 audit, ~3K LoC of working code
with 100 tests), and the goal stated by the user is **to learn the
VSDD methodology against an existing codebase**, not to redesign
otsniff from a blank slate.

Phase 0 is the correct entry for this shape: "Analyze an existing
codebase using the broad-then-converge analysis protocol. 6 broad
passes, then iterative deepening on every pass until novelty decays
to LOW. Produces a complete semantic understanding that feeds into
spec crystallization."

## Expected output of Phase 0

The brownfield-ingest skill will produce:

- Per-pass analysis docs (one per broad pass, capturing what was
  learned)
- Synthesis doc combining the passes into a unified codebase model
- Lessons / surprises log
- Validated extraction (behavioral + metric checks against the
  source)

These outputs then feed Phase 1 (spec crystallization), which will
**retrospectively** generate the VSDD-format artifacts (PRD, BCs,
VPs, ARCH-INDEX) from the existing code. The migration is mechanical
re-shaping of content that already exists.

## Alternative routes considered and rejected

1. **L0 → Collaborative Discovery.** Wrong — would treat otsniff as a
   greenfield concept, ignoring the shipped code and existing docs.
2. **Skip to Phase 1 spec crystallization directly.** Wrong — the
   spec crystallization agents expect inputs (brief, codebase ingest
   output) that we don't have yet. Doing Phase 0 first produces the
   bridge.
3. **Skip the methodology and just adopt Phase 6 tooling (Kani,
   fuzz, mutants).** Defensible alternative — these are the
   highest-value vsdd-factory pieces for otsniff specifically. But
   user's stated goal is learning the full methodology, not
   cherry-picking pieces. So Phase 0 first.

## Caveats for the human

- **Brownfield ingestion will produce a lot of artifacts** for a
  ~3K-LoC codebase. Per-pass docs, synthesis, lessons. For a project
  this size, the artifacts may exceed the code's own line count by
  3-5×. That's expected; the point is to see the shape of the
  methodology, not to produce production-grade traceability for a
  small CLI.
- **Existing ADRs and specs will be referenced as inputs** but not
  used as canonical sources. Phase 1 will produce new artifacts in
  VSDD format; the old docs stay in `docs/` for human readers but
  are not the methodology's source of truth going forward.
- **Decision point at end of Phase 0:** decide whether to continue
  the full pipeline (Phase 1 → 2 → 3 → 4 → 5 → 6 → 7) or stop here
  and just keep the ingestion artifacts as reference. The full
  pipeline retrofits a project this size with significant overhead
  for marginal practical benefit; the ingestion alone is high-value
  for understanding the methodology's shape.

## Next command

```
/vsdd-factory:phase-0-codebase-ingestion
```

Or equivalently the lower-level skill directly:

```
/vsdd-factory:brownfield-ingest .
```

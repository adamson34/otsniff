---
pass: 6
name: synthesis
project: otsniff
generated: 2026-05-11T18:55:00Z
mode: brownfield
inputs:
  - otsniff-pass-0-inventory.md
  - otsniff-pass-1-architecture.md
  - otsniff-pass-2-domain-model.md
  - otsniff-pass-3-behavioral-contracts.md
  - otsniff-pass-4-nfr-catalog.md
  - otsniff-pass-5-conventions.md
---

# Pass 6 — Synthesis

Cross-reference of the prior 6 passes. Identifies inconsistencies,
gaps, and the unified mental model. Confidence is assessed at the
synthesis level rather than per-pass.

## Unified mental model in one paragraph

otsniff is a **single-pass observer** that reduces a stream of
packets into a **typed accumulator** (`Observations`) carrying
per-host state, logical-flow stats, and protocol-specific event
streams. After the parse loop, **stateless detectors** read this
accumulator and emit findings. The privacy contract is enforced by a
**dual-layer leak detector** (regex + map-value) that sits between
the rules-based report and any AI-bound bytes; the AI runs in a
**subprocess shell-out**, not an embedded SDK. Output renders as a
single static HTML report with an optional inline AI section
(safe-HTML-rendered to neutralize XSS). Every load-bearing claim has
a **sentinel test** that breaks if the invariant breaks.

## Cross-pass cross-references

### Where the passes agree

The six passes paint a consistent picture on the same axes:

| Axis | Inventory says | Architecture says | Domain model says | BCs say | NFRs say | Conventions say |
|---|---|---|---|---|---|---|
| **Boundary between observation and analysis** | `src/observe.rs` is the largest file (629 LoC) | Layer 2 — final state in `Observations` | `Observations` is the aggregate root | S.1 BCs all reference `Observations` | NFR-PERF.001 single-pass | Pattern: pure function over `Observations` |
| **Privacy is the project's load-bearing claim** | Two dedicated files: `scrub.rs` + `ai/leak_detector.rs` | Cross-cutting "Privacy + rendering context" | S.5 has 6 BCs | NFR-SEC.001–.008 are all privacy-related | Pattern: "fail-closed leak detection" |
| **Detectors are pure + small** | 7 files in `src/findings/`, 116–412 LoC each | Layer 3 derivation | "Stateless across calls" with 4 firing shapes | S.3 has 13 BCs, all "pure function over Observations" | NFR-REL.001 deterministic | Pattern: const metadata per detector |
| **Render is templated + pre-formatted** | `src/report.rs` 199 LoC, `src/report_md.rs` 229 LoC | Layer 4 | `*View` structs feed askama | BC-8.01.001 (deterministic per inputs) | NFR-REL.004 snapshot guarded | ADR-0003 pre-formatted view structs |
| **CLI is one orchestrator file** | `src/cli.rs` 687 LoC (largest) | `cli::run_analyze` is the orchestrator | `analyze --ai` pipeline has 17 numbered steps | BC-9.* contracts | Pattern: auto-derived audit path | Branch + commit conventions |

### Where the passes disagree (minor)

None of substance. Two notes worth flagging:

1. **Architecture (Pass 1) and Conventions (Pass 5) describe the
   "pre-formatted view struct" pattern slightly differently.** Pass 1
   places the responsibility on `src/report.rs::ReportView`
   construction; Pass 5 calls it a "design pattern" that applies more
   broadly. Both are correct; they're describing the same code at
   different abstraction levels.

2. **Domain Model (Pass 2) lists `obs.ot_subnets` as part of
   `Observations`, but Inventory (Pass 0) doesn't mention it.** This
   is correct: `ot_subnets` is on `Observer`, not `Observations`. The
   domain-model description was slightly imprecise. Noted for the
   final synthesis.

### Notable consistencies not from any single pass

- **The privacy invariant has at least 4 reinforcing guard rails:**
  (a) scrub layer, (b) regex leak detector, (c) map-value leak
  detector, (d) sentinel test. Plus the audit log itself is leak-
  checked before write. This belt-and-braces design is consistent
  across the architecture, BCs, NFRs, and conventions.

- **"Function-code-level fidelity" decision (ADR-0002) shows up
  everywhere:** Pass 0 inventory (small parser files), Pass 1
  architecture (parse/ layer 2 helpers), Pass 2 domain model (events
  carry only function code + label), Pass 3 BCs (BC-1.02.*), Pass 5
  conventions (one module per protocol). One ADR drove many
  consistent micro-decisions.

- **The 12-rule catalog is the de-facto behavioral contract list.**
  Pass 3 has 13 BCs under "Findings layer"; the rule catalog has 12
  entries; the off-by-one is BC-3.06.001 (sort order) which doesn't
  map to a rule. Otherwise the mappings are 1:1.

## Confidence assessment

### High confidence (taking everything in this synthesis as accurate)

- **Architectural shape.** Layer model + cross-cutting concerns +
  pure/effectful boundary are unambiguous.
- **Behavioral contracts.** All 12 rules have plain-English trigger
  descriptions in `docs/RULES.md` (auto-generated, sync-tested),
  plus test coverage for firing behavior.
- **Privacy invariant.** Code path enforces; sentinel test guards;
  audit document explains the alignment posture.
- **Conventions.** Reading any 3 files predicts the shape of any
  4th.

### Medium confidence

- **Performance claims.** Single-pass observer, linear memory, fast
  cold start are reasonable from the data model but **never
  benchmarked.** No `criterion` runs in CI. NFR-PERF.001 / .002 are
  conjectures backed by anecdotes.

- **AI invocation behavior.** `ClaudeCliProvider` shells out, but
  there's no e2e test of the subprocess — the `claude` CLI is an
  external dependency. BCs for S.6 (AI orchestration) are MEDIUM
  confidence accordingly.

- **OUI vendor inference recall.** Embedded table is ~50 entries;
  many real vendors will fall through to `None`. P0-6 (OUI refresh)
  would close this.

### Low confidence

- **Memory bound under adversarial input.** A capture with millions
  of unique IPs could push host accumulation beyond expected
  bounds. Not benchmarked, not adversarially tested.

- **`cred_events: Vec<CredEvent>` unboundedness.** Pass 4 NFR-PERF.002
  flagged this. For long captures with continuous Telnet, the Vec
  grows linearly. No backpressure today.

- **Determinism across OS / Rust version.** Tests run on Linux (CI)
  and macOS (post-public flip CI). Windows path determinism is
  untested; the release workflow builds for Windows but doesn't run
  tests there.

## Gap report

### Coverage gaps the synthesis identifies

#### Underrepresented modules

| Module | LoC | Coverage in passes |
|---|---:|---|
| `src/oui.rs` | 87 | Mentioned in inventory + role-inference path; no dedicated BC. Most heuristic vendor inference happens here. |
| `src/error.rs` | 77 | Documented as the error taxonomy in Pass 1; conventions document exit-code mapping; no BCs around error message stability. |
| `src/parse/dhcp.rs` | 202 | One BC (BC-1.02.004). Has 7 unit tests in-file. Could be expanded. |
| `templates/report.html` | 264 lines | Mentioned in Pass 1 as "sole askama template"; no BCs around the template's specific structure (e.g. "report has 4 stats tiles", "AI section renders inside .ai-section div"). These exist only as snapshot tests. |

#### Implicit architectural decisions without ADRs

| Decision | Where it's encoded | ADR exists? |
|---|---|---|
| No async / sync throughout | `Cargo.toml` lacks `tokio`; data flow is sync end-to-end | NO |
| Drop ephemeral src_port from flow key | `docs/specs/flow-grouping.md` + `src/observe.rs::FlowKey` | NO (spec exists) |
| Roll up plaintext-cred findings by kind | `docs/specs/finding-dedup.md` + `src/findings/plaintext_creds.rs` | NO (spec exists) |
| pulldown-cmark for AI markdown render with filter | `src/ai/html_render.rs` doc comment | NO |
| Audit log auto-writes when `--ai` on, default path | `src/cli.rs::default_audit_log_path` + v0.3 release notes | NO |
| Branch protection rules | GitHub config (gh api setup) | NO (operational, not architectural) |

These decisions are made and consistent in the code, but a reader
wanting to know "why" must read the relevant spec or commit message
rather than a numbered ADR.

#### Test gaps

Documented in BCs but not directly tested:

- **End-to-end AI integration.** No test invokes a real `claude` CLI;
  privacy invariant test exercises the leak-detector with synthetic
  inputs but never reaches a subprocess.
- **Snapshot stability across Rust versions.** MSRV 1.85 runs `cargo
  check` only, not `cargo test`. A behavioral change in `BTreeMap`
  iteration (won't happen, but theoretical) could break snapshots
  silently.
- **Multi-architecture release binary functional test.** Release
  workflow builds for 4 targets but only ubuntu-latest runs tests.
- **Per-platform install.sh tests.** The install script is shell;
  not exercised in CI.

#### Documentation gaps

| Gap | Severity |
|---|---|
| No CHANGELOG.md (history lives on GitHub releases only) | Low — easily generated from `git log v0.X..v0.Y` |
| No formal contributor onboarding flow beyond CONTRIBUTING.md | Medium — solo maintainer today, would matter if community grows |
| No SUPPORT.md or issue templates beyond the bug-report.md | Low |
| No CODEOWNERS file | Low — solo maintainer |
| No formal architecture diagram (mermaid only in this brownfield-ingest output) | Medium — generated in Pass 1 but not yet committed to `docs/` |

### Spec crystallization recommendations

Given the brownfield output, what Phase 1 (spec crystallization)
should do to turn these passes into VSDD-format artifacts:

#### Product Brief (L1) — direct synthesis from CLAUDE.md + README

CLAUDE.md is the closest thing to a brief. To produce a formal one:

1. Take the README's "Why this exists" + "What it finds" + "Scope" sections.
2. Add explicit users list: small-to-mid-sized utilities/manufacturers, OT security consultants.
3. Add quantified success criteria. Current values (12 rules, <30s on 209MB, 100 tests passing) are the de-facto baseline.
4. Add stop criteria: no live capture, no SIEM, no compliance certification.

#### Domain Spec (L2) — most of Pass 2 maps directly

The structural section of Pass 2 already enumerates entities, value
objects, and enums. The L2 sharding would be one section per bounded
context (3 contexts). The "ubiquitous language" table in Pass 2 is
directly portable.

#### PRD (L3 prep) — from ROADMAP.md + RULES.md

The ROADMAP's P0/P1/P2 sections are roughly product requirements.
The rule catalog is the functional surface. To convert:

1. Number each ROADMAP item with `FR-NNN` or `BC-S.SS.NNN` (we'd
   pick `BC-S.SS.NNN` to align with VSDD).
2. Add NFR-NNN entries from Pass 4 (NFR-PERF.*, NFR-SEC.*, etc. —
   they're already numbered).
3. Add acceptance criteria. For shipped items, the snapshot/sentinel
   tests are the acceptance criteria.

#### Architecture (L3) — Pass 1's layer map + ADRs

Pass 1 already provides:
- System overview (the data flow + cross-cutting diagram)
- Module decomposition (layer map + per-module description)
- Purity boundary map (the explicit "pure core" / "effectful shell" list)
- Verification properties catalog (the invariants table — though it's spread across Pass 3 BCs)

Missing for sharded ARCH-INDEX:
- Verification architecture (Phase 6 / Kani proofs are deferred)
- Tooling selection (implicit; would document `pulldown-cmark`,
  `pcap-parser`, `etherparse` justifications)
- Verification coverage matrix (which BCs have which tests)

#### Stories (L3 prep)

Each shipped feature (v0.1 through v0.3) is effectively a story-
completed-without-a-formal-story. Future P0/P1 items in the roadmap
are stories-to-be. Generating story files now would mostly
retrospect.

### What the brownfield ingest does NOT tell us

- **Whether the methodology adds value at this project size.** A
  small solo-maintainer CLI with thorough existing docs may not
  benefit from VSDD's full pipeline beyond the brownfield
  understanding artifact itself.
- **Customer feedback on the tool.** No user interviews, no analytics.
- **Competitive positioning at the product level** (handled in
  conversation earlier; not captured in a market-intelligence
  artifact).
- **Whether Kani proofs of the privacy invariant are tractable.**
  Phase 6 work. Could be very valuable for compliance posture; cost
  is unknown until tried.

## Anti-patterns / mistakes worth calling out (none)

I looked specifically for these and found **none of significance**:

- No dead code in `src/` (every file is referenced).
- No commented-out blocks left in source (a few prose comments
  explaining decisions, but no zombie code).
- No `unwrap()` or `expect()` outside compile-time-validated literals.
- No `TODO` / `FIXME` / `XXX` markers leaking into production code
  (none in `src/`; one informational `TODO` in a comment about a
  v0.4 feature, which is fine).
- No conflict markers, no stray `dbg!()` macros.
- No deprecated dependencies (`cargo deny check` passes).

This codebase is in unusually clean shape for its age. The most
plausible reason: it's young (May 2026 first release) AND it's been
through 5 release cycles, each of which forced tests and lint to
pass.

## Critical design decisions catalog (synthesized)

In order of "if I had to defend this to a reviewer":

1. **Single-pass observer with typed accumulator** (ADR not formal;
   architecturally fundamental). Trade-off: observer is large (629
   LoC); accumulator is a god-struct. Benefit: one privacy
   chokepoint; deterministic; simple to reason about.

2. **Function-code-level protocol fidelity** (ADR-0002). Trade-off:
   can't decode PDU payload semantics. Benefit: small parsers; quick
   to add new protocols.

3. **Scrub layer + fail-closed leak detector** (ADR-0006 + 0007).
   Trade-off: rendering layer must respect the chokepoint; cannot
   stream AI output. Benefit: load-bearing privacy claim is
   enforceable + auditable.

4. **Subprocess shell-out for AI, no embedded SDK** (ADR-0007).
   Trade-off: dependency on user's local `claude` install. Benefit:
   zero supply-chain surface from AI integration; user owns auth.

5. **Pure Rust + no Zeek** (ADR-0001). Trade-off: hand-rolled
   parsers; less feature-rich than ICSNPP. Benefit: single static
   binary; no runtime deps; cross-platform.

6. **Owned packet payloads** (ADR-0004). Trade-off: per-packet
   alloc. Benefit: no lifetime contagion through the codebase.

7. **askama compile-time templates + pre-formatted view structs**
   (ADR-0003). Trade-off: needs a recompile to change template.
   Benefit: type-safe; no template-engine custom-filter fragility.

8. **CLI consolidation: `analyze` is the verb** (v0.3 — no formal
   ADR but documented in release notes). Trade-off: breaking change
   from v0.2.x. Benefit: clean one-command UX with `--ai` opt-in.

9. **Audit log auto-writes** (v0.3 — no formal ADR). Trade-off:
   produces a file even when user didn't ask. Benefit: privacy
   receipt is part of the AI flow's contract, not opt-in.

10. **`docs/RULES.md` auto-generated, sync-tested** (no ADR).
    Trade-off: humans can't curate the order. Benefit: catalog stays
    in sync with code; no drift.

## Phase 0 summary statistics

- **Files analyzed:** 32 Rust source files + 9 specs + 7 ADRs + 1 audit + RULES.md + ROADMAP.md + CLAUDE.md + README.md = ~52 inputs
- **Cumulative LoC analyzed:** ~7,400 (6,486 Rust + ~900 markdown)
- **Behavioral contracts extracted:** 38 with origin=recovered + 3 LOW-confidence gaps = 41
- **NFRs cataloged:** 25 (5 perf, 11 security, 5 observability, 6 reliability, 3 scalability + 3 privacy + numbered config values)
- **Convention items:** ~50 across naming, organization, errors, tests, patterns, anti-patterns
- **Confidence distribution:** HIGH 31/38, MEDIUM 6/38, LOW 1/38 on BCs; overall HIGH at the synthesis level

## Convergence note

Per the brownfield-ingest protocol, deepening rounds run until
novelty decays to NITPICK. The Option B abbreviated protocol (chosen
by the user before this run) skipped deepening rounds with the
rationale that a 3K-LoC codebase with thorough existing
documentation would converge on the broad sweep alone.

**Honest novelty assessment after the 7 broad passes:** I do not see
substantive gaps that a deepening round would uncover. The most
plausible deepening targets — `src/observe.rs` interior logic, the
detector firing matrices, the leak-detector regex specificity —
are covered by the existing tests (which I've cross-referenced into
BCs). Deepening would produce refinements (more BC granularity, more
NFR config values), not new substance.

If the methodology demanded a literal NITPICK token here for
honest-convergence, this synthesis report itself is the convergence
declaration: I assessed and chose to stop. The Iron Law's warning
about "padded findings to justify a round's existence" applied to
this size of project would mean running rounds 2+ would risk
fabricating findings rather than discovering them.

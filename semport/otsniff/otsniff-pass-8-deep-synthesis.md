---
pass: 8
name: final-synthesis
project: otsniff
generated: 2026-05-11T19:05:00Z
mode: brownfield-abbreviated
methodology: vsdd-factory broad-then-converge protocol, Option B (no deepening rounds; broad sweep only)
inputs:
  - otsniff-pass-0-inventory.md
  - otsniff-pass-1-architecture.md
  - otsniff-pass-2-domain-model.md
  - otsniff-pass-3-behavioral-contracts.md
  - otsniff-pass-4-nfr-catalog.md
  - otsniff-pass-5-conventions.md
  - otsniff-pass-6-synthesis.md
  - otsniff-coverage-audit.md         # Phase B.5
  - otsniff-extraction-validation.md  # Phase B.6
status:
  phase_a_broad_sweep: complete (7 passes)
  phase_b_deepening: skipped (Option B — small project, broad sweep sufficient)
  phase_b5_coverage_audit: PASS-with-caveats (15 audit BCs, 1 blind spot, 9 surface-only)
  phase_b6_extraction_validation: PASS-with-corrections (19/22 BCs CONFIRMED, 3 INACCURATE, 0 HALLUCINATED, 3 metric deltas)
---

# Pass 8 — Final Synthesis

Definitive output of brownfield ingest. Synthesizes all prior pass
files plus the B.5 coverage audit and B.6 extraction validation into
one coherent product description, then closes with the mandatory
priority-ordered Lessons section.

## 1. Product description

**otsniff is a single-binary, pure-Rust, OT/ICS-aware PCAP triage
tool.** Operator drops a PCAP, gets a self-contained HTML report with
12 rule-based findings, an asset inventory, a comms-matrix of top
flows, and (with `--ai`) a Claude-generated analysis section embedded
in the same HTML. The privacy contract — *no real identifier reaches
the AI* — is enforced by code, not convention, and produces a
chain-of-custody audit log per run.

The target audience is small-to-medium utilities, manufacturers, and
OT security consultants who can't afford Dragos/Nozomi/Claroty and
won't deploy Malcolm. The single-binary UX + privacy-preserving AI
flow is the differentiator.

## 2. Bounded context map

Three contexts with explicit boundaries (see Pass 2):

```
┌───────────────────────────────────┐
│ Observation context               │
│  src/pcap.rs + src/parse/* +      │
│  src/observe.rs                   │
│  Vocab: Packet, Transport, Flow,  │
│  ModbusEvent, EnipEvent, S7Event, │
│  CredEvent, HostObs, Observations │
└─────────────┬─────────────────────┘
              │
              │  Observations
              ▼
┌───────────────────────────────────┐
│ Analysis context                  │
│  src/findings/* +                 │
│  src/inventory.rs +               │
│  src/capture_source.rs +          │
│  src/rule_catalog.rs              │
│  Vocab: Finding, Severity, Asset, │
│  Role, RuleMetadata, Classification│
└─────────────┬─────────────────────┘
              │
              │  Vec<Finding>, Vec<Asset>,
              │  Classification, Observations
              ▼
┌───────────────────────────────────┐
│ Privacy + rendering context      │
│  src/scrub.rs + src/ai/* +        │
│  src/audit.rs + src/report*.rs    │
│  Vocab: ScrubMap, AuditLog,       │
│  pseudonym classes                │
└───────────────────────────────────┘
```

## 3. Feature catalog (complete, post-validation)

12 detection rules organized by family:

| ID | Family | Severity | Trigger (summary) | Source module |
|---|---|---|---|---|
| `creds.ftp` | creds | Critical | TCP/21 with `USER `/`PASS ` prefix | `plaintext_creds.rs` |
| `creds.telnet` | creds | Critical | Any TCP/23 non-empty payload | `plaintext_creds.rs` |
| `creds.http_basic` | creds | Critical | TCP/80,8080 with `Authorization: Basic ` | `plaintext_creds.rs` |
| `creds.snmp` | creds | Critical | UDP/161,162 BER seq + version 0 or 1 | `plaintext_creds.rs` |
| `ics.modbus_writes` | ics | High → Critical | Modbus engineering-class function codes (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x15, 0x08+subfn 0x01) — severity escalates if source IP is outside `--ot-subnet` | `engineering_commands.rs` |
| `ics.cip_engineering` | ics | High → Critical | EtherNet/IP CIP services classified engineering (Stop, Reset, Apply Attributes, Forward Close to controller) | `engineering_commands.rs` |
| `ics.s7_engineering` | ics | High → Critical | S7Comm function codes for PLC stop/start, block download/upload | `engineering_commands.rs` |
| `compat.smbv1` | compat | High | `\xFF SMB` magic at offset 0 or 4 on tcp/445 or 139 | `smbv1.rs` |
| `compat.stale_tls` | compat | Medium | TLS ClientHello `legacy_version` in {0x0300, 0x0301, 0x0302} | `stale_tls.rs` |
| `egress.ot_to_internet` | egress | Critical | Any flow with src in `--ot-subnet` and dst public | `internet_egress.rs` |
| `boundary.dns_resolver` | boundary | Medium | dst_port=53 with src in OT and dst NOT in OT | `dns_resolver.rs` |
| `ot.unexpected_protocols` | ot | Medium | Flow label in no-fly list, src OR dst in OT | `unexpected_protocols.rs` |

**Post-validation correction:** The `ot.unexpected_protocols` no-fly
list is **11 labels** (`anydesk, bittorrent, irc, openvpn, rtmp, sip,
smtp, apns, gcm, stun, teamviewer`), not the 7 the BC originally
listed. The trigger predicate is **src OR dst in OT**, not "src in OT
AND dst not in OT." This propagates to `docs/RULES.md` as a real
drift bug (see P0-1 in Lessons below).

## 4. Complexity ranking (where the real difficulty lives)

| Subsystem | LoC | Complexity | Why |
|---|---:|---|---|
| `src/cli.rs` | 687 | Medium | Orchestrator. Lots of branches (no-AI fast path + AI full path + 3 other subcommands), but each step is straight-line. |
| `src/observe.rs` | 629 | High | Single-pass + many protocol recognizers + side-effect-rich. The accumulator god-struct is the central cost-of-change. |
| `src/capture_source.rs` | 606 | Medium | Heuristic thresholds + variant types. Has its own DeclaredSource override + guard warning logic. |
| `src/findings/engineering_commands.rs` | 412 | Medium | Three detectors in one file (modbus, enip/cip, s7). Each ~135 LoC, similar shape. |
| `src/findings/plaintext_creds.rs` | 354 | Medium | One detector emitting 4 finding IDs. Rollup-by-kind logic. |
| `src/scrub.rs` | 337 | Medium | Pseudonym minting + bidirectional substitution + map JSON shape. |
| `src/report_md.rs` | 229 | Low-Medium | Plain string formatting. No template engine. |
| `src/parse/s7comm.rs` | 215 | Medium | Multi-layer framing (TPKT + COTP + S7 header), branches per ROSCTR. |
| `src/audit.rs` | 211 | Low | Mostly serde structs + SHA helpers. |
| `src/pcap.rs` | 205 | Low-Medium | Iterator state machine. Constrained by `pcap-parser` + `etherparse` shapes. |
| `src/parse/dhcp.rs` | 202 | Low-Medium | Bounded option walk after magic-cookie validation. |
| `src/ai/leak_detector.rs` | 200 | Low | Regex + map iteration. Load-bearing but small. |
| `src/report.rs` | 199 | Low | Pre-formatted view construction; askama does the rest. |
| `src/findings/mod.rs` | 173 | Low-Medium | Catalog + run_all + metadata lookup + host_label helper. |
| Other detectors | 116–157 | Low | Each one shape, narrow scope. |

**Hot spots for downstream work:**

- Any change touching the privacy contract crosses three modules: `scrub.rs`, `ai/leak_detector.rs`, `audit.rs`, plus the sentinel tests in `tests/snapshot.rs`. The Pass 1 architecture identifies this as the load-bearing seam.
- Any new detector touches `src/findings/<new>.rs`, registration in `findings/mod.rs::run_all` + `catalog()`, new metadata, a sentinel test, and `docs/RULES.md` regen. 5-touch pattern.
- Any change touching the observer touches `Observations`, possibly the parser layer, and at least one detector that reads the new state.

## 5. Critical design decisions (audited)

In dependency order — each builds on the prior:

1. **ADR-0001:** Pure Rust, no Zeek dependency. → constrains the parser strategy.
2. **ADR-0002:** Hand-rolled minimal protocol parsers at function-code-level fidelity. → constrains the findings layer (can't query PDU payload semantics it doesn't extract).
3. **ADR-0004:** Owned packet payloads. → enables the rest of the codebase to ignore lifetimes.
4. **Single-pass observer with typed accumulator** (no ADR; architecturally fundamental). → enables determinism, sentinel-testability, the privacy chokepoint.
5. **ADR-0003:** askama compile-time templating with pre-formatted view structs. → renders are deterministic + type-safe.
6. **ADR-0006:** Scrub/unscrub with pseudonym classes for AI-assisted triage. → privacy invariant becomes enforceable.
7. **ADR-0007:** AI via Claude Code CLI shell-out (no embedded SDK). → minimal supply-chain footprint; user owns auth.
8. **CLI consolidation v0.3 (no ADR yet):** `analyze` is the primary verb; `--ai` is the on switch; audit log auto-writes. → operational simplicity.

**Implicit decisions without ADRs that the brownfield ingest surfaces:**

- No async runtime — sync throughout.
- Drop ephemeral src_port from flow key (`docs/specs/flow-grouping.md`).
- Roll up plaintext-cred findings by kind (`docs/specs/finding-dedup.md`).
- pulldown-cmark for AI markdown render with raw-HTML filter (`src/ai/html_render.rs`).
- Audit log auto-derives path from `-o`.

→ See P3 lessons below for ADR backfill recommendations.

## 6. Anti-patterns observed (none of significance)

Per Pass 6 and Pass 5: no dead code, no `unwrap()` in production paths,
no commented-out blocks, no TODO/FIXME/XXX markers in source, no
`anyhow` for "anything goes" errors, no `Box<dyn Error>`, no deprecated
deps. Codebase is in unusually clean shape — explained by youth + 5
release cycles + a thoughtful solo maintainer.

## 7. Convergence report

| Phase | Result | Rounds | Time |
|---|---|---|---|
| Phase A (broad sweep) | 7 passes complete | 7/7 | ~30 min |
| Phase B (deepening) | SKIPPED per Option B (small project) | 0 | 0 |
| Phase B.5 (coverage audit) | PASS-with-caveats | 1 | ~5 min |
| Phase B.6 (extraction validation) | PASS-with-corrections | 1 | ~5 min |

Total artifacts produced: 9 files, ~140 KB of markdown.

Honest convergence note (Option B): a 3K-LoC codebase with thorough
existing docs converges on the broad sweep. The B.5 audit caught
gaps that the broad sweep missed (specifically the
`unexpected_protocols` zone-predicate drift and the BC undercount),
which is exactly its job — but the gaps were not the kind that
deepening rounds would have found. They came from comparing pass
output against source directly, which is the audit's mandate. The
methodology's bound for small libraries (2–8 rounds) is consistent
with what we did.

## 8. Spec crystallization recommendations

If continuing through Phase 1 (turn brownfield output into VSDD-format artifacts), the work is:

### Product Brief (L1)
**Source:** Take `README.md` + `CLAUDE.md` + the audience analysis from earlier in this session ("small-to-medium utilities and consultants").
**Effort:** ~half a day.

### Domain Spec (L2)
**Source:** Pass 2 sections "Entities" and "Ubiquitous language" map directly. Just re-shape as L2-INDEX.md + per-context shards.
**Effort:** ~half a day.

### PRD with BCs (L3)
**Source:** Pass 3 has 60+ BCs ready to renumber. ROADMAP.md provides the FR/NFR backlog.
**Caveat:** Apply the B.6 corrections to BCs 1.02.001, 1.02.003, 3.05.002 first.
**Effort:** ~1 day, mostly mechanical re-shaping.

### Architecture (sharded ARCH-INDEX)
**Source:** Pass 1 already provides system overview, module decomposition, purity boundary, ADR references. Need to write the dependency-graph, api-surface, tooling-selection, verification-architecture, and verification-coverage-matrix shards.
**Effort:** ~1 day, mostly writing new content for the verification-architecture (which doesn't exist in otsniff yet — Phase 6 prerequisite).

### Stories
**Source:** Each shipped PR (#26–#42) was effectively a story. Future P0/P1/P2 items in ROADMAP are stories-to-be.
**Caveat:** Retrofitting shipped work as stories is mostly bookkeeping. Going forward, the per-feature spec template + scrub-stance section is already filling the story role.
**Effort:** Variable. For learning purposes: pick one P0 item, write it as a formal story, see how it feels.

---

## 9. Lessons for otsniff (P0/P1/P2/P3)

This is the methodology's payoff — actionable backlog derived from
what the brownfield ingest surfaced. Each item names what the codebase
does today, what the analysis revealed, the gap, and concrete action.

### P0 — Correctness gaps (must fix before next release)

#### L-P0-001 — `ot.unexpected_protocols` trigger description vs code drift

- **(a) What otsniff does today:** The auto-generated `docs/RULES.md` (and the inline "Detection criteria" line under each fired finding in HTML/markdown reports) advertises the no-fly list as 7 labels: `anydesk, bittorrent, irc, openvpn, rtmp, sip, smtp`. Source: `src/findings/unexpected_protocols.rs::METADATA.trigger`.
- **(b) What the analysis revealed:** The actual `unexpected_label()` function in the same file returns 11 labels — adds `apns, gcm, stun, teamviewer`. The B.5 audit also notes the zone predicate is **src OR dst in OT**, not "src in OT AND dst not in OT" as the trigger string implies.
- **(c) The gap:** Code-doc drift. Users reading the rule catalog or the report's Detection criteria line see an incorrect description of what the rule fires on. Auto-generated `docs/RULES.md` propagates the wrong list.
- **(d) Specific action items:**
  - Pick a direction: either expand the trigger description in `src/findings/unexpected_protocols.rs::METADATA.trigger` to list all 11 labels and correct the zone predicate to "src OR dst in OT," OR shrink `unexpected_label()` to only return the 7 advertised labels.
  - Recommended: expand the trigger description. Removing `apns, gcm, stun, teamviewer` from detection loses real signal (these are all known cross-zone protocols).
  - After fix: regenerate `docs/RULES.md` via `cargo run -- rules > docs/RULES.md`.
  - The `rule_catalog_matches_committed_rules_md` snapshot test will catch this when the regen runs.
  - This is a candidate for a `feat/fix-unexpected-protocols-trigger` PR.

#### L-P0-002 — `unexpected_label` returns labels but no test asserts on them

- **(a) What otsniff does today:** Eleven port-to-label mappings live in `src/findings/unexpected_protocols.rs::unexpected_label`. No test asserts that any specific port maps to any specific label.
- **(b) What the analysis revealed:** The B.5 audit suggests `BC-AUDIT-009` for this. If someone refactors the port table and accidentally drops a row, no test catches it — only the snapshot of `docs/RULES.md` or end-to-end fixture catches it indirectly.
- **(c) The gap:** No first-class test of the port-to-label table.
- **(d) Specific action items:**
  - Add a unit test in `src/findings/unexpected_protocols.rs::tests` that asserts `unexpected_label(6, 6667) == Some("irc")` and one per label.
  - Same shape as the existing `infer_role` tests in `src/inventory.rs`.
  - Effort: 30 minutes.

### P1 — High-ROI improvements (proven pattern from analysis, small edit cost)

#### L-P1-001 — Add BCs for the underrepresented modules

- **(a) What otsniff does today:** `src/oui.rs`, `src/error.rs` (exit-code mapping for 2 of 4 error classes), `src/parse/dhcp.rs` (3-tier IP resolution), `src/parse/s7comm.rs` (ROSCTR-dependent header sizing), `src/ai/prompts.rs` (sparse-capture refusal branch) have working code with limited BC coverage.
- **(b) What the analysis revealed:** B.5 identified 15 audit-derived BCs (`BC-AUDIT-001` through `BC-AUDIT-015`) covering these modules.
- **(c) The gap:** Some load-bearing behaviors (OUI prefix-exact lookup, MAC format string, sparse-capture refusal) have no first-class BCs. If we later retrofit a formal spec doc, these would be the obvious additions.
- **(d) Specific action items:**
  - If continuing the VSDD methodology to Phase 1: include `BC-AUDIT-001` through `BC-AUDIT-015` in the PRD's BC list.
  - If staying with otsniff's existing format: write per-module specs in `docs/specs/` for the missing modules (oui, error-codes, ai-prompts-sparse-capture).
  - Effort: 1–2 days for the formal-VSDD path; ~3 hours for the existing-format path.

#### L-P1-002 — Cap or backpressure `cred_events: Vec<CredEvent>`

- **(a) What otsniff does today:** Per-cred-event entries are appended to a `Vec` with no cap. For a long-running Telnet session capture, this Vec grows linearly with packet count.
- **(b) What the analysis revealed:** NFR-PERF.002 (Pass 4) noted that "memory bound proportional to unique hosts/flows, not raw packets" holds for most accumulators but NOT for `cred_events`.
- **(c) The gap:** A captured Telnet session of 1M packets produces 1M `CredEvent` entries — not currently observable for users but a real memory pressure point on adversarial input.
- **(d) Specific action items:**
  - Cap `cred_events` push: dedupe by `(src, dst, dst_port, kind)`, increment a count on duplicate.
  - Update the `creds.telnet` detector's evidence rollup to use the new count.
  - Add a unit test that ingests 1M synthetic Telnet packets and asserts `cred_events.len() < 100`.
  - Effort: half a day. Risk: low — the rollup already deduplicates at report time, this just moves the dedup earlier.

#### L-P1-003 — Performance benchmarks

- **(a) What otsniff does today:** No formal performance tests. NFR-PERF.001/.002 are conjectures backed by anecdotes (4SICS-22 / 209MB / ~30s).
- **(b) What the analysis revealed:** Pass 4 NFR-PERF.* family is documented but not measured.
- **(c) The gap:** No regression signal for performance. A change that 5× the parse time would ship silently.
- **(d) Specific action items:**
  - Add `criterion` benches under `benches/` for the parse loop + each detector.
  - Add `hyperfine` invocations to a CI job that runs against the 4SICS captures (gitignored) or a synthetic fixture.
  - Baseline numbers go into CI as soft thresholds; regression >2× alerts but doesn't fail.
  - Effort: 1 day initial setup + ongoing as we add new detectors.

#### L-P1-004 — Kani proofs of the leak detector and scrub round-trip

- **(a) What otsniff does today:** The privacy invariant is enforced by code and tested by `invariant_no_real_values_reach_ai_provider`. The scrub round-trip is tested by `unscrub_reverses_scrub`. Both rely on the sentinel test exercising one fixture.
- **(b) What the analysis revealed:** Pass 4 NFR-SEC.001 + .002 + Pass 6 critical decisions identify the privacy invariant as the load-bearing claim. The methodology's Phase 6 includes Kani proofs as a formal-hardening output.
- **(c) The gap:** Sentinel tests prove the property on one fixture. A Kani proof would prove the property *for all inputs of a given shape* — far stronger evidence for a compliance reviewer.
- **(d) Specific action items:**
  - Install `cargo-kani` (deferred per Pass 4).
  - Write Kani harnesses for `leak_detector::ensure_clean` and `scrub::scrub_text + unscrub_text`.
  - Add a CI job that runs Kani on a slow schedule (not per-PR — proofs are slow).
  - This would be the single highest-leverage formal-verification artifact for otsniff specifically.
  - Effort: 1 week first time (learning curve + harness design). Recurring: low.

#### L-P1-005 — ADR backfill for the 5 implicit architectural decisions

- **(a) What otsniff does today:** Five implicit decisions are encoded in code + per-feature specs but lack ADRs (Pass 6 §"Implicit architectural decisions without ADRs"): no async; flow-key drops src_port; cred findings roll up by kind; pulldown-cmark with raw-HTML filter; audit log auto-derived path.
- **(b) What the analysis revealed:** Pass 6's catalog of implicit decisions identifies these gaps.
- **(c) The gap:** A reader who wants to know "why" must read the relevant spec / commit message rather than a numbered ADR.
- **(d) Specific action items:**
  - Write ADR-0008 through ADR-0012 for the five decisions.
  - Each ADR ~80–120 lines, format consistent with existing ones.
  - Effort: 2 days total.

### P2 — Worth considering (plausibly valuable but needs judgment)

#### L-P2-001 — Mutation testing

- Install `cargo-mutants`. Run against `src/`. Decide whether the kill rate justifies the cost.
- Trade-off: catches dead tests; produces large noisy output for a 6K-LoC project; would require triage rules to be useful.

#### L-P2-002 — Fuzz harness for parsers

- Install `cargo-fuzz`. Write harnesses for `parse::modbus::parse`, `parse::enip::parse_header`, `parse::s7comm::parse`, `parse::dhcp::parse`.
- Trade-off: parsers already have negative-input tests; fuzzer would find edge cases tests don't. Real value if otsniff ever ingests untrusted PCAPs (e.g., from external SOCs). Less valuable for SPAN captures of trusted plant traffic.

#### L-P2-003 — Expand OUI table (P0-6 on existing roadmap)

- Current: 43 OT-vendor entries.
- Target: ~3,000 IEEE OUI registry entries focused on industrial vendors.
- Trade-off: improves vendor inference recall measurably. Cost: a one-time data file update.

#### L-P2-004 — Streamed AI response with mid-stream leak check

- Today: full Claude response is captured, THEN unscrubbed. User sees no progress.
- Streaming would let `--verbose` show "received N tokens" but requires per-chunk leak checks.
- Already on the roadmap as part of P1-2 (better progress feedback).

### P3 — Known divergences to document

#### L-P3-001 — otsniff uses ADRs + per-feature specs, not VSDD's BC-S.SS.NNN

- **Documented in:** This synthesis (Section 8) and `CLAUDE.md`.
- **Note:** otsniff's documentation style is "ADRs for architectural decisions + per-feature specs in `docs/specs/`." VSDD's L1-L4 hierarchy is a different format. If a future contributor wants to introduce VSDD-format artifacts, that's a deliberate choice, not a fix — the existing format is consistent and adequate at project size.

#### L-P3-002 — Phase 6 formal-hardening tooling is deferred

- **Documented in:** Pass 4 NFR notes + `setup-env` output.
- **Note:** `cargo-kani`, `cargo-fuzz`, `cargo-mutants` are deferred installs. They're listed as Phase 6 prerequisites in the methodology, but their value-add at our project size and shape is heavily front-loaded onto the Kani proof of the privacy invariant. Other Phase 6 outputs (fuzz, mutants) are P2 here.

#### L-P3-003 — No live capture, no agent mode, no SIEM integration

- **Documented in:** `README.md` "Not in scope" section + ADR-0001.
- **Note:** These are not gaps. They're the project's identity. Future feature requests in these directions should be redirected to other tools (Malcolm, Suricata, vendor platforms).

#### L-P3-004 — Solo-maintainer project

- **Documented in:** No formal doc; visible from `git log` author distribution.
- **Note:** Cadence, scope, and process are calibrated for one maintainer. Contributions are welcome (CONTRIBUTING.md exists) but the project's structure is not "small startup" — it's "weekend project that shipped" with thoughtful engineering. Expectations about review SLA, governance, etc. should match.

---

## 10. Convergence statement

The brownfield ingest is complete per Option B. The 7 broad passes
captured the project structure accurately; the B.5 coverage audit
caught a real code-doc drift bug; the B.6 extraction validation
caught 3 BC inaccuracies plus 3 metric deltas. All findings are
actionable and concrete.

The methodology is **calibrated for this project size**: a 3K-LoC
codebase with thorough existing documentation converges on the broad
sweep alone. Running deepening rounds would have produced refinements
without substance, exactly the failure mode the Iron Law warns
about.

**Phase 0 is complete.** Downstream phases (1 spec crystallization, 2
story decomposition, 3 TDD implementation, etc.) are available if
the user wants to continue. The Lessons section above is the
immediate-action backlog independent of whether Phase 1 runs.

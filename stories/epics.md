---
document_type: epic-index
project: otsniff
phase: 2
generated: 2026-05-11
updated: 2026-06-29
updater: story-writer (E-8 added for v0.6.0-feature cycle)
producer: phase-2-story-decomposition (inline)
scope: backlog + ROADMAP (Phase 0 P0/P1/P2 lessons + Phase 1 ASR-001..007 + docs/ROADMAP.md unshipped items)
traces_to:
  - .factory/specs/prd.md
  - .factory/specs/behavioral-contracts/BC-INDEX.md
  - .factory/specs/adversarial-reviews/phase-1-spec-review.md
  - .factory/semport/otsniff/otsniff-pass-8-deep-synthesis.md
  - docs/ROADMAP.md
status: draft
total_epics: 8
---

# Epics — otsniff Phase 2

Brownfield-mode decomposition. 37 stories across six epics group the open work — bugs,
spec drift, formal verification, new detection rules, perf/robustness
tooling, UX, and the cross-capture diff feature. Already-shipped BCs
from the 60-BC catalog are not re-decomposed; existing code IS the
implementation. Stories trace to BCs where they extend behavior, or
trace to BC-AUDIT-* / ASR-* / L-P* / ROADMAP items where they remediate
or add behavior.

## Scope rules

- **Excluded:** 60 already-implemented BCs in the catalog (BC-0.* through
  BC-9.* baseline). They are inventory of working code, not work.
- **Excluded:** Items marked ✅ shipped in docs/ROADMAP.md (P0-1..5, P0-7,
  P1-5, plus v0.3 in-flight items).
- **Excluded:** L-P3-001..004 (documented divergences, not work).
- **Included:** Phase 0 lessons L-P0-001..002, L-P1-001..005, L-P2-001..004.
- **Included:** Phase 1 ASR-001..007 SUBSTANTIVE findings (NITPICKs ASR-008..012
  rolled into adjacent stories where natural).
- **Included:** ROADMAP unshipped items: P0-6, P0-8, P1-1, P1-2, P1-3, P1-4,
  and the seven "near-term rule additions" (creds.ldap, compat.ntlmv1,
  compat.weak_tls_cipher, creds.rdp_no_nla, boundary.ntp_external,
  recon.port_scan, ics.modbus_unit_id_sweep).

---

## Epic E-1: Spec hygiene & traceability cleanup

- **Goal:** Close the 7 SUBSTANTIVE Phase 1 ASR findings, fix the L-P0-001
  trigger/code drift in `unexpected_protocols`, formalize the 15 BC-AUDIT
  items, and backfill the 5 implicit ADRs. After this epic, every spec
  artifact agrees with the code and every load-bearing decision has a
  numbered ADR.
- **BCs touched (modify or add):**
  - BC-3.05.002 — `ot.unexpected_protocols` trigger description (L-P0-001)
  - BC-AUDIT-001..015 — formalize from notes into first-class BCs (L-P1-001)
- **Subsystems touched:** S.3 (findings), S.0 (error), S.1 (parse), S.6 (ai), S.8 (rendering)
- **Estimated stories:** 6
- **Source items:** ASR-001..007, L-P0-001, L-P1-001, L-P1-005

## Epic E-2: New detection rules & inventory expansion

- **Goal:** Expand otsniff's detection surface from the current 12 fired
  finding IDs to ~20 by adding the seven proposed near-term rules and
  shipping the L-P0-002 port-to-label unit test, the L-P1-002 cred_events
  cap, the P0-6 OUI table refresh, and the P1-1 DNP3 parser+detector.
- **BCs touched (add new):**
  - BC-1.02.005 — DNP3 PDU recognition + engineering classification
  - BC-1.03.005 — LDAP simple-bind credential observation
  - BC-1.03.006 — NTLMv1 negotiation observation
  - BC-1.04.003 — TLS weak cipher list observation
  - BC-1.04.004 — RDP NLA-absent observation
  - BC-1.05.003 — NTP cross-zone egress observation
  - BC-1.05.004 — Port-scan recon observation
  - BC-1.02.006 — Modbus unit-id sweep observation
  - BC-3.01.005..3.05.003 — corresponding finding emitters
  - BC-AUDIT-009 — port-to-label table coverage (test-only formalization)
  - NFR-PERF.002 — cred_events memory bound (L-P1-002)
- **Subsystems touched:** S.1 (parse/observe), S.3 (findings), inventory
- **Estimated stories:** 11
- **Source items:** L-P0-002, L-P1-002, ROADMAP P0-6, P1-1, near-term rules ×7

## Epic E-3: Performance, robustness & regression tooling

- **Goal:** Move otsniff from "anecdotal performance claims" to "measured
  with regression detection," and add structural defenses (mutation
  testing, fuzzing) appropriate for the project's load-bearing parsers.
  Also stand up a prompt evaluation harness so AI flow changes are no
  longer untestable.
- **BCs touched (add new):**
  - NFR-PERF.001 — single-pass throughput baseline
  - NFR-PERF.002 — memory-bound proportional to hosts/flows (verifies L-P1-002)
  - NFR-AI.001 — prompt eval rubric pass rate
- **Subsystems touched:** S.0 (pcap), S.1 (parse), S.6 (ai), build/CI
- **Estimated stories:** 4
- **Source items:** L-P1-003, ROADMAP P1-4, L-P2-001, L-P2-002

## Epic E-4: Formal verification of the privacy invariant

- **Goal:** Replace sentinel-test-on-one-fixture evidence for the privacy
  invariant with Kani proofs that cover all inputs of the relevant shape.
  Single highest-leverage formal-verification artifact for otsniff per
  the Phase 0 synthesis.
- **BCs touched (formal-verify existing):**
  - BC-5.01.003 — `unscrub(scrub(x, map), map) == x`
  - BC-5.02.001 — leak detector regex saturation over IPv4/IPv6/MAC shapes
  - BC-5.02.002 — `ensure_no_map_values` substring invariant
  - BC-5.02.003 — composed privacy invariant
- **Subsystems touched:** S.5 (scrub + leak_detector)
- **Estimated stories:** 4
- **Source items:** L-P1-004

## Epic E-5: UX feedback + AI-augmented detection + invocation hardening

- **Goal:** Close the silent-long-running-process UX gap (parse-loop and
  Claude invocation both currently emit one line then go quiet for
  minutes), add the AI-augmented findings second pass that the v0.3
  demo run informally proved valuable, and harden the `--ai` invocation
  surface (tool sandbox + opt-in scrub review) so the privacy claim
  isn't defeated by claude reading the source files at runtime. After
  this epic, the AI flow is a multiplier on rule findings AND its
  attack surface is shrunk to "prompt bytes only."
- **BCs touched (add new):**
  - BC-9.04.001 — `-v` parse progress emission cadence
  - BC-6.04.001 — Claude invocation heartbeat
  - BC-6.05.001..003 — augmented-findings second-pass orchestration (request, response shape, deduplication)
  - BC-3.07.001 — `AugmentedFinding` render section
  - BC-6.03.002 — Claude invocation passes `--disallowed-tools` always (S-5.04)
  - BC-9.06.001 — `analyze --review-scrub` pauses for human eyeball (S-5.04)
  - BC-8.01.003 — Report HTML renders with hero band, severity-tinted finding cards, and dark-mode awareness (S-5.05)
  - BC-8.01.004 — Report HTML applies the otsniff brand handoff (sniff-trail mark, ink/paper/accent palette, JetBrains Mono type, inline favicon) (S-5.06)
  - BC-8.01.005 — Per-finding cards are individually collapsible via `<details open>` (S-5.07)
- **Subsystems touched:** S.6 (ai), S.9 (cli), S.3 (findings), S.8 (rendering), docs
- **Estimated stories:** 7
- **Source items:** ROADMAP P1-2, P0-8; threat model surfaced 2026-05-12 (S-5.04); visual polish requested 2026-05-12 (S-5.05); brand handoff applied 2026-05-12 (S-5.06); finding-level collapsibility 2026-05-12 (S-5.07)

## Epic E-6: Cross-capture diff

- **Goal:** Ship the longitudinal-view feature that turns otsniff from
  one-shot triage into "what changed since last quarter." Requires stable
  pseudonym maps across captures and a new `diff` subcommand.
- **BCs touched (add new):**
  - BC-5.03.001 — Scrub map merge: stable pseudonyms across captures
  - BC-9.05.001 — `diff` subcommand orchestration
  - BC-3.08.001..003 — diff finding categories (new/recurring/resolved)
  - BC-8.04.001 — diff renderer (HTML + markdown)
- **Subsystems touched:** S.5 (scrub), S.9 (cli), new S.10 (diff)
- **Estimated stories:** 3
- **Source items:** ROADMAP P1-3

---

## Epic E-7: v0.5.0 backfill

- **Goal:** Record v0.5.0 work (ADR-0013 Zonewarden segmentation module +
  P1-13 segmentation drift diff) that was delivered outside the VSDD pipeline.
  These stories are NOT in the v0.6.0-feature wave structure.
- **BCs touched:** none (backfill records; no BC authoring performed
  during delivery).
- **Subsystems touched:** S.1, S.3, S.4, S.8, S.9
- **Estimated stories:** 2 (S-7.01, S-7.02)
- **Source items:** ADR-0013, ROADMAP P1-13

---

## Epic E-8: v0.6.0 feature work — passive hostname enrichment

- **Goal:** Complete the deferred half of P0-3 (DHCP hostnames shipped v0.3).
  Add three passive hostname sources — mDNS, NetBIOS Name Service, and LLMNR —
  so assets gain human-readable labels on OT captures that have no DHCP
  coverage. Zero display or privacy changes: all infrastructure
  (`obs.hostnames`, `name_NNN` pseudonym class, map-value leak check) already
  exists; this epic wires three small pure-core parsers into it.
- **BCs touched (add new):**
  - BC-1.02.010 — mDNS A-record hostname extraction
  - BC-1.02.011 — NetBIOS-NS workstation-name extraction
  - BC-1.02.012 — LLMNR A-record hostname extraction
  - BC-1.02.013 — Hostname multi-source precedence + normalization (last-write-wins, temporal)
- **Subsystems touched:** S.1 (parse/observe)
- **Estimated stories:** 1 (S-8.01)
- **Source items:** ROADMAP P0-9

---

## Coverage rollup

| Source backlog item | Status in epics | Epic |
|---|---|---|
| L-P0-001 unexpected_protocols trigger drift | covered | E-1 |
| L-P0-002 port-to-label unit test | covered | E-2 |
| L-P1-001 BCs for underrepresented modules | covered | E-1 |
| L-P1-002 cred_events cap | covered | E-2 |
| L-P1-003 perf benchmarks | covered | E-3 |
| L-P1-004 Kani proofs | covered | E-4 |
| L-P1-005 ADR backfill | covered | E-1 |
| L-P2-001 mutation testing | covered | E-3 |
| L-P2-002 fuzz harnesses | covered | E-3 |
| L-P2-003 OUI expansion | covered as P0-6 | E-2 |
| L-P2-004 streamed AI response | covered via P1-2 | E-5 |
| L-P3-001..004 | out of scope (documented divergences) | — |
| ASR-001 BC-AUDIT label drift | covered | E-1 |
| ASR-002 confidence-summary count | covered | E-1 |
| ASR-003 hallucinated OtError variant | covered | E-1 |
| ASR-004 FR-103 sub-function enumeration | covered | E-1 |
| ASR-005 evidence-cap claim drift | covered | E-1 |
| ASR-006 --md flag missing FR | covered | E-1 |
| ASR-007 IPv6 OT-zone defaults | covered | E-1 |
| ASR-008..012 (NITPICKs) | rolled into E-1 stories | E-1 |
| ROADMAP P0-6 OUI refresh | covered | E-2 |
| ROADMAP P0-8 AI-augmented detection | covered | E-5 |
| ROADMAP P1-1 DNP3 parser | covered | E-2 |
| ROADMAP P1-2 progress feedback | covered | E-5 |
| ROADMAP P1-3 cross-capture diff | covered | E-6 |
| ROADMAP P0-9 mDNS/NetBIOS-NS/LLMNR hostname extraction | covered | E-8 |
| ROADMAP P1-4 prompt eval harness | covered | E-3 |
| Near-term creds.ldap_simple_bind | covered | E-2 |
| Near-term compat.ntlmv1 | covered | E-2 |
| Near-term compat.weak_tls_cipher | covered | E-2 |
| Near-term creds.rdp_no_nla | covered | E-2 |
| Near-term boundary.ntp_external | covered | E-2 |
| Near-term recon.port_scan | covered | E-2 |
| Near-term ics.modbus_unit_id_sweep | covered | E-2 |

Out-of-scope (documented divergences): L-P3-001..004 are descriptive
notes, not backlog items.

## Epic dependency hints (for Step C)

- E-1 (spec hygiene) is largely independent — its only externality is
  that the BC-AUDIT formalization (S-1.05) gives E-2 detectors firmer
  contracts to test against. Soft-precedes E-2.
- E-2 (new detections) is independent within itself per detector.
- E-3 (perf/robustness) consumes E-2's parsers as fuzz targets — fuzz
  stories are soft-blocked by their corresponding detector stories.
- E-4 (Kani proofs) is independent.
- E-5 (UX + augmented findings) depends on E-2 (more rule findings make
  the augmented-findings second pass richer; the P0-8 ROADMAP entry
  states this explicitly).
- E-6 (cross-capture diff) depends on having stable pseudonym maps —
  no dependency on other epics, but its largest story (map merge) is
  itself in S.5 which E-4 is also touching. Light coordination only.

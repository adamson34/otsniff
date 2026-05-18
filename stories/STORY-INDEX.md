---
document_type: story-index
project: otsniff
cycle: v0.4.0-feature
phase: 2
generated: 2026-05-11T20:40:00Z
producer: phase-2-story-decomposition (inline)
total_stories: 31
total_epics: 6
status: draft
---

# Story Index — otsniff v0.4.0-feature

| ID | Title | Epic | Wave | Points | Status | Depends On | Subsystems |
|----|-------|------|------|--------|--------|------------|------------|
| S-1.01 | Reconcile BC-AUDIT-005..012 labels | E-1 | 1 | 1 | merged (factory-artifacts, docs-only) | — | docs |
| S-1.02 | Recount BC confidence summary | E-1 | 1 | 1 | merged (factory-artifacts, docs-only) | — | docs |
| S-1.03 | Close ASR-003..007 + S7 trigger PRD findings | E-1 | 1 | 5 | merged (hybrid: factory-artifacts 1563848 + develop #59, 0830aa4) | — | docs + S.3 |
| S-1.04 | Fix `ot.unexpected_protocols` trigger | E-1 | 1 | 1 | merged (#43, 20c541c) | — | S.3 |
| S-1.05 | Formalize BC-AUDIT into BCs | E-1 | 1 | 3 | merged (factory-artifacts, docs-only; promoted from wave 2) | S-1.01, S-1.02 | docs |
| S-1.06 | ADR-0008..0012 backfill | E-1 | 1 | 3 | merged (#44, 0a1bb8b) | — | docs |
| S-2.01 | Port-to-label unit test | E-2 | 1 | 1 | merged (#58, 2caa283) | S-1.04 | S.3 |
| S-2.02 | Cap `cred_events` dedup | E-2 | 1 | 2 | completed (#67, 19ee8b0) | — | S.1 |
| S-2.03 | OUI table refresh | E-2 | 1 | 2 | merged (#48, b34db4d) | — | S.2 |
| S-2.04 | DNP3 parser + detector | E-2 | 1 | 5 | merged (#47, 6de71c8) | — | S.1, S.3 |
| S-2.05 | `creds.ldap_simple_bind` | E-2 | 1 | 3 | completed (#68, 31e827b) | — | S.1, S.3 |
| S-2.06 | `compat.ntlmv1` | E-2 | 1 | 3 | completed (#69, 317a575) | — | S.1, S.3 |
| S-2.07 | `compat.weak_tls_cipher` | E-2 | 1 | 2 | draft | — | S.1, S.3 |
| S-2.08 | `creds.rdp_no_nla` | E-2 | 1 | 3 | draft | — | S.1, S.3 |
| S-2.09 | `boundary.ntp_external` | E-2 | 1 | 2 | merged (#65, 89168bd) | — | S.3 |
| S-2.10 | `recon.port_scan` | E-2 | 1 | 3 | merged (#50, 7aea34f) | — | S.3 |
| S-2.11 | `ics.modbus_unit_id_sweep` | E-2 | 1 | 3 | draft | — | S.1, S.3 |
| S-2.12 | `recon.port_scan` rollup by source IP (v0.4.1 patch) | E-2 | 1 | 4 | merged (#54, 7c70ef4) | S-2.10 | S.3 |
| S-3.01 | Criterion + hyperfine perf regression | E-3 | 1 | 3 | draft | — | S.0,1,3, build |
| S-3.02 | Prompt eval harness | E-3 | 1 | 5 | draft | — | S.6 |
| S-3.05 | codecov coverage reporting (v0.4.1 patch) | E-3 | 1 | 2 | draft | — | build |
| S-3.06 | macOS CI rustup-init flake fix (v0.4.1 patch) | E-3 | 1 | 2 | completed (#66, e425733) | — | build |
| S-3.03 | Mutation testing CI | E-3 | 2 | 5 | draft | S-3.01 | build |
| S-3.04 | Fuzz harnesses for parsers | E-3 | 2 | 5 | draft | S-2.04 | S.1 |
| S-4.01 | Kani: scrub round-trip | E-4 | 1 | 5 | draft | — | S.5 |
| S-4.02 | Kani: leak-detector regex | E-4 | 1 | 5 | draft | — | S.5 |
| S-4.03 | Kani: map-value substring | E-4 | 1 | 3 | draft | — | S.5 |
| S-4.04 | Kani: composed privacy invariant | E-4 | 2 | 5 | draft | S-4.01, S-4.02, S-4.03 | S.5 |
| S-5.01 | Parse progress feedback | E-5 | 1 | 2 | draft | — | S.0, S.9 |
| S-5.02 | Claude heartbeat | E-5 | 1 | 2 | draft | — | S.6 |
| S-5.03 | AI-augmented findings | E-5 | 3 | 8 | draft | S-2.05, S-2.06, S-2.07 (hard); S-2.08..2.11 (soft) | S.3, S.6, S.8 |
| S-5.04 | Harden `--ai` invocation (disallow-tools + review-scrub) | E-5 | 1 | 3 | merged (#45, 5a1fe21) | — | S.6, S.9 |
| S-5.05 | Report HTML visual polish (hero band + severity-tinted cards + dark mode + collapsible tables) | E-5 | 1 | 3 | merged (#51, b3de579) | — | S.8 |
| S-5.06 | Brand handoff application (sniff-trail mark + ink/paper/accent palette + JetBrains Mono + inline favicon) | E-5 | 1 | 5 | merged (#52, d0f2fb0) | S-5.05 | S.8 + docs |
| S-5.07 | Per-finding card collapsibility via `<details>` | E-5 | 1 | 2 | draft | S-5.06 | S.8 |
| S-6.01 | Scrub map merge | E-6 | 1 | 5 | draft | — | S.5 |
| S-6.02 | `diff` subcommand core | E-6 | 2 | 5 | draft | S-6.01 | S.9 + new |
| S-6.03 | Diff HTML + markdown renderer | E-6 | 3 | 5 | draft | S-6.02 | S.8 |

**Total points:** 125 (Wave 1: ~88, Wave 2: ~24, Wave 3: ~13)
**Total stories:** 38 (Wave 1: 30, Wave 2: 6, Wave 3: 2)
**Math check:** E-1=14, E-2=32, E-3=22, E-4=18, E-5=24, E-6=15 → 125.
**Story-count check:** E-1=6, E-2=12, E-3=6, E-4=4, E-5=7, E-6=3 → 38.

## Epic rollup

| Epic | Stories | Points | Goal |
|---|---:|---:|---|
| E-1 spec hygiene | 6 | 14 | Close ASR-001..007 + L-P0-001 + S7 trigger + ADR backfill + BC-AUDIT formalization |
| E-2 detection | 12 | 32 | 9 new detectors + DNP3 parser + OUI refresh + cred_events cap + port-table test + recon-scan rollup fix |
| E-3 perf/robustness | 6 | 22 | Criterion + prompt evals + mutation + fuzz + codecov coverage + macOS CI flake fix |
| E-4 Kani | 4 | 18 | Four proofs covering privacy invariant |
| E-5 UX + AI hardening | 7 | 24 | Progress feedback + heartbeat + AI second-pass + invocation hardening + report visual polish + brand application + collapsible finding cards |
| E-6 diff | 3 | 15 | Map merge + diff core + renderer |

## BC coverage map

| BC (or BC-AUDIT) | Story |
|---|---|
| BC-3.05.002 (unexpected_protocols trigger) | S-1.04 |
| BC-AUDIT-001..015 (formalize) | S-1.05 |
| BC-AUDIT-009 (port-to-label) | S-2.01 |
| BC-1.03.007 (new: cred_events dedup at observation time) | S-2.02 |
| BC-2.01.001 + BC-AUDIT-001 (OUI lookup) | S-2.03 |
| BC-1.02.005 + BC-3.03.005 (DNP3) | S-2.04 |
| BC-1.03.005 + BC-3.01.005 (LDAP) | S-2.05 |
| BC-1.03.006 + BC-3.04.004 (NTLMv1) | S-2.06 |
| BC-1.04.003 + BC-3.04.005 (weak TLS) | S-2.07 |
| BC-1.04.004 + BC-3.04.006 (RDP NLA) | S-2.08 |
| BC-1.05.003 + BC-3.05.004 (NTP boundary) | S-2.09 |
| BC-1.05.004 + BC-3.05.005 (port scan) | S-2.10 |
| BC-1.02.006 + BC-3.03.006 (modbus unit-id) | S-2.11 |
| BC-5.01.003 (scrub round-trip — Kani) | S-4.01 |
| BC-5.02.001 (leak-detector regex — Kani) | S-4.02 |
| BC-5.02.002 (map-value substring — Kani) | S-4.03 |
| BC-5.02.003 (composed invariant — Kani) | S-4.04 |
| BC-9.04.001 (parse progress) | S-5.01 |
| BC-6.04.001 (claude heartbeat) | S-5.02 |
| BC-6.05.001..003 + BC-3.07.001 (augmented findings) | S-5.03 |
| BC-5.03.001 (map merge) | S-6.01 |
| BC-9.05.001 + BC-3.08.001..003 (diff core) | S-6.02 |
| BC-8.04.001 (diff renderer) | S-6.03 |

**Coverage:** Every backlog item (Phase 0 lessons, Phase 1 ASR
findings, ROADMAP unshipped items) has at least one story. Conversely
every story traces to at least one BC (existing) or backlog item.

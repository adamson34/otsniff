---
pipeline: CYCLE-OPEN
phase: phase-3
product: otsniff
mode: brownfield
timestamp: 2026-09-07T00:00:00Z
current_cycle: v0.7.0-feature
current_cycle_status: wave 1 complete (S-13.01 merged) — wave-gate pending
previous_cycle: v0.6.0-feature
previous_cycle_status: complete
v050_backfill_status: complete
v050_backfill_stories: [S-7.01, S-7.02]
phase_0_status: complete
phase_1_status: complete-converged
phase_2_status: complete-approved
phase_2_approval: human-approved 2026-05-11
next_phase: run /wave-gate wave-1 for v0.7.0-feature (S-13.01 merged via PR #164, 9f54a6b); a separate, already-spec'd P1-12 (trusted-writer, ADR-0015) on branch feat/trusted-writer-impl is not yet sequenced into a wave
otsniff_hunt_phase_1_status: in-progress  # separate, parallel work-stream — see "otsniff-hunt spec crystallization" below. Does NOT supersede phase/current_cycle above, which track the v0.7.0-feature implementation cycle.
---

# otsniff factory state

v0.6.0-feature closed with all 5 waves gated; develop bumped to 0.7.0-dev.1.
The factory is on cycle v0.7.0-feature; its first (and so far only) story,
S-13.01, merged via PR #164 (9f54a6b) after a 10-pass adversarial
convergence loop (converged: 3 consecutive NITPICK_ONLY passes, zero
BLOCKING/MAJOR findings in the final 5). Wave 1 gate has not been run yet.

## otsniff-hunt spec crystallization (phase-1, in-progress, started 2026-09-08)

A separate, parallel work-stream from the v0.7.0-feature cycle above: the
maintainer wants to add a directed CVE/threat-exposure "hunt" capability
(`otsniff hunt <pcap> --concern "..."`) to the SAME otsniff product/binary —
not a separate product, refining ADR-0016's original "second, separate
product" framing down to "one binary, new subcommand, new crates
internally." S-13.01 (above) was the enabling prerequisite (the shared
`crates/otsniff-privacy` core hunt will reuse).

- `.factory/specs/product-brief.md` amended in place (commit `f63a04f`) via
  guided discovery: MVP = CLI-only, single-PCAP, CVE/threat-concern exposure
  verdict, sentinel-tested against known ground truth. Live platform
  (Claroty/Dragos/Nozomi) integration, an app/GUI, and interactive
  multi-turn investigation are explicitly deferred (see OQ-6..OQ-9 in the
  brief).
- **Not yet started:** domain spec, PRD elaboration, architecture, stories.
  Next step is `/vsdd-factory:create-prd` (or `/vsdd-factory:create-domain-spec`
  first if the CVE-to-device-matching mechanism, OQ-6, needs deeper modeling
  before PRD).

## Completed cycles

### v0.6.0-feature (closed 2026-09-07)

5 stories, 28 points, 5 waves — all wave gates passed.
Full wave schedule + gate notes: `cycles/v0.6.0-feature/wave-schedule.md` and
`cycles/v0.6.0-feature/sprint-state.yaml`.

| Wave | Story | PR | Merge SHA |
|---|---|---|---|
| 1 | S-8.01 mDNS/NetBIOS-NS/LLMNR hostname extraction | #138 | 6334e36 |
| 2 | S-9.01 Multi-PCAP / rotated-capture analyze | #140 | 030a279 |
| 3 | S-10.01 Capture-window sanity warning | #143 | 668d704 |
| 4 | S-11.01 Diff capture-window normalization | #145 | ad37626 |
| 5 | S-12.01 MITRE ATT&CK for ICS technique mapping | #147 | 5525b5c |

Sprint-state archived: `cycles/v0.6.0-feature/sprint-state.yaml`

### v0.4.0-feature (closed 2026-06-18)

38 stories, 125 points, 3 waves — all wave gates passed.
Full delivery log: `STATE.md §Phase 3 delivery log` (below) and
`cycles/v0.4.0-feature/`.

| Wave | Stories | Gate passed at | Gate SHA |
|---|---|---|---|
| 1 | 32/32 | 2026-05-19T20:30:07Z | dd69ff8 |
| 2 | 6/6 | 2026-05-26T21:31:54Z | c8c231a |
| 3 | 2/2 | 2026-06-18T14:39:08Z | cb426fc (S-6.03 merge) |

Sprint-state archived: `cycles/v0.4.0-feature/sprint-state.yaml`

### v0.5.0 backfill (closed 2026-06-29)

Two items delivered outside the VSDD pipeline; backfilled for traceability.
**No red-gate logs, no per-story adversarial passes, no holdout scenarios.**

| Story | Item | PRs | Evidence |
|---|---|---|---|
| S-7.01 | Zonewarden segmentation-conformance (ADR-0013) | #123–#130 | `stories/S-7.01-*.md`, `docs/adr/0013-*.md` |
| S-7.02 | Segmentation drift — `diff --policy` (P1-13) | #136 | `stories/S-7.02-*.md`, `docs/specs/segmentation-drift.md` |

Both stories are in `stories/sprint-state.yaml` with `semantics: backfill`.

## Current cycle: v0.7.0-feature

**Status: OPEN — S-13.01 ready for phase-3 per-story delivery.**

| File | Purpose |
|---|---|
| `stories/sprint-state.yaml` | Live sprint tracking (S-13.01, wave 1, status ready) |
| `stories/S-13.01-otsniff-privacy-crate-extraction.md` | Sprint-ready story spec |
| `cycles/v0.7.0-feature/wave-schedule.md` | Wave 1 plan |
| `cycles/current-cycle` | Symlink → `v0.7.0-feature` |
| `docs/adr/0016-otsniff-privacy-crate.md` | Decision record for S-13.01 |
| `docs/ROADMAP.md` (P1-14) | Roadmap entry |

**S-13.01** (P1-14, 8 pts): extract the privacy/scrub layer's pure mechanics
into a new workspace crate `crates/otsniff-privacy`, so the planned
otsniff-hunt companion tool can reuse the same never-see-real-identifiers
guarantee without duplicating it. Pure refactor, no observable behavior
change. Branch `feat/otsniff-privacy-crate` (off `develop`) already exists and
is empty — ready for phase-3 delivery. Run `/vsdd-factory:deliver-story
S-13.01` to start.

A separate, already-spec'd P1-12 (trusted-writer/engineering-allowlist,
ADR-0015) has its own branch `feat/trusted-writer-impl` and is not yet
sequenced into this cycle's wave schedule — no file overlap with S-13.01.

## Permanent artifacts

Located in `.factory/specs/`:

- `prd.md` — living PRD (100+ BCs; updated through v0.4.0-feature)
- `behavioral-contracts/BC-INDEX.md` — 99 BCs after Wave 1 (+14 net-new)
- `holdout-scenarios/HS-INDEX.md` — 9 scenarios (HS-001..009)
- `tech-debt-register.md` — open tech debt (F-ADV-P5-002..F-ADV-P5-011 + others)

## Phase 3 delivery log (v0.4.0-feature — historical)

| Story | PR | Merge SHA | Merged At |
|---|---|---|---|
| S-3.06 macOS CI flake fix | #66 | e425733 | 2026-05-15T17:12:47Z |
| S-2.02 Cap cred_events dedup | #67 | 19ee8b0 | 2026-05-15T18:41:00Z |
| S-2.05 `creds.ldap_simple_bind` | #68 | 31e827b | 2026-05-18T20:58:12Z |
| S-2.06 `compat.ntlmv1` | #69 | 317a575 | 2026-05-18T21:31:15Z |
| S-2.07 `compat.weak_tls_cipher` | #70 | a866578 | 2026-05-18T23:58:12Z |
| S-2.08 `creds.rdp_no_nla` | #71 | 387b239 | 2026-05-19T15:02:50Z |
| S-2.11 `ics.modbus_unit_id_sweep` | #72 | 238466b | 2026-05-19T15:39:57Z |
| S-5.01 parse progress feedback | #73 | 7556939 | 2026-05-19T16:17:44Z |
| S-5.02 Claude heartbeat | #74 | 62c937d | 2026-05-19T16:44:25Z |
| S-5.07 per-finding card collapsibility | #75 | 84b0489 | 2026-05-19T17:42:02Z |
| S-6.01 scrub map merge | #76 | 896c9e2 | 2026-05-19T18:12:08Z |
| S-3.05 codecov coverage reporting | #77 | 51a3faf | 2026-05-19T18:32:29Z |
| S-3.01 Criterion + hyperfine perf | #78 | 0c64832 | 2026-05-19T19:02:15Z |
| S-3.02 Prompt eval harness | #79 | 18a7b62 | 2026-05-19T19:25:16Z |
| S-4.01 Kani scrub round-trip | #80 | fde249d | 2026-05-19T19:44:05Z |
| S-4.02 Kani leak-detector regex | #81 | 827d5b6 | 2026-05-19T20:00:57Z |
| S-4.03 Kani map-value substring | #82 | 31619ea | 2026-05-19T20:15:02Z |
| S-3.03 Mutation testing CI | #94 | cfd6058 | 2026-05-22T21:19:44Z |
| S-3.04 Fuzz harnesses | #95 | b7f7bf4 | 2026-05-22T21:56:58Z |
| S-4.04 Kani composed invariant | #96 | 5aaaff7 | 2026-05-23T02:53:00Z |
| S-6.02 diff subcommand core | #97 | 5f9963a | 2026-05-23T03:25:00Z |
| S-5.03 AI-augmented findings | #114 | 43fe86d | 2026-05-28T20:51:20Z |
| S-6.03 Diff HTML + markdown renderer | #119 | cb426fc | 2026-06-18T14:39:08Z |

Wave-1/2/3 gate results: see `cycles/v0.4.0-feature/adversarial-reviews/`
and `stories/sprint-state.yaml` (archived at
`cycles/v0.4.0-feature/sprint-state.yaml`).

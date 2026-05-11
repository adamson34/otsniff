---
artifact: artifact-inventory
phase: pre-1
generated: 2026-05-11T18:55:00Z
mode: brownfield
---

# Artifact inventory — otsniff

## VSDD-format artifacts inside `.factory/`

None. The factory worktree was just bootstrapped during this session; the
directory skeleton (`specs/`, `stories/`, `holdout-scenarios/`, etc.)
is in place but every index file is absent.

| Expected | Path | Status |
|---|---|---|
| Product Brief (L1) | `.factory/specs/product-brief.md` | MISSING |
| Domain Spec (L2) | `.factory/specs/domain-spec/L2-INDEX.md` | MISSING |
| PRD | `.factory/specs/prd.md` | MISSING |
| Behavioral Contracts (L3) | `.factory/specs/behavioral-contracts/BC-INDEX.md` | MISSING |
| Verification Properties (L4) | `.factory/specs/verification-properties/VP-INDEX.md` | MISSING |
| Architecture | `.factory/specs/architecture/ARCH-INDEX.md` | MISSING |
| Stories | `.factory/stories/epics.md`, `.factory/stories/stories/` | MISSING |
| Holdout scenarios | `.factory/holdout-scenarios/wave-scenarios/` | MISSING |
| Adversarial reviews | `.factory/cycles/**/adversarial-reviews/` | MISSING |

## Non-VSDD documentation present in the project

The project has substantial documentation accumulated over v0.1–v0.3.1
that maps **functionally** to several VSDD artifact roles but uses
otsniff's own conventions, not VSDD's L1–L4 hierarchy or
`BC-S.SS.NNN` numbering.

### Project-root and `docs/`

| Path | What it is | VSDD analog |
|---|---|---|
| `CLAUDE.md` | Project conventions, architecture overview, subcommand reference, design contract | Closest to Product Brief + lightweight Architecture |
| `README.md` | User-facing pitch, install, usage, scope | Marketing surface; not a VSDD artifact |
| `SECURITY.md` | Vulnerability reporting policy | Not a VSDD artifact |
| `CONTRIBUTING.md` | Contributor guide | Process doc; not a VSDD artifact |
| `docs/ROADMAP.md` | Prioritized backlog (P0/P1/P2), shipped items, non-goals | Closest to a backlog / PRD-supplement |
| `docs/RULES.md` | Auto-generated rule catalog (12 detectors with trigger conditions, data sources, MITRE/CWE/RFC references) | Closest to Behavioral Contracts + Verification Properties combined |
| `docs/audits/scrub-audit-cip011.md` | Field-by-field NERC CIP-011 / IEC 62443 audit | Verification artifact (privacy invariant); no direct VSDD analog |

### Architecture decisions

| Path | Title |
|---|---|
| `docs/adr/0001-pure-rust-no-zeek.md` | Pure Rust, no Zeek dependency |
| `docs/adr/0002-minimal-protocol-parsers.md` | Hand-rolled minimal protocol parsers |
| `docs/adr/0003-askama-with-preformatted-views.md` | askama compile-time templating |
| `docs/adr/0004-owned-packet-payloads.md` | Owned packet payloads in `Packet` struct |
| `docs/adr/0005-embedded-oui-table.md` | Embedded OT-vendor OUI table |
| `docs/adr/0006-scrub-unscrub-pseudonyms.md` | Scrub/unscrub for AI-assisted triage |
| `docs/adr/0007-ai-via-claude-cli.md` | AI via Claude Code CLI |

VSDD analog: Architecture Decision Records would feed into the
`architecture/ARCH-INDEX.md` and individual section files (e.g.
`tooling-selection.md`, `dependency-graph.md`).

### Per-feature specifications

| Path | Topic |
|---|---|
| `docs/specs/capture-source-detector.md` | Capture-source heuristic + AI prompt qualifier |
| `docs/specs/finding-dedup.md` | Rollup-by-kind for plaintext-cred findings |
| `docs/specs/flow-grouping.md` | Logical flow keying (drop src_port) |
| `docs/specs/hostname-extraction.md` | DHCP option 12 + CIP-011-aware scrub |
| `docs/specs/install-script.md` | curl-pipe-sh installer design |
| `docs/specs/investigation-playbooks.md` | Per-finding playbook contract |
| `docs/specs/new-rule-findings.md` | SMBv1 / stale TLS / DNS-resolver rules |
| `docs/specs/s7comm-parser.md` | S7Comm parser |
| `docs/specs/scrub-stance-template.md` | Required scrub-stance section for new specs |

VSDD analog: each spec is roughly a feature-level capability that
would decompose to one or more Behavioral Contracts and a Story.

## Format detection

- **Numbering format:** otsniff uses ADR-NNNN for architecture
  decisions and free-form filenames for per-feature specs. Does NOT
  use VSDD's `BC-S.SS.NNN` or `VP-NNN` schemes.
- **Architecture structure:** flat ADR directory plus per-feature
  specs. Does NOT use VSDD's sharded `ARCH-INDEX.md + 7 section
  files` layout.
- **Legacy FR-NNN format:** not detected. The non-VSDD format is
  otsniff's own, not the older VSDD format.

## Test surface (not a VSDD artifact, but relevant for routing)

100 tests pass on develop, organized as:

- `tests/cli_smoke.rs` — 11 end-to-end CLI tests
- `tests/snapshot.rs` — 20 insta snapshot tests (HTML report,
  scrubbed markdown, scrub map, audit log, AI section safety, etc.)
- Inline `#[cfg(test)]` modules — 69 unit tests across `src/`

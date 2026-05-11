# Product Brief: otsniff

**Author:** Luke Adamson (`adamson34`)
**Date:** 2026-05-11
**Status:** draft (brownfield-recovered — synthesized from Pass 0–6 of `.factory/semport/otsniff/`, `CLAUDE.md`, `README.md`, and `docs/ROADMAP.md`)

## Problem Statement

Small and medium operators of industrial control systems — utilities, manufacturers, water/wastewater plants — routinely capture PCAPs from plant networks for security review, but lack tooling to triage them.

Existing options are all wrong for this audience:

- **Wireshark** — capable but expert-only; no findings layer, no roll-up of what matters
- **Malcolm** (CISA/INL) — full Elasticsearch + Arkime + Logstash deployment; hours to stand up; not laptop-grade
- **Dragos / Nozomi / Claroty** — proprietary, ~$200k; effectively excludes small operators
- **NetworkMiner** — file/credential carving; not OT-aware

A consulting firm or in-house analyst captures a PCAP, then either spends 4+ hours in Wireshark or has nothing to show their leadership beyond raw packets. Critical OT-specific signals (engineering writes to PLCs, internet egress from plant networks, plaintext SCADA credentials) get missed because the tooling doesn't surface them.

**Stakes:** OT incidents like Colonial Pipeline, Florida water treatment, and various ICS ransomware events demonstrate that the gap between "we have a PCAP" and "we know what's wrong" matters at the safety level. Compliance pressure (NERC CIP, AWIA, IEC 62443, NIS2) is increasing for operators who don't have continuous monitoring.

## Target Users

### Primary

- **Small / mid-size OT operators with one IT person and no dedicated OT security analyst.** They have a laptop, occasionally capture a PCAP, can't afford the vendor platforms.
- **OT security consultants doing on-site assessments.** Their workflow is *visit plant → capture → analyze → write report*; analysis is the bottleneck.

### Secondary

- **Internal SOC analysts at larger operators** who already have vendor platforms but want a portable OT-aware tool for ad-hoc captures (incident response, vendor laptop forensics, etc.).
- **Researchers and educators** studying ICS protocols; CTF participants.

### Technical sophistication

Mixed. The primary user reads `tcpdump` output but doesn't write code. The secondary user is a Rust-or-Python comfortable engineer. The tool's UX defaults to "drop the file, get an HTML report" rather than scripted use.

## Value Proposition

A **single static binary** that turns a plant PCAP into an exec-readable security report in seconds, with **OT-aware detections** the IT-focused tools miss, and an **optional AI analysis pass** that never sends real plant data anywhere.

Three differentiators (validated against the alternatives above):

1. **OT-aware, laptop-grade.** Function-code-level recognition of Modbus, EtherNet/IP, S7Comm, with detections that name the threat (`ics.modbus_writes`, `creds.snmp`, `boundary.dns_resolver`). No vendor portal, no Elasticsearch, no agents.

2. **Privacy-preserving AI integration.** Operator gets Claude-grade analysis without sending real IPs / MACs / hostnames anywhere. Code-enforced via fail-closed leak detector. Compliance-aligned to NERC CIP-011 BCSI principles (designed-to-align-with, not certified).

3. **OSS, auditable.** Apache-2.0. Every rule, the scrub logic, the leak detector all in the same Rust source any analyst can read. Trust comes from inspection, not vendor reputation.

### Core thing it must do well

**Produce an exec-readable HTML report from one PCAP in under 60 seconds, with at least the load-bearing findings (plaintext creds, OT engineering writes, internet egress, SMB/TLS legacy, cross-zone DNS) named correctly and a usable inventory of assets.**

## Success Criteria

### Measurable outcomes

- **Coverage:** at least 12 rule-based detections shipping, each with non-empty playbook (currently met — 12 rules, all with playbooks; sentinel-tested).
- **Privacy invariant:** no real IP / MAC / hostname reaches the AI provider on any test fixture. Code-enforced. (Currently met — `invariant_no_real_values_reach_ai_provider` test passing.)
- **Performance:** 2.3M-packet capture (~209 MB) processes in <60s on a recent laptop. (Currently met anecdotally; not benchmarked formally — see L-P1-003 in `otsniff-pass-8-deep-synthesis.md`.)
- **Reproducibility:** byte-identical output for identical PCAP + flags. (Currently met — 20 snapshot tests covering HTML, markdown, scrubbed-markdown, scrub map, JSON.)
- **Single-binary install:** `curl … | sh` lands a working binary on macOS / Linux / Windows in under 60s. (Currently met — v0.3.1 published with 4-platform artifacts.)
- **Detection accuracy:** every fired finding's id appears in the rule catalog with a plain-English trigger description. (Currently met — sentinel-tested.)

### MVP vs full vision

- **MVP (shipped at v0.3.1):** rules-based report + scrub layer + Claude CLI integration + 12 detection rules + capture-source heuristic + privacy audit log.
- **Near-term vision:** DNP3 parser (electric utilities); OUI table expansion; AI-augmented detection that cross-references findings; 5–7 additional rule families (NTLMv1, weak TLS ciphers, RDP-no-NLA, NTP-external, LDAP simple bind, port scan, Modbus unit-ID sweep).
- **Long-term vision:** OPC-UA + BACnet parsers (modern industrial + building automation); cross-capture diff; web playground (WASM); native packaging (Homebrew tap, AUR); local-AI provider (Ollama).

## Scope

### In Scope

- Offline PCAP / PCAPNG analysis on Ethernet captures
- Modbus/TCP, EtherNet/IP, S7Comm protocol awareness at function-code level (ADR-0002)
- Findings, asset inventory, comms-matrix in self-contained HTML
- LLM-friendly markdown rendering (`--md` sidecar)
- Capture-source heuristic classification with `--source-type` override
- Scrub/unscrub pipeline + closed-loop AI triage via local `claude` CLI
- Per-run privacy audit log with chain-of-custody SHA-256s
- Investigation playbooks per finding
- Rule catalog (`otsniff rules`, `docs/RULES.md`)

### Out of Scope (deliberately)

- **Live capture / agent / sensor mode** — use Malcolm or a vendor platform
- **Detection rules / IDS alerting / dashboards** — use Suricata / Zeek for signature-based detection
- **Full protocol decoding** — we recognize function/service codes, not full PDU payload semantics
- **Compliance attestation** — the project *aligns with* NERC CIP / IEC 62443 handling but does not certify
- **HTTP / SDK / vendor cloud for AI** — AI is shell-out to local `claude` CLI (ADR-0007)
- **Embedded LLM client** — user picks AI provider; we don't bundle one (ADR-0006)
- **Node.js / npm in toolchain** — supply-chain conscious; pure Rust dependency tree
- **Async runtime** — sync throughout
- **Multi-user / multi-tenant** — single-machine tool
- **Auto-updates / phone-home / telemetry** — none. Pure local tool.

## Constraints

### Technical

- **Pure Rust.** ADR-0001 prohibits Zeek dependency. ADR-0007 prohibits embedded HTTP/SDK to AI providers.
- **Single static binary.** Compiled by `cargo build --release` with `lto = "thin"`, `codegen-units = 1`, `strip = true`. Cross-compiled to 4 targets (aarch64-apple-darwin, x86_64-apple-darwin, x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu).
- **MSRV 1.85** — Rust edition 2021. Bumped from 1.75 because transitive deps required `edition = "2024"`.
- **No `unsafe` code.** Every introduction would require a `// SAFETY:` justification.
- **Single-pass observer.** Memory bound by unique hosts/flows/events, not raw packets.
- **Determinism.** Same inputs → byte-identical outputs. `BTreeMap` over `HashMap` where iteration order matters.

### Timeline / team

- **Solo maintainer.** One author. Cadence calibrated for one person.
- **Public OSS since 2026-05-11.** v0.3.1 is the current release.
- **No support SLA.** Issues filed publicly; security disclosure private (GitHub Advisories).

### Regulatory / compliance

- **NERC CIP-011 BCSI alignment** — see `docs/audits/scrub-audit-cip011.md`. Designed to align with BES Cyber System Information handling principles. Not a certification.
- **IEC 62443-3-3 / TSA / NIS2** — analogous frameworks; same scrub-stance posture applies.
- **No HIPAA / GDPR / PCI** — not in scope; the tool doesn't process PII or payment data.

## Prior Art & References

### Open-source

- **Malcolm** (https://github.com/idaholab/Malcolm) — full network-traffic analysis platform. otsniff is "what to use when Malcolm is too heavy."
- **Zeek** (https://zeek.org) — script-driven network analysis. Considered + rejected as a dependency (ADR-0001). Used as reference for protocol parser fidelity (ICSNPP).
- **Suricata** (https://suricata.io) — signature-based IDS. Complementary, not competitive: otsniff does behavioral detection, Suricata does signatures.
- **NetworkMiner** (https://www.netresec.com/?page=NetworkMiner) — file/credential carving. otsniff is closer to "report builder" than "carver."

### Commercial

- **Dragos** (https://www.dragos.com) — vendor platform; not a competitor at our price/audience tier.
- **Nozomi Networks** (https://www.nozominetworks.com)
- **Claroty** (https://claroty.com)

### Public PCAP sources for testing

- **4SICS ICS Lab** (https://www.netresec.com/?page=PCAP4SICS) — primary fixture corpus.
- **ICS-pcap** (https://github.com/automayt/ICS-pcap) — community collection.
- **ICSNPP test traces** (https://github.com/cisagov/icsnpp) — per-protocol fixtures.

### Existing documentation

- 7 ADRs in `docs/adr/` (ADR-0001 through 0007)
- 9 per-feature specs in `docs/specs/`
- 1 audit document: `docs/audits/scrub-audit-cip011.md`
- Auto-generated rule catalog: `docs/RULES.md`
- Roadmap: `docs/ROADMAP.md`
- Brownfield analysis: `.factory/semport/otsniff/` (Pass 0–6 + B.5 audit + B.6 validation + Pass 8 synthesis)

## Open Questions

These are the items NOT decisively answered by the brownfield-recovered brief, flagged so the PRD step can pin them down:

### OQ-1 — Long-term monetization posture

Is the long-term plan:

- **A.** Pure OSS, no monetization (current state)
- **B.** OSS + paid SaaS (host otsniff for consultants per-customer)
- **C.** OSS + enterprise tier (multi-customer dashboards, SIEM integrations)
- **D.** Consulting / support contracts as the only paid layer

Different answers change downstream architecture choices (B requires a hosted service; C requires multi-tenant features and customer auth; D requires nothing technical). Today the project posture is A by default; this should be a deliberate decision rather than drift.

### OQ-2 — Detection rule velocity / community contribution

The 12 rules today were authored by one maintainer. The roadmap proposes 5–7 additional rules. Open question: will rules continue to be in-tree code-only, or should the project support user-supplied rules (e.g., a TOML config or domain-specific YAML)? Earlier strategic discussion concluded "in-tree until 25+ rules accumulate; then re-evaluate." This brief inherits that posture but the PRD might revisit if a community contributor explicitly asks.

### OQ-3 — Cross-event correlation

The methodology surfaced that otsniff today has no cross-detector correlation ("engineer FTP'd in then issued Modbus writes within 30s"). Should this be a goal for v0.4 or v0.5? Adding it changes the detector data model (Findings would carry references to other Findings). Architecture review concluded: defer until a real correlation requirement is documented.

### OQ-4 — Formal verification of the privacy invariant (Kani)

The brownfield analysis identifies Kani proofs as the single highest-leverage verification artifact for otsniff. Open question: is this a v0.4 deliverable or deferred indefinitely? Trade-off: real compliance-posture differentiator vs. 1 week of Kani learning curve + ongoing maintenance.

### OQ-5 — Cred event memory bound

`obs.cred_events: Vec<CredEvent>` is the one accumulator that scales linearly with raw packets, not unique events. For long-duration Telnet captures this is unbounded. Should pre-rollup dedup land in v0.4? See L-P1-002 in Phase 0 synthesis.

---

These five open questions should be resolved (or explicitly deferred with a recorded decision) before the PRD step finalizes the BC list and the architecture shards.

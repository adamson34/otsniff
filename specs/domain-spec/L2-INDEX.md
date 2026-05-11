---
artifact_type: domain-spec-index
project: otsniff
generated: 2026-05-11
status: draft (brownfield-recovered)
traces_to:
  - product-brief.md
  - .factory/semport/otsniff/otsniff-pass-2-domain-model.md
---

# L2 Domain Specification — otsniff

The L2 domain model decomposes the problem domain into bounded
contexts, entities, value objects, relationships, and the ubiquitous
language used across the project. See the sharded files below for
each section.

## Capabilities (CAP-NNN)

The L2 capabilities — top-level units of value the product delivers.

| ID | Capability | Spec ref |
|---|---|---|
| CAP-001 | Read PCAP / PCAPNG and extract per-packet metadata at L2–L4 (ethernet, IPv4/IPv6, TCP/UDP) | `domain-observation.md` |
| CAP-002 | Recognize protocol-level signals for Modbus/TCP, EtherNet/IP CIP, S7Comm, DHCP option 12, plaintext credentials (FTP/Telnet/HTTP-Basic/SNMP), SMBv1 magic, TLS legacy versions | `domain-observation.md` |
| CAP-003 | Accumulate observations into a typed, deterministic, single-pass state struct | `domain-observation.md` |
| CAP-004 | Classify capture provenance (SPAN / host-side / TAP / ambiguous) heuristically with optional explicit override | `domain-analysis.md` |
| CAP-005 | Derive an asset inventory with inferred role per host (PLC / HMI / EWS / historian / network infra / IT endpoint) | `domain-analysis.md` |
| CAP-006 | Run a catalog of detection rules over observations and produce prioritized findings with playbooks | `domain-analysis.md` |
| CAP-007 | Pseudonymize all observed identifiers (IP, MAC, hostname) into stable scrub classes | `domain-privacy.md` |
| CAP-008 | Enforce — at runtime, fail-closed — that no real identifier reaches an AI provider | `domain-privacy.md` |
| CAP-009 | Invoke a user-local AI provider (Claude CLI) with scrubbed payload, capture response, restore real values | `domain-privacy.md` |
| CAP-010 | Persist a chain-of-custody audit log per AI invocation with cryptographic hashes of the exact bytes exchanged | `domain-privacy.md` |
| CAP-011 | Render observations + findings + asset inventory + (optional) AI analysis into a self-contained HTML report | `domain-rendering.md` |
| CAP-012 | Surface the detection rule catalog in three forms: print to stdout (`otsniff rules`), committed `docs/RULES.md`, inline "Detection criteria" in every fired finding | `domain-analysis.md` |

## Bounded contexts

Three contexts. Each shard is a separate file under `.factory/specs/domain-spec/`.

| Context | File | Vocabulary |
|---|---|---|
| **Observation** | `domain-observation.md` | Packet, Transport, Flow, FlowKey, ModbusEvent, EnipEvent, S7Event, CredEvent, ExternalFlow, HostObs, Observations |
| **Analysis** | `domain-analysis.md` | Asset, Role, Finding, Severity, RuleMetadata, Reference, Classification, CaptureSource, DeclaredSource |
| **Privacy + Rendering** | `domain-privacy.md` | ScrubMap, pseudonym classes (host_NNN / mac_NNN / name_NNN), AuditLog, AiProvider, ClaudeCliProvider, leak detector verdicts |
|  | `domain-rendering.md` | ReportView, AssetView, FindingView, TopFlow, ai_section, rendered HTML / markdown / JSON |

The boundary between contexts is enforced by Rust's module system:
the `Observations` struct flows context 1 → 2; `Vec<Finding>` +
`Vec<Asset>` + `Classification` flow context 2 → 3.

## Cross-context invariants

| Invariant | Cross context | Where enforced |
|---|---|---|
| **Privacy invariant.** No real value (IP, MAC, hostname) reaches an AI provider. | Observation → Privacy | `src/ai/leak_detector.rs::ensure_clean` + `ensure_no_map_values` |
| **Scrub round-trip.** `unscrub(scrub(x, map), map) == x`. | Privacy internal | `src/scrub.rs` |
| **Determinism.** Same `Observations` → byte-identical render output. | Analysis → Rendering | `BTreeMap` + `sort_by` throughout |
| **Rule catalog completeness.** Every fired Finding's id appears in `findings::catalog()`. | Analysis → Rendering | `findings::run_all` + `RuleMetadata` |
| **Audit log no-leak.** Per-run audit JSON never contains real identifiers. | Privacy internal | `src/cli.rs::run_analyze` pre-write leak check |
| **AI HTML safety.** Markdown-to-HTML conversion drops raw HTML events. | Privacy → Rendering | `src/ai/html_render::render_safe` |

## Ubiquitous language

The terms used consistently across the codebase, documentation, and
domain. Definitions follow Pass 2's compilation.

| Term | Definition |
|---|---|
| **Observation** | A fact extracted from one or more packets without interpretation. Counts, presence, raw labels. |
| **Finding** | An interpreted observation that warrants operator action. Carries severity, evidence, recommendation, and playbook. |
| **Flow** | Logical aggregation of packets by `(src, dst, dst_port, proto)`. NOT a TCP connection — drops ephemeral `src_port`. |
| **Connection** | A single `(src_port, dst_port)` tuple within a flow. Counted as `flow.unique_src_ports.len()`. |
| **Event** | A point-in-time protocol-specific observation: Modbus PDU, ENIP command, S7 function call, credential line. |
| **Engineering-class** | A function code or service that writes / changes / stops device state. Used to filter detector input for `ics.*` rules. |
| **Scrub** | Pseudonymize observed identifiers before they reach an AI provider. |
| **Pseudonym class** | One of `host_NNN`, `mac_NNN`, `name_NNN`. Format is regex-safe and part of the public contract (ADR-0006). |
| **OT zone** | A CIDR range supplied via `--ot-subnet`. Default is RFC1918. Used by cross-zone rules. |
| **BCSI** | "BES Cyber System Information." NERC CIP-011 term for plant-identifying data. otsniff's scrub stance aligns with BCSI handling. |
| **Privacy invariant** | "No real value reaches the AI provider." Enforced by fail-closed leak detector. |
| **Capture source** | One of SPAN / host-side / TAP / ambiguous. Different sources need different report interpretation. |
| **Asset** | A host with inferred role and rolled-up metadata. The inventory table is `Vec<Asset>`. |
| **Rule catalog** | The metadata block per rule (12 today). Surfaced via `otsniff rules`, `docs/RULES.md`, and inline "Detection criteria" in every fired finding. |
| **Playbook** | A `Vec<String>` of concrete next-action steps tied to a finding's actual evidence. Different from `recommendation` (single sentence). |
| **Leak detector** | The fail-closed code path (regex check + map-value check) between the scrub layer and any AI provider invocation. |
| **Audit log** | A per-run JSON artifact recording chain-of-custody hashes of the bytes sent to / received from the AI. Never contains real identifiers. |

## Open questions inherited from the brief

OQ-1 (monetization), OQ-2 (community rules), OQ-3 (cross-event
correlation), OQ-4 (Kani proofs), OQ-5 (cred_events memory bound) —
see `product-brief.md` § Open Questions. The L2 domain model is
sound regardless of which way these are decided; OQ-3 would change
the data model by adding finding-to-finding references but doesn't
otherwise touch L2.

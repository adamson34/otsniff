---
artifact_type: prd
project: otsniff
version: 1.0
generated: 2026-05-11
status: draft (brownfield-recovered)
traces_to:
  - product-brief.md
  - domain-spec/L2-INDEX.md
  - .factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md
  - .factory/semport/otsniff/otsniff-extraction-validation.md
---

# Product Requirements Document — otsniff

PRD recovered from v0.3.1 shipped state. Functional requirements
trace to existing behavior; non-functional requirements come from
Pass 4 NFR catalog with B.6 corrections applied.

## 1. Functional Requirements

### Subsystem S.0 — PCAP iteration

| ID | Requirement | BC trace |
|---|---|---|
| FR-001 | Read PCAP/PCAPNG files via `pcap-parser` and decode L2–L4 via `etherparse`, yielding owned `Packet` records | BC-0.01.001 |
| FR-002 | Reject non-PCAP input with `OtError::BadInput` and exit code 2 | BC-0.01.002 |
| FR-003 | Reject missing input files with `OtError::InputOpen` and exit code 2 | BC-0.01.003 |
| FR-004 | Packets carry timestamp, src/dst MACs, src/dst IPs, src/dst ports, transport, owned payload | BC-0.01.001, BC-0.01.004 |

### Subsystem S.1 — Observation and protocol parsing

| ID | Requirement | BC trace |
|---|---|---|
| FR-101 | Accumulate per-packet observations into a single typed `Observations` struct in a single pass | BC-1.01.001 |
| FR-102 | Aggregate flows by `(src, dst, dst_port, proto)` — drop ephemeral source port | BC-1.01.002 |
| FR-103 | Recognize Modbus PDUs on tcp/502 and classify by function code (engineering = 0x05, 0x06, 0x08+subfn 0x01, 0x0F, 0x10, 0x15, 0x16, 0x17) | **BC-1.02.001 (B.6 corrected)** |
| FR-104 | Recognize EtherNet/IP encapsulation on tcp/44818; flag CIP services we classify as engineering (Stop, Reset, Apply Attributes, Forward Close to controller) | BC-1.02.002 |
| FR-105 | Recognize S7Comm PDUs on tcp/102; classify by function code with engineering flag (PLC stop/start, block download/upload) — **note: "password ops" wording in original BC was inaccurate (B.6 finding)** | **BC-1.02.003 (B.6 corrected)** |
| FR-106 | Recognize DHCP option 12 on udp/67,68; associate hostname with yiaddr (priority) or ciaddr (fallback) or option-50 requested IP | BC-1.02.004 |
| FR-107 | Detect plaintext credential traffic: FTP `USER`/`PASS` lines (tcp/21), any Telnet payload (tcp/23), HTTP Basic auth lines (tcp/80,8080), SNMPv1/v2c BER-tagged messages (udp/161,162) | BC-1.03.001–004 |
| FR-108 | Detect SMBv1 magic bytes `\xFF SMB` at offset 0 or 4 on tcp/445,139 | BC-1.04.001 |
| FR-109 | Capture TLS ClientHello `legacy_version` field on tcp/443,8443 | BC-1.04.002 |
| FR-110 | Aggregate cross-zone egress: src in `--ot-subnet` AND dst is public | BC-1.05.001 |
| FR-111 | Default OT zone is RFC1918 (10/8, 172.16/12, 192.168/16) when no `--ot-subnet` flag is supplied | BC-1.05.002 |

### Subsystem S.2 — Asset inventory

| ID | Requirement | BC trace |
|---|---|---|
| FR-201 | Derive `Asset` per host with role inference (PLC vendors + ICS protocols → Plc; SCADA shape → Hmi; etc.) | BC-2.01.001 |
| FR-202 | Populate `Asset.hostname` from `obs.hostnames` lookup; `None` when unknown | BC-2.01.002 |

### Subsystem S.3 — Detection rules

| ID | Requirement | BC trace |
|---|---|---|
| FR-301 | Emit one `creds.{ftp,telnet,http_basic,snmp}` Finding per CredKind seen — Severity Critical | BC-3.01.001, .002 |
| FR-302 | Roll up credential findings by `(dst, port)` within kind; cap evidence at 15 lines | BC-3.01.003 |
| FR-303 | Emit `egress.ot_to_internet` (Severity Critical) when `obs.external_flows` is non-empty | BC-3.02.001 |
| FR-304 | Emit `ics.{modbus_writes,cip_engineering,s7_engineering}` (Severity High → Critical if any source IP is outside `--ot-subnet`) | BC-3.03.001–.003 |
| FR-305 | Emit `compat.smbv1` (Severity High) on any SMBv1 observation | BC-3.04.001 |
| FR-306 | Emit `compat.stale_tls` (Severity Medium) when any ClientHello version is in `{0x0300, 0x0301, 0x0302}` | BC-3.04.002 |
| FR-307 | Emit `boundary.dns_resolver` (Severity Medium) when a flow on `dst_port=53` has src in OT AND dst NOT in OT | BC-3.05.001 |
| FR-308 | Emit `ot.unexpected_protocols` (Severity Medium) when a flow whose `src OR dst` is in OT carries a port-derived label in the no-fly list (`anydesk, apns, bittorrent, gcm, irc, openvpn, rtmp, sip, smtp, stun, teamviewer` — 11 labels) | **BC-3.05.002 (B.6 corrected — see L-P0-001)** |
| FR-309 | Sort findings by severity DESC then id ASC | BC-3.06.001 |
| FR-310 | Every fired Finding's `id` must appear in `findings::catalog()` (sentinel-tested) | BC-3.06.002 |
| FR-311 | Every Finding must carry a non-empty `playbook: Vec<String>` (sentinel-tested) | BC-3.06.003 |
| FR-312 | When `obs.hostnames` knows a name for an IP, finding evidence renders `HOSTNAME (1.2.3.4)` not just the IP | BC-3.06.004 |

### Subsystem S.4 — Capture-source classification

| ID | Requirement | BC trace |
|---|---|---|
| FR-401 | Classify as `HostSide` when one MAC at ≥95% of frames AND second-MAC at <30% | BC-4.01.001 |
| FR-402 | Classify as `Tap` when top two MACs both at ≥95% coverage AND third <10% | BC-4.01.002 |
| FR-403 | Classify as `Span` when ≥10 distinct MACs AND dominant MAC <60% AND broadcasts present | BC-4.01.003 |
| FR-404 | When user passes `--source-type`, that declaration is authoritative for `report_line()` and AI prompt qualifier; heuristic verdict preserved on `Classification::source` | BC-4.02.001 |
| FR-405 | When declared type and heuristic type disagree (and heuristic is not Ambiguous), `guard_warning()` returns a stderr-ready warning | BC-4.02.002 |

### Subsystem S.5 — Privacy: scrub + leak detector

| ID | Requirement | BC trace |
|---|---|---|
| FR-501 | Mint deterministic pseudonyms keyed sorted by real value: `host_NNN` (IPs), `mac_NNN` (MACs), `name_NNN` (hostnames) | BC-5.01.001 |
| FR-502 | `scrub_text` substitutes only values present in the `ScrubMap` — no false positives on IP-shaped substrings | BC-5.01.002 |
| FR-503 | `unscrub_text(scrub_text(x, map), map) == x` for any text containing only mapped pseudonyms + ordinary prose | BC-5.01.003 |
| FR-504 | Leak detector regex scans for IPv4 dotted-quad, IPv6 abbreviated forms, MAC colon-hex | BC-5.02.001 |
| FR-505 | `ensure_no_map_values` iterates every real value in the ScrubMap and verifies absence verbatim | BC-5.02.002 |
| FR-506 | Combined check (`ensure_clean` + `ensure_no_map_values`) on the scrubbed report AND on the assembled user message AND on the audit log JSON — fail-closed on any leak | BC-5.02.003 |

### Subsystem S.6 — AI orchestration

| ID | Requirement | BC trace |
|---|---|---|
| FR-601 | Render AI markdown response to HTML with `Event::Html` and `Event::InlineHtml` filtered out (XSS defense) | BC-6.01.001 |
| FR-602 | System prompt has 4 capture-source-tag variants (span / host-side / tap / ambiguous); each is snapshot-tested | BC-6.02.001 |
| FR-603 | AI invocation is via subprocess shell-out to `claude -p` — no HTTP, no SDK | BC-6.03.001 |

### Subsystem S.7 — Audit log

| ID | Requirement | BC trace |
|---|---|---|
| FR-701 | When `--ai` is on and no `--audit-log` override is given, audit log auto-writes to `<output-stem>.audit.json` | BC-7.01.001 |
| FR-702 | Audit log's recorded SHA-256s match the bytes actually sent to / received from the AI provider | BC-7.01.002 |
| FR-703 | Audit log contains no real identifiers (sentinel-tested) | BC-7.01.003 |
| FR-704 | `CredEvent.note` is `#[serde(skip)]` and never reaches HTML, markdown, scrubbed-markdown, or per-event JSON (sentinel-tested) | BC-7.02.001 |

### Subsystem S.8 — Rendering

| ID | Requirement | BC trace |
|---|---|---|
| FR-801 | `render_html` is deterministic per inputs (sentinel-tested via snapshot) | BC-8.01.001 |
| FR-802 | `rule_catalog::render_markdown` output matches the committed `docs/RULES.md` | BC-8.02.001 |
| FR-803 | Scrubbed markdown contains no real identifiers from any fixture | BC-8.03.001 |

### Subsystem S.9 — CLI

| ID | Requirement | BC trace |
|---|---|---|
| FR-901 | `analyze <PCAP> -o <HTML>` defaults to rules-only HTML output | BC-9.01.001 |
| FR-902 | `analyze --ai <PCAP> -o <HTML>` engages the full privacy pipeline (scrub → leak-check → claude → unscrub → embed) | BC-9.01.002 |
| FR-903 | `scrub` / `unscrub` round-trip exits 0 with pseudonyms restored; `--strict` exits non-zero on unmapped tokens | BC-9.02.001 |
| FR-904 | `otsniff rules [--format md|json]` prints the catalog to stdout without requiring a PCAP | BC-9.03.001 |

## 2. Non-Functional Requirements

Per Pass 4 NFR catalog. Each NFR carries a measurable target where applicable.

### Performance

| ID | NFR | Target |
|---|---|---|
| NFR-PERF-001 | Single-pass observer | O(N) in packet count |
| NFR-PERF-002 | Memory bound proportional to unique hosts/flows/events | Caveat: `cred_events` unbounded — see OQ-5 |
| NFR-PERF-003 | Release profile: `lto=thin`, `codegen-units=1`, `strip=true` | Binary size ≤ 3 MB |
| NFR-PERF-004 | Stream-hashed PCAP input | 64 KB chunk buffer in audit log SHA-256 computation |
| NFR-PERF-005 | Linear-time pseudonym substitution within current map sizes | Acceptable for reports under 10 MB |

### Security

| ID | NFR | Target |
|---|---|---|
| NFR-SEC-001 | Privacy invariant enforced by code | Sentinel test `invariant_no_real_values_reach_ai_provider` passes on every CI run |
| NFR-SEC-002 | Two-layer leak detection (regex + map-value) | Both must pass before AI invocation; either failing aborts the run |
| NFR-SEC-003 | No `unsafe` code in `src/` | Lint enforced by convention; grep-verified |
| NFR-SEC-004 | AI markdown XSS defense | Sentinel test `ai_section_in_html_strips_script_tags_from_claude_response` passes |
| NFR-SEC-005 | NERC CIP-011 BCSI alignment documented | `docs/audits/scrub-audit-cip011.md` covers every extractor + render surface |
| NFR-SEC-006 | Scrub map JSON is treated as a secret with same threat model as the original PCAP | Documented in README + ADR-0006 |
| NFR-SEC-007 | `CredEvent.note` cannot leak | `#[serde(skip)]` + sentinel test |
| NFR-SEC-008 | No HTTP / SDK to AI vendor | Architectural: ADR-0007 |
| NFR-SEC-009 | Branch protection on main + develop | 5 status checks required; no force push; no delete |
| NFR-SEC-010 | Vulnerability disclosure via private channel | SECURITY.md routes to GitHub Security Advisories |

### Observability

| ID | NFR | Target |
|---|---|---|
| NFR-OBS-001 | `--verbose` mode emits privacy ledger lines during `analyze --ai` | scrub counts, leak-check verdicts, AI timing, unscrub stats |
| NFR-OBS-002 | Audit log is the post-run privacy receipt | JSON, written for every `--ai` invocation |
| NFR-OBS-003 | `--json findings.json` sidecar | inventory + findings structured serialization |
| NFR-OBS-004 | "Detection criteria" inline in every fired finding | sourced from `RuleMetadata::trigger` |
| NFR-OBS-005 | `otsniff rules` for catalog inspection | works without a PCAP |

### Reliability

| ID | NFR | Target |
|---|---|---|
| NFR-REL-001 | Byte-identical output for identical input | 20 snapshot tests + `cargo insta review` for output changes |
| NFR-REL-002 | Fail-closed on privacy violation | Run aborts BEFORE AI invocation with descriptive error |
| NFR-REL-003 | Sysexits-style exit codes | 2 for bad/missing input; 1 for other failures; 0 for success |
| NFR-REL-004 | Snapshot tests cover all output surfaces | HTML, markdown, scrubbed markdown, scrub map, JSON, prompts |
| NFR-REL-005 | Sentinel tests guard each cross-cutting invariant | At least 9 sentinel tests today |
| NFR-REL-006 | No `unwrap()` / `expect()` on data-dependent values | Compile-time-validated literals only |

### Scalability

| ID | NFR | Target |
|---|---|---|
| NFR-SCALE-001 | 2.3M-packet capture (~209 MB) processes in under 60s | Anecdotal; not benchmarked formally (see L-P1-003) |
| NFR-SCALE-002 | Linear scaling with packet count | Architectural |
| NFR-SCALE-003 | Single-binary deployment, no horizontal scaling | Architectural |

### Privacy / compliance

| ID | NFR | Target |
|---|---|---|
| NFR-PRIV-001 | Designed-to-align-with NERC CIP-011 / IEC 62443 / TSA / NIS2 — not certified | Documented in README + ADR-0006 |
| NFR-PRIV-002 | Audit document specifies alignment claims | `docs/audits/scrub-audit-cip011.md` |
| NFR-PRIV-003 | Scrub-stance template required in every new feature spec | `docs/specs/scrub-stance-template.md` |

## 3. Edge cases catalog

Boundary conditions every requirement must consider:

| Case | Behavior |
|---|---|
| Empty PCAP (0 packets) | `total_packets = 0`; `Classification::Ambiguous { reason: "no frames parsed" }`; 0 findings; HTML report renders normally |
| 1 packet | Same shape as normal run; finding firing depends on whether the packet matches any detector trigger |
| All-IPv6 capture | Hosts keyed by IPv6 addresses; `is_public` IPv6 path handles loopback / ULA / multicast |
| Capture with no DHCP | `obs.hostnames` empty; `Asset.hostname = None`; evidence renders bare IPs; sentinel test still validates the path on a fixture with hostnames |
| Capture with only ICMP / non-TCP/UDP | `mac_frame_counts` updated; no `FlowObs` records produced; capture-source classification may be Ambiguous |
| Modbus packet with malformed MBAP | `parse::modbus::parse` returns `None`; no `ModbusEvent` produced; packet still counts toward host/flow stats |
| TLS ClientHello with extension that pushes legacy_version offset | Per our parser, we read bytes [9..11] regardless — if those bytes don't represent a real legacy_version (e.g. fragmented record), we still record what we read. Tested by snapshot fixture. |
| Claude returns response containing `<script>` | `ai::html_render::render_safe` strips it; rendered HTML safe. Tested. |
| Claude returns response containing valid pseudonym `host_999` not in our map | `unscrub_text` leaves it as-is; `unmapped` count increments; `--strict` mode would error |
| `--ai` set without `claude` CLI installed | `ClaudeCliProvider::analyze` fails; `OtError::AiProvider` propagates; exit code 1 |
| `--audit-log` set without `--ai` | Audit log path is computed but not used (no AI invocation = nothing to record) |
| `--ot-subnet` with overlapping CIDRs | `is_public` and `in_ot_zone` use first-match logic via `IpNet::contains`; equivalent to union semantics |
| `--source-type` declared, heuristic returns Ambiguous | No warning (Ambiguous is treated as "no opinion") |
| `--source-type` declared, declared matches heuristic kind | No warning |

## 4. Open questions (to resolve before stories)

Inherited from product brief; restated here so they don't drift:

- **OQ-1** Long-term monetization posture
- **OQ-2** Detection rule velocity / community contribution
- **OQ-3** Cross-event correlation (would touch the Finding data model)
- **OQ-4** Kani proofs of the privacy invariant — v0.4 deliverable or deferred?
- **OQ-5** `cred_events` Vec memory bound — pre-rollup dedup in v0.4?

## 5. B.6 corrections applied

Three BC inaccuracies from Phase 0 B.6 are corrected in this PRD:

| Original BC | Issue | Correction in PRD |
|---|---|---|
| BC-1.02.001 Modbus engineering | sub-functions under-specified | FR-103 enumerates the exact function-code set (0x05, 0x06, 0x08+subfn 0x01, 0x0F, 0x10, 0x15, 0x16, 0x17) |
| BC-1.02.003 S7 "password ops" | "password ops" wording not in code | FR-105 narrows to PLC stop/start, block download/upload (the actually-implemented classifiers) |
| BC-3.05.002 no-fly list | listed 7 labels; zone predicate wrong | FR-308 enumerates all 11 labels and corrects the predicate to "src OR dst in OT" |

The third correction is the real-bug case (L-P0-001) — the trigger
description in the source code still has the old 7-label list and
"src in OT AND dst not in OT" predicate. **Source-code fix is
required** for FR-308 to match reality. Stories will track this.

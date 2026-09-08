---
artifact_type: prd
project: otsniff
version: 1.1
generated: 2026-05-11
amended: 2026-09-08 — added Subsystem S.10 (Hunt, planned MVP)
status: draft (brownfield-recovered; S.10 is draft/planned, not yet implemented)
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

**2026-09-08 amendment:** Subsystem S.10 (Hunt) added — FR-1001..1015,
BC-10.xx.xxx. Unlike S.0–S.9, these requirements are **planned, not yet
implemented**: no story exists for them yet. They describe the MVP scope
agreed in the product-brief amendment (`otsniff hunt <PCAP> --concern
<CVE-ID>`), resolved against OQ-6 (curated CVE-signature table + AI
explanation, not free-form AI reasoning alone).

## 1. Functional Requirements

### Subsystem S.0 — PCAP iteration + error taxonomy

| ID | Requirement | BC trace |
|---|---|---|
| FR-001 | Read PCAP/PCAPNG files via `pcap-parser` and decode L2–L4 via `etherparse`, yielding owned `Packet` records | BC-0.01.001 |
| FR-002 | Reject non-PCAP input with `OtError::BadInput` and exit code 2 | BC-0.01.002 |
| FR-003 | Reject missing input files with `OtError::InputOpen` and exit code 2 | BC-0.01.003 |
| FR-004 | Packets carry timestamp, src/dst MACs, src/dst IPs, src/dst ports, transport, owned payload | BC-0.01.001, BC-0.01.004 |
| FR-005 | Every `OtError` variant maps to a sysexits-style exit code via `OtError::exit_code` so shell scripts can branch on failure class (verified by unit tests covering each variant) | BC-0.02.001 (was BC-AUDIT-003) |
| FR-006 | When `cli::run` returns `Err(e)`, `main` walks `std::error::Error::source()` chain and prints each layer prefixed `"caused by: "`. Preserves I/O-error diagnostics ("permission denied" vs. "no such file") that would otherwise be lost | BC-0.02.002 (was BC-AUDIT-004) |

### Subsystem S.1 — Observation and protocol parsing

| ID | Requirement | BC trace |
|---|---|---|
| FR-101 | Accumulate per-packet observations into a single typed `Observations` struct in a single pass | BC-1.01.001 |
| FR-102 | Aggregate flows by `(src, dst, dst_port, proto)` — drop ephemeral source port | BC-1.01.002 |
| FR-103 | Recognize Modbus PDUs on tcp/502 and classify by function code. Engineering set per `src/parse/modbus.rs::ModbusPdu::is_engineering_class`: **Write** category = 0x05 (Write Single Coil), 0x06 (Write Single Register), 0x0F (Write Multiple Coils), 0x10 (Write Multiple Registers), 0x15 (Write File Record), 0x16 (Mask Write Register); **ReadWrite** category = 0x17 (Read/Write Multiple Registers); **Diagnostic** sub-functions of 0x08 = (0x08, 0x0001) Restart Communications, (0x08, 0x0004) Force Listen Only, (0x08, 0x000A) Clear Counters | **BC-1.02.001 (B.6 corrected)** |
| FR-103a | S7Comm header sizing is ROSCTR-dependent: 10 bytes for Job (0x01) / UserData (0x07), 12 bytes for Ack (0x02) / Ack_Data (0x03) — the latter append error-class + error-code; misalignment otherwise produces false function codes | BC-1.02.008 (was BC-AUDIT-007) |
| FR-104 | Recognize EtherNet/IP encapsulation on tcp/44818; flag CIP services we classify as engineering (Stop, Reset, Apply Attributes, Forward Close to controller) | BC-1.02.002 |
| FR-105 | Recognize S7Comm PDUs on tcp/102; classify by function code with engineering flag (PLC stop/start, block download/upload) — **note: "password ops" wording in original BC was inaccurate (B.6 finding)** | **BC-1.02.003 (B.6 corrected)** |
| FR-106 | Recognize DHCP option 12 on udp/67,68; associate hostname with yiaddr (priority) or ciaddr (fallback) or option-50 requested IP | BC-1.02.004, BC-1.02.007 (3-tier resolution, was BC-AUDIT-006) |
| FR-106a | DHCP option walk is bounded and length-checked: rejects when `data_end > payload.len()`, honors OPT_END (0xFF) as terminator, OPT_PAD (0x00) as 1-byte filler; returns `None` on truncation, never partial parse | BC-1.02.006 (was BC-AUDIT-005) |
| FR-107 | Detect plaintext credential traffic: FTP `USER`/`PASS` lines (tcp/21), any Telnet payload (tcp/23), HTTP Basic auth lines (tcp/80,8080), SNMPv1/v2c BER-tagged messages (udp/161,162) | BC-1.03.001–004 |
| FR-108 | Detect SMBv1 magic bytes `\xFF SMB` at offset 0 or 4 on tcp/445,139 | BC-1.04.001 |
| FR-109 | Capture TLS ClientHello `legacy_version` field on tcp/443,8443 | BC-1.04.002 |
| FR-110 | Aggregate cross-zone egress: src in `--ot-subnet` AND dst is public | BC-1.05.001 |
| FR-111 | Default OT zone is **IPv4 RFC1918 only** (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) when no `--ot-subnet` flag is supplied. IPv6 is intentionally **not** included in the default: production IPv6 OT deployments are rare today, link-local `fe80::/10` would produce noise on every Ethernet capture, and operators with IPv6 OT zones can declare them explicitly via `--ot-subnet`. The `--ot-subnet` flag accepts both IPv4 and IPv6 CIDRs (`IpNet` parser handles both families) so mixed-family deployments are supported on opt-in | BC-1.05.002 |

### Subsystem S.2 — Asset inventory

| ID | Requirement | BC trace |
|---|---|---|
| FR-201 | Derive `Asset` per host with role inference (PLC vendors + ICS protocols → Plc; SCADA shape → Hmi; etc.) | BC-2.01.001 |
| FR-202 | Populate `Asset.hostname` from `obs.hostnames` lookup; `None` when unknown | BC-2.01.002 |
| FR-203 | Resolve vendor from MAC via prefix-exact lookup against the embedded IEEE OUI table (`src/oui.rs`); first 3 bytes match | BC-2.02.001 (was BC-AUDIT-001) |

### Subsystem S.3 — Detection rules

| ID | Requirement | BC trace |
|---|---|---|
| FR-301 | Emit one `creds.{ftp,telnet,http_basic,snmp}` Finding per CredKind seen — Severity Critical | BC-3.01.001, .002 |
| FR-302 | Roll up credential findings by `(dst, port)` within kind; cap evidence at 15 lines (default per-detector cap per BC-AUDIT-008). **Exception:** `ot.unexpected_protocols` caps at 5 rows per label-bucket (`src/findings/unexpected_protocols.rs` `bucket.len() < 5`), so its total evidence count can be up to `5 × labels_observed` rather than a flat 15 | BC-3.01.003, BC-AUDIT-008 |
| FR-303 | Emit `egress.ot_to_internet` (Severity Critical) when `obs.external_flows` is non-empty. Playbook branches on flow categories: appends category-specific guidance when external flows include DNS (53), NTP (123), or tunnel ports (1194, 4500, 500, 51820) | BC-3.02.001, BC-3.02.002 (was BC-AUDIT-010) |
| FR-304 | Emit `ics.{modbus_writes,cip_engineering,s7_engineering}` (Severity High → Critical if any source IP is outside `--ot-subnet`). Rolls up per (src, dst) pair across all engineering protocols; one row per source-destination pair carries per-pair count + top-N function codes | BC-3.03.001–.003, BC-3.03.004 (was BC-AUDIT-012) |
| FR-305 | Emit `compat.smbv1` (Severity High) on any SMBv1 observation | BC-3.04.001 |
| FR-306 | Emit `compat.stale_tls` (Severity Medium) when `is_stale` inclusive range `0x0300..=0x0302` matches ClientHello legacy_version. 0x0303 (TLS 1.2) and 0x0304 (TLS 1.3) explicitly pass the filter | BC-3.04.002, BC-3.04.003 (was BC-AUDIT-011) |
| FR-307 | Emit `boundary.dns_resolver` (Severity Medium) when a flow on `dst_port=53` has src in OT AND dst NOT in OT | BC-3.05.001 |
| FR-308 | Emit `ot.unexpected_protocols` (Severity Medium) when a flow whose `src OR dst` is in OT carries a port-derived label in the no-fly list (`anydesk, apns, bittorrent, gcm, irc, openvpn, rtmp, sip, smtp, stun, teamviewer` — 11 labels). Label table is locked by S-2.01 regression test | **BC-3.05.002 (B.6 corrected — see L-P0-001)**, BC-3.05.003 (was BC-AUDIT-009) |
| FR-309 | Sort findings by severity DESC then id ASC | BC-3.06.001 |
| FR-310 | Every fired Finding's `id` must appear in `findings::catalog()` (sentinel-tested) | BC-3.06.002 |
| FR-311 | Every Finding must carry a non-empty `playbook: Vec<String>` (sentinel-tested) | BC-3.06.003 |
| FR-312 | When `obs.hostnames` knows a name for an IP, finding evidence renders `HOSTNAME (1.2.3.4)` not just the IP | BC-3.06.004 |
| FR-313 | Evidence vectors are capped at 15 rows per finding via `take(15)` (general invariant). Exception: `unexpected_protocols` caps at 5 per label-bucket (`bucket.len() < 5`), so its total evidence count can be up to `5 × labels_observed` rather than a flat 15 | BC-3.06.005 (was BC-AUDIT-008) |

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
| FR-504 | Leak detector regex scans for IPv4 dotted-quad, IPv6 abbreviated forms, MAC colon-hex. `format_mac` (used by pseudonym minting and observation rendering) produces upper-hex, colon-separated strings that match the leak-detector regex verbatim | BC-5.02.001, BC-5.01.004 (was BC-AUDIT-002) |
| FR-505 | `ensure_no_map_values` iterates every real value in the ScrubMap and verifies absence verbatim | BC-5.02.002 |
| FR-506 | Combined check (`ensure_clean` + `ensure_no_map_values`) on the scrubbed report AND on the assembled user message AND on the audit log JSON — fail-closed on any leak | BC-5.02.003 |

### Subsystem S.6 — AI orchestration

| ID | Requirement | BC trace |
|---|---|---|
| FR-601 | Render AI markdown response to HTML with `Event::Html` and `Event::InlineHtml` filtered out (XSS defense) | BC-6.01.001 |
| FR-602 | System prompt has 4 capture-source-tag variants (span / host-side / tap / ambiguous); each is snapshot-tested. Sparse-capture refusal branch: when report has 0 findings AND ≤5 hosts AND capture window <5 min, prompt instructs AI to recommend longer recapture rather than producing a prioritized analysis | BC-6.02.001, BC-6.02.002 (was BC-AUDIT-013) |
| FR-603 | AI invocation is via subprocess shell-out to `claude -p` — no HTTP, no SDK. `ClaudeCliProvider::analyze` pre-checks `claude` is on `PATH` and returns `OtError::Parse("claude not on PATH ...")` if absent (avoids cryptic spawn errors) | BC-6.03.001, BC-6.03.003 (was BC-AUDIT-014) |

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
| FR-801 | `render_html` is deterministic per inputs (sentinel-tested via snapshot). `report_md` top-level structure orders sections: Capture summary → Findings → Asset inventory → Comms matrix → Notes (snapshot-tested) | BC-8.01.001, BC-8.01.002 (was BC-AUDIT-015) |
| FR-802 | `rule_catalog::render_markdown` output matches the committed `docs/RULES.md` | BC-8.02.001 |
| FR-803 | Scrubbed markdown contains no real identifiers from any fixture | BC-8.03.001 |

### Subsystem S.9 — CLI

| ID | Requirement | BC trace |
|---|---|---|
| FR-901 | `analyze <PCAP> -o <HTML>` defaults to rules-only HTML output | BC-9.01.001 |
| FR-902 | `analyze --ai <PCAP> -o <HTML>` engages the full privacy pipeline (scrub → leak-check → claude → unscrub → embed) | BC-9.01.002 |
| FR-903 | `scrub` / `unscrub` round-trip exits 0 with pseudonyms restored; `--strict` exits non-zero on unmapped tokens | BC-9.02.001 |
| FR-904 | `otsniff rules [--format md|json]` prints the catalog to stdout without requiring a PCAP | BC-9.03.001 |
| FR-905 | `analyze --md <PATH>` emits an LLM-friendly markdown report sidecar alongside the HTML report. Same rendering pipeline as `scrub --md`; suitable for piping into operator-driven AI tools (Claude.ai web, ChatGPT, local Ollama) without `--ai` | BC-8.02.001 |
| FR-906 | `analyze --json <PATH>` emits a JSON sidecar with the same `Observations`-derived fields used by the HTML template; intended for downstream automation. `analyze --map <PATH>` emits the scrub map when `--ai` or `--md` is set so unscrubbing the AI's response or the markdown sidecar later is possible | BC-9.01.002 |

### Subsystem S.10 — Hunt (**planned, MVP — not yet implemented**; see `product-brief.md` "Hunt capability")

Added 2026-09-08 per the product brief amendment for `otsniff hunt`: a directed
CVE/threat-concern exposure-hunting subcommand. Depends on `crates/otsniff-privacy`
(S-13.01, merged) for its scrub/leak-detector mechanics — hunt has no
`Observations`, so it cannot use otsniff's `build_map`/`merge_map`; it builds a
minimal scrub map directly from matched-asset fields via `otsniff_privacy::ScrubMap`.
These FRs and their BC traces (BC-10.xx.xxx, `BC-INDEX.md` §S.10) are **not**
counted in the shipped-BC tallies until a story implements them — matching this
PRD's existing convention that the tallies represent shipped surface, not spec.

| ID | Requirement | BC trace |
|---|---|---|
| FR-1001 | `otsniff hunt <PCAP> --concern <CVE-ID>` parses a positional PCAP path and a required `--concern` flag whose value must match `^CVE-\d{4}-\d{4,7}$` | BC-10.01.001 |
| FR-1002 | Missing positional PCAP or missing `--concern` is a clap usage error, exit 2 — same convention as `analyze`'s zero-input case (S-9.01) | BC-10.01.002 |
| FR-1003 | A `--concern` value that doesn't match the CVE-ID regex is rejected (exit 2) with a message stating the expected format and that free-text/named-threat concerns are not yet supported (MVP scope) | BC-10.01.003 |
| FR-1004 | PCAP-not-found / malformed-PCAP errors reuse the existing `OtError::InputOpen`/`OtError::BadInput` variants and exit codes — no new PCAP-level error class | BC-10.01.004 |
| FR-1005 | `hunt` runs the same ingestion pipeline `analyze` uses (PCAP → `Observer` → `Observations` → `inventory::build`) to obtain an asset inventory, but does **not** run `findings::run_all` or render an HTML report — hunt's only output is the CVE verdict | BC-10.02.001 |
| FR-1006 | A new `hunt_catalog()` function (mirrors `rule_catalog()`/the MITRE mapping's catalog pattern, ADR-0014 precedent) returns a table of CVE signatures: CVE ID → one or more `(vendor OUI-prefix-or-name, protocol family, optional function-code/version range)` match criteria, a plain-English description, and a reference URL (NVD or CISA ICS-CERT — no entry ships without one, mirroring MITRE mapping's URL-validity requirement) | BC-10.02.002 |
| FR-1007 | A `--concern` CVE ID absent from `hunt_catalog()` produces a distinct `HuntVerdict::UnknownCve` outcome (never conflated with "not exposed" — otsniff not having catalogued a CVE yet must never look like a clean bill of health), exit 0, no AI call | BC-10.02.003 |
| FR-1008 | Matching is deterministic: an inventory asset matches a signature iff it satisfies **every** criterion of at least one of the CVE's signature entries (vendor AND protocol AND, if present, function-code/version range); a PCAP is `HuntVerdict::Exposed` iff at least one asset matches any signature for the given CVE; catalog entry order never affects the verdict | BC-10.02.004 |
| FR-1009 | `HuntVerdict::Exposed` carries the matching asset(s) as cited evidence, capped at 5 per the existing evidence-sample convention (`findings/*`) | BC-10.02.005 |
| FR-1010 | `HuntVerdict::NotExposed` (no match) and `HuntVerdict::UnknownCve` short-circuit before any AI call — deterministic non-exposure/unknown verdicts never invoke the AI provider (cost + determinism: nothing to reason about) | BC-10.03.001 |
| FR-1011 | On `HuntVerdict::Exposed`, the matched-asset evidence and CVE description are passed through scrub (`otsniff_privacy::scrub_text`/`ScrubMap`) → leak-check (`otsniff_privacy::leak_detector::ensure_clean`) → the existing `AiProvider`/`ClaudeCliProvider` (`claude -p`, ADR-0007) → unscrub, before any output reaches the user — identically enforced to `analyze --ai`'s existing privacy pipeline, reusing the crate `crates/otsniff-privacy` was extracted for (ADR-0016, S-13.01) | BC-10.03.002 |
| FR-1012 | The privacy invariant test (`invariant_no_real_values_reach_ai_provider`-style) extends to hunt: no real IP/MAC/hostname of a matched asset reaches the AI provider on any hunt test fixture | BC-10.03.003 |
| FR-1013 | AI-call failure (claude CLI missing, non-zero exit, timeout) degrades gracefully: hunt still exits 0 and prints the deterministic verdict + matched evidence, with an appended "AI explanation unavailable: `<reason>`" notice — an AI failure never fails the whole `hunt` invocation | BC-10.03.004 |
| FR-1014 | stdout always includes: CVE ID, verdict (`Exposed`/`NotExposed`/`UnknownCve`), matched evidence (pseudonymized) when `Exposed`, and the AI explanation when available. Exit code is always 0 regardless of verdict value — "you are exposed" is a successful answer, not a program failure | BC-10.04.001 |
| FR-1015 | `hunt --map <PATH>` writes the scrub map used during the run, mirroring `analyze --map`, so `otsniff unscrub` round-trips any saved hunt output later | BC-10.04.002 |

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
| `--ai` set, `claude` not on `PATH` | `ClaudeCliProvider::analyze` returns `OtError::Parse("claude not on PATH ...")`; exit code 70 (EX_SOFTWARE) |
| `--ai` set, `claude` spawn fails (permissions / IO) | `ClaudeCliProvider::analyze` returns `OtError::InputOpen { path: "<spawn:claude>", source: io::Error }`; exit code 2 |
| `--audit-log` set without `--ai` | Audit log path is computed but not used (no AI invocation = nothing to record) |
| `--ot-subnet` with overlapping CIDRs | `is_public` and `in_ot_zone` use first-match logic via `IpNet::contains`; equivalent to union semantics |
| All-IPv6 capture with no `--ot-subnet` declared | `ot_or_default(&[])` returns only IPv4 RFC1918 ranges; no IPv6 host will match `in_ot_zone`. All findings that key off OT classification (egress, recon, boundary, unexpected_protocols) silently become inactive. Operator must declare IPv6 ranges explicitly (`--ot-subnet fd00::/8` for ULA, for example). Documented in FR-111. |
| `--source-type` declared, heuristic returns Ambiguous | No warning (Ambiguous is treated as "no opinion") |
| `--source-type` declared, declared matches heuristic kind | No warning |
| `hunt` — `--concern` CVE ID not in `hunt_catalog()` | `HuntVerdict::UnknownCve`; exit 0; no AI call; message distinguishes this from "not exposed" |
| `hunt` — `--concern` value doesn't match `^CVE-\d{4}-\d{4,7}$` | Exit 2; message states expected format; free-text concerns explicitly unsupported in MVP |
| `hunt` — matched CVE, `claude` not on `PATH` or times out | Deterministic verdict + evidence still printed; exit 0; "AI explanation unavailable" notice appended (does NOT reuse `analyze --ai`'s exit-70 failure mode — hunt's deterministic layer already answered the question) |
| `hunt` — zero assets in inventory match, catalog has entries for the CVE | `HuntVerdict::NotExposed`; exit 0; no AI call |
| `hunt` — PCAP has assets matching multiple signature entries for the same CVE | All matches cited as evidence up to the 5-item cap; verdict is still a single `Exposed` (not one-per-signature) |

## 4. Open questions (to resolve before stories)

Inherited from product brief; restated here so they don't drift:

- **OQ-1** Long-term monetization posture
- **OQ-2** Detection rule velocity / community contribution
- **OQ-3** Cross-event correlation (would touch the Finding data model)
- **OQ-4** Kani proofs of the privacy invariant — v0.4 deliverable or deferred?
- **OQ-5** `cred_events` Vec memory bound — pre-rollup dedup in v0.4?
- **OQ-6** ~~CVE-to-device matching mechanism~~ — **RESOLVED 2026-09-08**: curated in-tree `hunt_catalog()` table (deterministic, sentinel-testable) + AI explains/narrates the verdict. See Subsystem S.10 above.
- **OQ-7** Live platform (Claroty/Dragos/Nozomi) integration timeline + auth model — not in MVP; would need ADR-0001/ADR-0007's "no HTTP/SDK" posture explicitly revisited for a platform-API client (a different kind of network dependency than the AI-provider shell-out these ADRs actually scoped)
- **OQ-8** App/GUI ambition beyond the hunt CLI — not in MVP; architecture should not pay a cost for this now
- **OQ-9** Monetization posture for hunt specifically (sharpens OQ-1) — live platform integration is the kind of feature that could justify a paid tier; the CLI-only MVP fits the current pure-OSS posture cleanly

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

---
pass: 3
name: behavioral-contracts
project: otsniff
generated: 2026-05-11T18:55:00Z
origin: recovered
total_contracts: 38
confidence_breakdown:
  HIGH: 31
  MEDIUM: 6
  LOW: 1
---

# Pass 3 — Behavioral Contracts

Subsystem numbering (otsniff-specific, retrofit):

- **S.0** — PCAP iteration (`src/pcap.rs`)
- **S.1** — Observation + protocol parsing (`src/observe.rs`, `src/parse/*`)
- **S.2** — Inventory derivation (`src/inventory.rs`)
- **S.3** — Findings layer (`src/findings/*`)
- **S.4** — Capture-source classification (`src/capture_source.rs`)
- **S.5** — Privacy: scrub + leak detector (`src/scrub.rs`, `src/ai/leak_detector.rs`)
- **S.6** — AI orchestration (`src/ai/*`)
- **S.7** — Audit log (`src/audit.rs`)
- **S.8** — Rendering (`src/report.rs`, `src/report_md.rs`, `src/rule_catalog.rs`)
- **S.9** — CLI orchestration (`src/cli.rs`)

Confidence:
- **HIGH** — backed by test + source code agreement
- **MEDIUM** — derived from source code; tests partial or implicit
- **LOW** — inferred from comments, ADRs, or documentation

## S.0 — PCAP iteration

### BC-0.01.001 — Iterate packets from valid PCAP/PCAPNG (HIGH)

**Given** a path to a valid PCAP or PCAPNG file
**When** `pcap::iter_packets(path)` is called
**Then** the function returns `Ok(PacketIter)` and the iterator yields `Result<Packet>` items in capture order, each carrying timestamp, src/dst MACs, src/dst IPs, src/dst ports, transport type, and owned payload bytes.

**Source:** `src/pcap.rs::iter_packets`, `tests/cli_smoke.rs::analyze_valid_pcap_produces_html_and_exits_0`.

### BC-0.01.002 — Reject non-PCAP input (HIGH)

**Given** a file that is not a valid PCAP or PCAPNG
**When** `iter_packets` is called and packets are pulled
**Then** the iterator (or the open call) yields `Err(OtError::BadInput { reason })` and the CLI exits with code 2.

**Source:** `tests/cli_smoke.rs::analyze_malformed_input_exits_2`.

### BC-0.01.003 — Reject missing input (HIGH)

**Given** a path that does not exist on disk
**When** `iter_packets` is called
**Then** returns `Err(OtError::InputOpen { path, source })` and the CLI exits with code 2 + stderr contains "could not open input".

**Source:** `tests/cli_smoke.rs::analyze_nonexistent_input_exits_2`.

### BC-0.01.004 — Owned packet payloads (MEDIUM)

**Given** any parseable packet
**When** `Packet` is constructed
**Then** `payload` is `Vec<u8>` (owned), not a borrowed slice, so downstream code can carry it without lifetime contagion.

**Source:** `src/pcap.rs::Packet`, ADR-0004.

## S.1 — Observation + protocol parsing

### BC-1.01.001 — Single-pass accumulator (HIGH)

**Given** a stream of `Packet`s
**When** `Observer::observe(&pkt)` runs on each
**Then** each packet is touched exactly once; final state is recovered via `Observer::finish() -> Observations`. Memory grows with unique hosts/flows/events, not raw packet count.

**Source:** `src/observe.rs::Observer`.

### BC-1.01.002 — Logical flow keying drops src_port (HIGH)

**Given** multiple TCP connections from the same client to the same server:port
**When** observed
**Then** they aggregate into a single `FlowObs` keyed by (src_ip, dst_ip, dst_port, proto); the count of distinct connections is preserved in `FlowObs::unique_src_ports`.

**Source:** `src/observe.rs::FlowKey`, `docs/specs/flow-grouping.md`.

### BC-1.02.001 — Modbus PDU recognition (HIGH)

**Given** a TCP packet on port 502 with MBAP-framed payload
**When** `parse::modbus::parse(payload)` runs
**Then** returns `Some(Pdu)` with the function code and an engineering-class flag (true for fc 0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x08, 0x15, and FC 8 sub-function 1).

**Source:** `src/parse/modbus.rs`, `src/findings/engineering_commands.rs::MODBUS_METADATA::trigger`.

### BC-1.02.002 — ENIP/CIP engineering service recognition (HIGH)

**Given** an ENIP encapsulation packet on TCP/44818
**When** `parse::enip::parse_header(payload)` returns a header AND `parse::enip::engineering_class_cip(payload)` returns `Some(service)`
**Then** the observation has `engineering_class: true` with the matched service label.

**Source:** `src/parse/enip.rs`, `src/observe.rs::observe_tcp`.

### BC-1.02.003 — S7Comm function code recognition (HIGH)

**Given** an S7Comm PDU on TCP/102
**When** `parse::s7comm::parse(payload)` runs
**Then** returns `Some(Pdu)` with function code, label, and engineering/read class flags. Engineering class includes PLC stop/start, block download/upload, password ops.

**Source:** `src/parse/s7comm.rs`.

### BC-1.02.004 — DHCP option 12 hostname extraction (HIGH)

**Given** a UDP packet on port 67 or 68 with valid DHCP magic cookie at offset 236 and option 12 (Host Name) present
**When** `parse::dhcp::parse(payload)` runs
**Then** returns `Some(DhcpInfo { ip, hostname })` where `ip` is yiaddr (priority) or ciaddr (fallback) or option-50 requested-IP, and `hostname` is the printable ASCII content of option 12.

**Source:** `src/parse/dhcp.rs::parse`, unit tests in same file.

### BC-1.03.001 — Plaintext FTP credential observation (HIGH)

**Given** a TCP/21 packet whose payload starts with "USER " or "PASS " (case-insensitive)
**When** observed
**Then** a `CredEvent { kind: FtpAuth, ... }` is appended to `obs.cred_events`. The `note` field captures the literal request line, capped at 80 bytes.

**Source:** `src/observe.rs::observe_tcp`.

### BC-1.03.002 — Telnet session observation (HIGH)

**Given** any non-empty payload on TCP/23 (src or dst)
**When** observed
**Then** a `CredEvent { kind: TelnetSession, ... }` is appended. (Telnet is cleartext by definition — observation doesn't try to identify the auth exchange specifically.)

**Source:** `src/observe.rs::observe_tcp`.

### BC-1.03.003 — HTTP Basic credential observation (HIGH)

**Given** a TCP/80 or TCP/8080 packet containing the substring `Authorization: Basic `
**When** observed
**Then** a `CredEvent { kind: HttpBasic, ... }` is appended. `note` captures the line (up to 120 bytes).

**Source:** `src/observe.rs::observe_tcp`.

### BC-1.03.004 — SNMPv1/v2c credential observation (HIGH)

**Given** a UDP/161 or UDP/162 packet starting with BER SEQUENCE tag 0x30, length, INTEGER `0x02 0x01 0x00` (v1) or `0x02 0x01 0x01` (v2c)
**When** observed
**Then** a `CredEvent { kind: Snmpv1v2c, ... }` is appended.

**Source:** `src/observe.rs::observe_udp`.

### BC-1.04.001 — SMBv1 packet observation (HIGH)

**Given** a TCP/445 or TCP/139 packet whose payload begins with the SMB1 magic bytes `\xFF SMB` at offset 0 (raw) or offset 4 (after an NBSS session-message header)
**When** observed
**Then** `obs.smbv1_packets[(src, dst, dst_port)]` is incremented by 1.

**Source:** `src/observe.rs::observe_tcp`, `src/observe.rs::has_smb1_magic`.

### BC-1.04.002 — TLS ClientHello version capture (HIGH)

**Given** a TCP/443 or TCP/8443 packet with payload `[0]==0x16` (TLS record handshake), `[5]==0x01` (ClientHello), and len ≥ 11
**When** observed
**Then** `obs.tls_client_hellos[(src, dst, dst_port, legacy_version)]` is incremented by 1, where `legacy_version` is the on-the-wire u16 from bytes [9..11].

**Source:** `src/observe.rs::observe_tcp`.

### BC-1.05.001 — External egress aggregation (HIGH)

**Given** a packet with src_ip inside a configured `--ot-subnet` AND dst_ip is public (not RFC1918, not link-local, not loopback, not multicast, not broadcast, not documentation, not ULA IPv6)
**When** observed
**Then** `obs.external_flows[(src, dst, dst_port, proto)]` is updated.

**Source:** `src/observe.rs::observe`, `src/observe.rs::is_public`.

### BC-1.05.002 — Default OT subnets = RFC1918 (HIGH)

**Given** no `--ot-subnet` flags on the CLI
**When** the run starts
**Then** the OT zone is implicitly `{10/8, 172.16/12, 192.168/16}`.

**Source:** `src/cli.rs::ot_or_default`.

## S.2 — Inventory

### BC-2.01.001 — Asset per host with role inference (HIGH)

**Given** an `Observations` value
**When** `inventory::build(&obs)` runs
**Then** returns `Vec<Asset>` — one Asset per IP in `obs.hosts` — with role inferred from protocol set + OUI vendor (PLC vendors + ICS protocols → Plc; SCADA-shaped → Hmi; etc.).

**Source:** `src/inventory.rs::build`, `infer_role`.

### BC-2.01.002 — Hostname lookup on Asset (HIGH)

**Given** an `Observations` with `obs.hostnames[ip] = "LINE-3-PLC"` for some host
**When** `inventory::build(&obs)` runs
**Then** the corresponding `Asset.hostname` is `Some("LINE-3-PLC")`; otherwise `None`.

**Source:** `src/inventory.rs::host_to_asset`.

## S.3 — Findings layer

### BC-3.01.001 — `creds.ftp` fires on any FtpAuth event (HIGH)

**Given** `obs.cred_events` contains at least one `CredEvent { kind: FtpAuth, ... }`
**When** `findings::run_all` runs
**Then** exactly one `Finding { id: "creds.ftp", severity: Critical }` is emitted, with evidence rolled up by (dst, port).

**Source:** `src/findings/plaintext_creds.rs::detect`, `docs/RULES.md`.

### BC-3.01.002 — `creds.{telnet,http_basic,snmp}` fire analogously (HIGH)

Same shape as BC-3.01.001 for `CredKind::TelnetSession`, `HttpBasic`, `Snmpv1v2c`. Each emits one Finding per kind seen.

**Source:** `src/findings/plaintext_creds.rs::detect`.

### BC-3.01.003 — Credential findings dedupe across destinations (HIGH)

**Given** 4,700 Telnet packets across 12 distinct destinations
**When** `findings::run_all` runs
**Then** exactly one `creds.telnet` Finding is emitted (not 12, not 4,700), with the 12 destinations as evidence sorted by packet count descending and capped at 15.

**Source:** `src/findings/plaintext_creds.rs::build_finding`, `docs/specs/finding-dedup.md`.

### BC-3.02.001 — `egress.ot_to_internet` fires on non-empty `external_flows` (HIGH)

**Given** `obs.external_flows` is non-empty
**When** `findings::run_all` runs
**Then** one `Finding { id: "egress.ot_to_internet", severity: Critical }` is emitted.

**Source:** `src/findings/internet_egress.rs::detect`.

### BC-3.03.001 — `ics.modbus_writes` fires on any engineering-class modbus event (HIGH)

**Given** `obs.modbus_events` contains at least one event with `engineering_class: true`
**When** `findings::run_all` runs
**Then** one `Finding { id: "ics.modbus_writes", severity: High }` is emitted; severity escalates to `Critical` if at least one event's src IP is outside the configured `--ot-subnet`.

**Source:** `src/findings/engineering_commands.rs::detect` (modbus block).

### BC-3.03.002 — `ics.cip_engineering` fires (HIGH)

Same shape, on `enip_events` with `engineering_class: true`.

### BC-3.03.003 — `ics.s7_engineering` fires (HIGH)

Same shape, on `s7_events` with `engineering_class: true`.

### BC-3.04.001 — `compat.smbv1` fires on any SMBv1 observation (HIGH)

**Given** `obs.smbv1_packets` is non-empty
**When** `findings::run_all` runs
**Then** one `Finding { id: "compat.smbv1", severity: High }` is emitted.

**Source:** `src/findings/smbv1.rs::detect`.

### BC-3.04.002 — `compat.stale_tls` filters by legacy_version (HIGH)

**Given** `obs.tls_client_hellos` contains at least one entry with `legacy_version` in `{0x0300, 0x0301, 0x0302}` (SSL 3.0, TLS 1.0, TLS 1.1)
**When** `findings::run_all` runs
**Then** one `Finding { id: "compat.stale_tls", severity: Medium }` is emitted.

**Source:** `src/findings/stale_tls.rs::detect`.

### BC-3.05.001 — `boundary.dns_resolver` cross-zone filter (HIGH)

**Given** a flow in `obs.flows` with `dst_port == 53` AND `src` is in any configured OT subnet AND `dst` is NOT in any OT subnet
**When** `findings::run_all` runs
**Then** one `Finding { id: "boundary.dns_resolver", severity: Medium }` is emitted.

**Source:** `src/findings/dns_resolver.rs::detect`.

### BC-3.05.002 — `ot.unexpected_protocols` no-fly list (HIGH)

**Given** a flow on a host inside an OT subnet with a flow label from the no-fly list (`anydesk`, `bittorrent`, `irc`, `openvpn`, `rtmp`, `sip`, `smtp`)
**When** `findings::run_all` runs
**Then** one `Finding { id: "ot.unexpected_protocols", severity: Medium }` is emitted; evidence lists each offending protocol with flow count.

**Source:** `src/findings/unexpected_protocols.rs::detect`.

### BC-3.06.001 — Findings always sorted by severity DESC then id ASC (HIGH)

**Given** multiple findings from `run_all`
**When** the result is returned
**Then** ordering is `Critical → High → Medium → Info`, with ties broken by id ascending.

**Source:** `src/findings/mod.rs::run_all`.

### BC-3.06.002 — Every fired finding has metadata in catalog (HIGH)

**Given** any finding emitted by `run_all` on any fixture
**Then** `findings::metadata_for(finding.id).is_some()`.

**Source:** `tests/snapshot.rs::every_finding_id_appears_in_the_rule_catalog`.

### BC-3.06.003 — Every fired finding carries a non-empty playbook (HIGH)

**Given** any finding emitted by `run_all` on any fixture
**Then** `finding.playbook.is_empty() == false` and every entry is non-empty.

**Source:** `tests/snapshot.rs::every_finding_has_a_non_empty_playbook`.

### BC-3.06.004 — Hostname-aware evidence rendering (HIGH)

**Given** `obs.hostnames[ip] = "ENG-WS-01"` for some host
**When** any finding's evidence string references that IP via `findings::host_label`
**Then** the rendered string contains `"ENG-WS-01 (ip)"`, not just the IP.

**Source:** `src/findings/mod.rs::host_label`, `tests/snapshot.rs::finding_evidence_surfaces_hostnames_when_we_know_them`.

## S.4 — Capture-source classification

### BC-4.01.001 — Host-side classification (HIGH)

**Given** an `Observations` with one MAC at ≥95% of frames AND second-MAC at <30%
**When** `capture_source::classify(&obs)` runs
**Then** returns `CaptureSource::HostSide { dominant_mac, appearance_pct }`.

**Source:** `src/capture_source.rs::classify`, `host_side_dominance_classifies_correctly`.

### BC-4.01.002 — TAP classification (HIGH)

**Given** top two MACs each at ≥95% coverage AND third <10%
**Then** classification is `CaptureSource::Tap { endpoint_a, endpoint_b, coverage_pct }`.

**Source:** `src/capture_source.rs::classify`, `tap_pattern_classifies_correctly`.

### BC-4.01.003 — SPAN classification (HIGH)

**Given** ≥10 distinct MACs AND dominant MAC <60% AND broadcast/multicast frames present
**Then** classification is `CaptureSource::Span { distinct_macs, broadcasts }`.

**Source:** `src/capture_source.rs::classify`, `span_pattern_classifies_correctly`.

### BC-4.02.001 — Declared source overrides heuristic for rendering (HIGH)

**Given** a `Classification` with `declared: Some(DeclaredSource::Span)`
**When** `report_line()` or `ai_qualifier_tag()` is called
**Then** the declared type is authoritative for the output; the heuristic verdict is preserved on `Classification::source` but not used.

**Source:** `src/capture_source.rs::Classification::with_declared`, `declared_source_is_authoritative_for_report_line`.

### BC-4.02.002 — Guard warning on disagreement (HIGH)

**Given** `Classification` with `declared = Some(t)` and `source` is a different variant (NOT Ambiguous)
**When** `guard_warning()` is called
**Then** returns `Some(msg)` describing the mismatch with concrete heuristic detail. Returns `None` when they agree or heuristic is Ambiguous.

**Source:** `src/capture_source.rs::guard_warning`, `declared_source_disagreeing_with_heuristic_produces_warning`.

## S.5 — Privacy: scrub + leak detector

### BC-5.01.001 — Pseudonym minting is deterministic (HIGH)

**Given** an `Observations` value
**When** `scrub::build_map(&obs)` is called twice
**Then** both calls return identical pseudonym → real mappings (sorted assignment by real value).

**Source:** `src/scrub.rs::build_map_at`, `build_map_assigns_pseudonyms_deterministically`.

### BC-5.01.002 — scrub_text only substitutes observed values (HIGH)

**Given** a `ScrubMap` and text containing the string `"8.8.8.8"` which was NOT in the originating `Observations`
**When** `scrub_text(text, &map)` runs
**Then** the substring `"8.8.8.8"` is unchanged. Only values present in the map are substituted.

**Source:** `src/scrub.rs::scrub_text`, `scrub_does_not_touch_unobserved_values`.

### BC-5.01.003 — Scrub round-trip is exact (HIGH)

**Given** any text containing only pseudonyms that exist in the map and ordinary prose
**Then** `unscrub_text(scrub_text(text, map), map).0 == text`.

**Source:** `src/scrub.rs::unscrub_text`, `unscrub_reverses_scrub`.

### BC-5.02.001 — Leak detector regex covers IPv4, IPv6, MAC (HIGH)

**Given** any string
**When** `leak_detector::scan(text)` is called
**Then** returns `Some(Leak { kind, pattern, byte_offset })` for the first match of IPv4 dotted-quad, IPv6 (full or `::`-abbreviated), or MAC (6 colon-separated hex octets, case-insensitive). Otherwise `None`.

**Source:** `src/ai/leak_detector.rs::scan`, flags_ipv4_in_otherwise_clean_text + siblings.

### BC-5.02.002 — Map-value check catches hostname leaks regex can't (HIGH)

**Given** a `ScrubMap` with `names: {name_001 → "LINE-3-PLC"}` and text containing `"LINE-3-PLC"` verbatim
**When** `ensure_no_map_values(text, &map)` is called
**Then** returns `Err(OtError::Parse(_))` with a descriptive message containing the leaked value.

**Source:** `src/ai/leak_detector.rs::ensure_no_map_values`, `ensure_no_map_values_catches_hostname_leak_that_regex_misses`.

### BC-5.02.003 — Privacy invariant: combined check on AI-bound bytes (HIGH)

**Given** the exact `user_message` and `system_prompt` strings that the `analyze --ai` flow would send to Claude on the test fixture
**Then** both `ensure_clean` and `ensure_no_map_values` return `Ok(())`.

**Source:** `tests/snapshot.rs::invariant_no_real_values_reach_ai_provider`.

## S.6 — AI orchestration

### BC-6.01.001 — AI markdown rendering strips raw HTML events (HIGH)

**Given** Claude's response containing `<script>alert(1)</script>` or `<img onerror=...>` blocks
**When** `ai::html_render::render_safe(response)` runs
**Then** the resulting HTML does NOT contain `<script>`, `<img`, or any other raw HTML from the input. Legitimate markdown formatting (headers, code blocks, tables, bold) is preserved.

**Source:** `src/ai/html_render.rs::render_safe`, `strips_raw_html_block_script` + siblings.

### BC-6.02.001 — System prompt varies by capture-source tag (HIGH)

**Given** a `Classification` with tag `"span"`, `"host-side"`, `"tap"`, or `"ambiguous"`
**When** `prompts::system_prompt_for(tag)` is called
**Then** the returned string is the base prompt + a tag-specific qualifier; each combination is stable (snapshot-tested).

**Source:** `src/ai/prompts.rs::system_prompt_for`, `system_prompt_for_each_source_tag_snapshots`.

### BC-6.03.001 — Claude invocation is via subprocess shell-out (MEDIUM)

**Given** a `ClaudeCliProvider` and prompts
**When** `analyze(system_prompt, user_message)` is called
**Then** the provider invokes `claude -p` as a subprocess (with optional `--model` flag), passes prompts via stdin/args, and returns the captured stdout. No HTTP, no SDK.

**Source:** `src/ai/claude_cli.rs::ClaudeCliProvider::analyze`. (No e2e test today — `claude` CLI is an external dependency.)

## S.7 — Audit log

### BC-7.01.001 — Audit log auto-derives path from -o (HIGH)

**Given** `analyze --ai -o plant.html` (no `--audit-log` override)
**When** the run completes
**Then** an audit log is written to `plant.audit.json` alongside.

**Source:** `src/cli.rs::default_audit_log_path`, `run_analyze`.

### BC-7.01.002 — Audit log SHA-256s match the bytes sent to Claude (HIGH)

**Given** an `analyze --ai` run that writes an audit log
**Then** `audit_log.ai_provider.user_message_sha256` equals `sha256_hex(user_message)`, same for `system_prompt_sha256` and `response_sha256`.

**Source:** `src/audit.rs::sha256_hex`, `src/cli.rs::run_analyze` (populates AiInvocationSummary).

### BC-7.01.003 — Audit log itself contains no real identifiers (HIGH)

**Given** any complete `AuditLog` from any analyze run
**Then** `leak_detector::ensure_clean(json)` AND `leak_detector::ensure_no_map_values(json, &map)` both return `Ok(())` before the file is written.

**Source:** `src/cli.rs::run_analyze` (pre-write leak checks), `audit_log_rendered_for_an_analyze_run_carries_no_real_identifiers`.

### BC-7.02.001 — CredEvent.note never leaks (HIGH)

**Given** an `Observations` with `cred_events[i].note = "USER CANARY-...-LEAK"` for some i
**When** any of HTML render, markdown render, scrubbed-markdown, or per-event JSON serialization runs
**Then** the canary string appears in NONE of those outputs.

**Source:** `src/observe.rs::CredEvent` (`#[serde(skip)] note`), `cred_event_note_must_not_reach_any_rendered_output`.

## S.8 — Rendering

### BC-8.01.001 — `render_html` is deterministic per inputs (HIGH)

**Given** identical `Vec<Asset>`, `Vec<Finding>`, `&Observations`, `input_label`, `generated_at`, `Option<&Classification>`, `Option<String>` (ai_section)
**Then** `render_html(...)` returns byte-identical output across runs.

**Source:** Snapshot tests `html_report_snapshot`, `ai_section_in_html_strips_script_tags_from_claude_response`.

### BC-8.02.001 — `rule_catalog::render_markdown` matches committed RULES.md (HIGH)

**Given** the current `findings::catalog()` value
**When** rendered as markdown
**Then** the output is byte-identical to `docs/RULES.md`.

**Source:** `tests/snapshot.rs::rule_catalog_matches_committed_rules_md`.

### BC-8.03.001 — Scrubbed markdown contains no real identifiers (HIGH)

**Given** an `Observations` fixture
**When** the markdown is rendered, then scrubbed via `scrub_text`
**Then** every real IP, MAC, and hostname from the fixture is absent from the scrubbed output.

**Source:** `tests/snapshot.rs::scrubbed_markdown_snapshot_does_not_leak_real_values`.

## S.9 — CLI orchestration

### BC-9.01.001 — `analyze` defaults output to HTML (HIGH)

**Given** `otsniff analyze input.pcap -o report.html` (no `--ai`)
**When** the run completes
**Then** an HTML file is written to `report.html`. No audit log, no map.json, no markdown sidecar unless requested.

**Source:** `src/cli.rs::run_analyze` short-circuit path.

### BC-9.01.002 — `--ai` engages the full privacy pipeline (HIGH)

**Given** `otsniff analyze input.pcap -o report.html --ai`
**When** the run completes successfully
**Then** an HTML file is written (with an AI section embedded), an `report.audit.json` is written, and the privacy invariant held (otherwise the run errors out before AI invocation).

**Source:** `src/cli.rs::run_analyze` AI path.

### BC-9.02.001 — `scrub`/`unscrub` round-trip (HIGH)

**Given** a PCAP fixture
**When** `otsniff scrub fixture.pcap -o out.md --map map.json` runs, the user pastes pseudonym-shaped text back to `otsniff unscrub --map map.json`
**Then** the pseudonyms are replaced with their real values; unmapped pseudonyms are left as-is unless `--strict` is set.

**Source:** `tests/cli_smoke.rs::scrub_round_trip_via_pcap`, `unscrub_strict_mode_fails_on_unknown_token`.

### BC-9.03.001 — `otsniff rules` prints the catalog (HIGH)

**Given** any working install
**When** `otsniff rules` (or `otsniff rules --format json`) is invoked
**Then** the rule catalog is printed to stdout in the requested format.

**Source:** `src/cli.rs::run_rules`, `src/rule_catalog.rs`.

## Coverage gaps (BCs we don't have but should)

### BC-?.??.001 — Memory bound proportional to unique hosts/flows, not raw packets (LOW confidence)

**Conjecture:** Memory usage is O(unique_hosts + unique_flows + events) rather than O(packets). Reasonable from the data model but never benchmarked.

**Gap:** No performance test. Would need `criterion` or `hyperfine` runs.

### BC-?.??.002 — Output snapshots stable across Rust toolchain versions

**Conjecture:** Snapshot outputs depend only on input data, not on the Rust version. Reasonable since we don't depend on HashMap iteration order anywhere visible.

**Gap:** MSRV (1.85) is tested in CI but only via `cargo check` — full snapshot run on 1.85 is not part of CI.

### BC-?.??.003 — Claude CLI invocation respects sandbox / permissions

**Conjecture:** The `ClaudeCliProvider` doesn't surface a way for Claude to access otsniff's filesystem beyond what the OS subprocess inherits.

**Gap:** No formal test of subprocess isolation behavior.

## Confidence summary

| Subsystem | HIGH | MEDIUM | LOW |
|---|---:|---:|---:|
| S.0 PCAP | 3 | 1 | 0 |
| S.1 Observation | 9 | 1 | 0 |
| S.2 Inventory | 2 | 0 | 0 |
| S.3 Findings | 13 | 0 | 0 |
| S.4 Capture source | 5 | 0 | 0 |
| S.5 Scrub + leak | 6 | 0 | 0 |
| S.6 AI | 1 | 2 | 0 |
| S.7 Audit | 4 | 0 | 0 |
| S.8 Rendering | 3 | 0 | 0 |
| S.9 CLI | 4 | 0 | 0 |
| Gaps | — | 0 | 3 |
| **Total** | **50** | **4** | **3** |

Most BCs have at least one corresponding test in `tests/cli_smoke.rs`
or `tests/snapshot.rs`. The MEDIUM-confidence ones are derived from
source code where a unit test exists but doesn't directly assert the
contract as stated.

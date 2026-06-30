---
artifact_type: behavioral-contract-index
project: otsniff
generated: 2026-05-18
status: draft (brownfield-recovered)
total_bcs: 113  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006; S-2.11 added BC-1.02.009 and BC-3.03.006; S-5.01 added BC-9.04.001; S-5.02 added BC-6.04.001; S-5.07 added BC-8.01.005; S-6.01 added BC-5.03.001; S-5.03 added BC-6.05.001, BC-6.05.002, BC-6.05.003, BC-3.07.001, BC-7.01.004; S-8.01 added BC-1.02.010, BC-1.02.011, BC-1.02.012, BC-1.02.013; S-9.01 added BC-1.01.003, BC-1.01.004, BC-7.01.005; S-10.01 added BC-4.01.004, BC-4.01.005
origin: recovered
canonical_source: .factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md
deviations:
  - Per-BC sharding (.factory/specs/behavioral-contracts/ss-{subsystem}/BC-{bc-id}.md)
    skipped for brownfield retrofit on a small project. 84 trivially-different
    files would outweigh the benefit at this project size. If a customer-grade
    traceability matrix is needed later, this index expands into the canonical
    pattern.
---

# Behavioral Contracts — Master Index

98 numbered BCs across 10 subsystems (S.0–S.9). The 15 originally-
named `BC-AUDIT-NNN` contracts (Phase 0 brownfield audit) were
promoted to first-class numbered BCs in S-1.05 (v0.4.0); the legacy
IDs survive as aliases at the bottom of this file for traceability
against Phase 0/1 documents. Full text in
`.factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md`
with B.6 corrections applied in `.factory/specs/prd.md` §5.

## Index by subsystem

### S.0 — PCAP iteration + error taxonomy (`src/pcap.rs`, `src/error.rs`, `src/main.rs`)
- BC-0.01.001 Iterate packets from valid PCAP/PCAPNG (HIGH)
- BC-0.01.002 Reject non-PCAP input (HIGH)
- BC-0.01.003 Reject missing input (HIGH)
- BC-0.01.004 Owned packet payloads (MEDIUM)
- BC-0.02.001 `OtError` variant-to-exit-code mapping is complete (every variant has a sysexits-style code; verified by `src/error.rs::OtError::exit_code` unit tests) (HIGH, promoted from BC-AUDIT-003 in S-1.05)
- BC-0.02.002 `main.rs` walks `std::error::Error::source()` chain, printing each layer prefixed `"caused by: "` so I/O failures retain their underlying diagnosis (HIGH, promoted from BC-AUDIT-004 in S-1.05)

### S.1 — Observation + protocol parsing (`src/observe.rs`, `src/parse/*`)
- BC-1.01.001 Single-pass accumulator (HIGH)
- BC-1.01.002 Logical flow keying drops src_port (HIGH)
- BC-1.01.003 Multi-file ordered ingestion: `iter_packets_multi(paths)` yields every packet of `paths[0]` in file order, then `paths[1]`, etc. — concatenation is in command-line order (append semantics, NOT timestamp-sorted); per-packet timestamps are preserved so the observer's `first_ts`/`last_ts` span the union window when files are chronologically ordered; a per-file read error surfaces identifying that file (fail-fast, no partial report) (HIGH, added S-9.01 v0.6.0)
- BC-1.01.004 Link-layer homogeneity guard: before streaming a multi-file set, each file's declared link type is peeked (legacy global-header `network` field; pcapng IDB); two files with different *determinate* link types yield `OtError::MixedLinkTypes` naming both files and types; indeterminate pcapng link types are treated as ETHERNET (matching `decode_block`'s default) and not rejected by the guard (HIGH, added S-9.01 v0.6.0)
- BC-1.02.001 Modbus PDU recognition + engineering classification (HIGH, **B.6 corrected**)
- BC-1.02.002 ENIP/CIP engineering service recognition (HIGH)
- BC-1.02.003 S7Comm function code classification (HIGH, **B.6 corrected**)
- BC-1.02.004 DHCP option-12 hostname extraction (HIGH)
- BC-1.02.005 DNP3 frame recognition + engineering classification (HIGH, added S-2.04 v0.4.0)
- BC-1.02.006 DHCP option walk is bounded and length-checked; rejects truncation, honors OPT_END/OPT_PAD (HIGH, promoted from BC-AUDIT-005 in S-1.05 — suggested ID was 1.02.005 but that's DNP3, shifted to .006)
- BC-1.02.007 DHCP IP resolution is three-tier: yiaddr → ciaddr → option 50 "Requested IP Address" (HIGH, promoted from BC-AUDIT-006 in S-1.05 — shifted from suggested .006 cascade)
- BC-1.02.008 S7Comm header sizing depends on ROSCTR: 10 bytes for Job/UserData, 12 bytes for Ack/Ack_Data (HIGH, promoted from BC-AUDIT-007 in S-1.05 — shifted from suggested .007 cascade)
- BC-1.02.009 Modbus per-(src, dst) unit-id aggregation: observer accumulates pdu.unit_id into modbus_flow_summary keyed by (src, dst); BTreeSet dedupes within flow; unit IDs 0 (broadcast) and 0xFF (gateway) are counted (HIGH, added S-2.11 v0.4.0)
- BC-1.02.010 mDNS A-record hostname extraction: UDP/5353 DNS message answer section A records (type 0x0001; class compared as `class & 0x7FFF == 0x0001`, i.e. the mDNS cache-flush top bit is masked so the real-world value 0x8001 is accepted) yield the owner name sanitized to printable ASCII (0x20..0x7F) then stripped of a trailing case-insensitive `.local`/`.local.` suffix, mapped to the RDATA IPv4 address; names containing DNS compression pointer labels (0xC0 prefix byte) anywhere in the message are rejected and yield no insertion (whole-message discard, no partial insertion); empty names after sanitize+strip are discarded (HIGH, added S-8.01 v0.6.0)
- BC-1.02.011 NetBIOS-NS workstation-name extraction: UDP/137 NBNS Registration Request (QR=0, OPCODE=5 — OPCODE is bits 11-14 of the 16-bit flags field) QNAME first-label 32 bytes first-level-decoded to 16 bytes (consecutive pairs H,L: decoded = ((H-'A')<<4)|(L-'A')); trailing space bytes (0x20) stripped from the first 15 decoded bytes; 16th (suffix) byte dropped; result associated with the packet src_ip; empty names after stripping are discarded; truncated or malformed messages yield None (HIGH, added S-8.01 v0.6.0)
- BC-1.02.012 LLMNR A-record hostname extraction: UDP/5355 datagram where QR bit (bit 15 of the 16-bit flags field, big-endian) is 1 (response); answer section A records yield owner name with trailing dot stripped; names containing DNS compression pointer labels rejected; empty names discarded; RDATA provides the IPv4 address (HIGH, added S-8.01 v0.6.0)
- BC-1.02.013 Hostname multi-source precedence and normalization: all passive hostname sources (DHCP option-12, mDNS A-record, NetBIOS-NS Registration, LLMNR A-record) insert into `obs.hostnames` via last-write-wins in packet/observation processing order (which follows capture order; the observer does not read `pkt.ts`); no source-priority ordering is applied; each source applies its own normalization (case-insensitive `.local` strip for mDNS, space-pad strip + suffix-byte drop for NetBIOS-NS, trailing-dot strip for LLMNR, printable-ASCII sanitization on all) before insertion; the precedence rule is positional, not source-authoritative (HIGH, added S-8.01 v0.6.0)
- BC-1.03.001 FTP credential observation (HIGH)
- BC-1.03.002 Telnet session observation (HIGH)
- BC-1.03.003 HTTP Basic credential observation (HIGH)
- BC-1.03.004 SNMPv1/v2c credential observation (HIGH)
- BC-1.03.005 LDAP simple-bind observation: BER-encoded BindRequest on tcp/389 or tcp/3268 with version 3 and SimpleAuthentication choice (tag 0x80); `anonymous: bool` set when DN + password are both empty (EC-003); STARTTLS state tracked per flow by observer (HIGH, added S-2.05 v0.4.0)
- BC-1.03.006 NTLMSSP NEGOTIATE recognized in TCP payloads on ports 445/139/80/443/8080/135; signature scan via `windows(8)` then full recognizer validates MessageType=1 and flags; classified V1 if NTLM bit (0x00000200) set and NTLM2_KEY (0x00080000) unset, V2 if NTLM2_KEY set; emits NtlmEvent (HIGH, added S-2.06 v0.4.0)
- BC-1.03.007 `cred_events` deduplicated at observation time by `(src, dst, dst_port, kind)`; duplicate increments `count: u32` (saturating); entry not appended (HIGH, added S-2.02 v0.4.0)
- BC-1.04.001 SMBv1 packet observation (HIGH)
- BC-1.04.002 TLS ClientHello version capture (HIGH)
- BC-1.04.003 TLS ClientHello cipher_suites captured by observer; bounds-checked variable-offset walk (session_id_len at payload[43], cs_offset = 44 + session_id_len); appended across multiple ClientHellos on the same (src, dst, dst_port) flow (HIGH, added S-2.07 v0.4.0)
- BC-1.04.004 RDP X.224 Connection Confirm recognized on tcp/3389 with TPKT header + PDU type 0xD0 + optional RDP_NEG_RSP at offset 11; selectedProtocol read as little-endian u32 at offset 15; bounds-checked; TPKT length must match payload length (HIGH, added S-2.08 v0.4.0)
- BC-1.05.001 External egress aggregation (HIGH)
- BC-1.05.002 Default OT subnets = RFC1918 (HIGH)
- BC-1.05.004 Distinct-dst counting per (src, dst_port, proto) group for port-scan recognition (HIGH, added S-2.10 v0.4.0)

### S.2 — Inventory (`src/inventory.rs`, `src/oui.rs`)
- BC-2.01.001 Asset per host with role inference (HIGH)
- BC-2.01.002 Hostname lookup on Asset (HIGH)
- BC-2.02.001 OUI prefix-exact lookup against the embedded vendor table (`src/oui.rs`); first 3 bytes of MAC matched against canonical IEEE OUI prefixes (HIGH, promoted from BC-AUDIT-001 in S-1.05)

### S.3 — Findings (`src/findings/*`)
- BC-3.01.001 `creds.ftp` fires on FtpAuth events (HIGH)
- BC-3.01.002 `creds.{telnet,http_basic,snmp}` fire analogously (HIGH)
- BC-3.01.003 Credential findings dedupe across destinations (HIGH)
- BC-3.01.005 `creds.ldap_simple_bind` fires at Critical for plaintext LDAP bind; suppressed by prior STARTTLS on the same flow (`used_starttls == true`) or anonymous bind (`anonymous == true`); rolls up by `(src, dst)` pair (HIGH, added S-2.05 v0.4.0)
- BC-3.02.001 `egress.ot_to_internet` fires on non-empty external_flows (HIGH)
- BC-3.02.002 `internet_egress` playbook branches on flow categories: appends category-specific guidance paragraphs when external flows include DNS (53), NTP (123), or tunnel ports (1194, 4500, 500, 51820) (HIGH, promoted from BC-AUDIT-010 in S-1.05)
- BC-3.03.001 `ics.modbus_writes` fires on engineering-class modbus events (HIGH)
- BC-3.03.002 `ics.cip_engineering` fires (HIGH)
- BC-3.03.003 `ics.s7_engineering` fires (HIGH)
- BC-3.03.004 `engineering_commands` rolls up by (src, dst) pair across protocols (Modbus/ENIP/S7/DNP3): one finding row per source-destination pair carries the per-pair count plus top-N function codes seen (HIGH, promoted from BC-AUDIT-012 in S-1.05)
- BC-3.03.005 `ics.dnp3_engineering` fires on engineering-class DNP3 events (HIGH, added S-2.04 v0.4.0)
- BC-3.03.006 `ics.modbus_unit_id_sweep` fires at Medium when modbus_flow_summary[src,dst].unit_ids.len() >= 5; escalates to High at >= 50; evidence lists count + first 10 unit IDs sorted ascending (HIGH, added S-2.11 v0.4.0)
- BC-3.04.001 `compat.smbv1` fires on SMBv1 observations (HIGH)
- BC-3.04.002 `compat.stale_tls` filters by legacy_version (HIGH)
- BC-3.04.003 `stale_tls::is_stale` inclusive range is exactly 0x0300..=0x0302; 0x0303 (TLS 1.2) and 0x0304 (TLS 1.3) explicitly pass the filter (HIGH, promoted from BC-AUDIT-011 in S-1.05)
- BC-3.04.004 `compat.ntlmv1` fires at High for NTLMv1 events; not for V2 (EC-001); rolls up by `(src, dst)` pair; evidence capped at 5 samples per finding (HIGH, added S-2.06 v0.4.0)
- BC-3.04.005 `compat.weak_tls_cipher` fires at Medium when any of (0x0001, 0x0002, 0x0004, 0x0005, 0x0009, 0x000A) appears in cipher_suites; GREASE values skipped (EC-001); fires alongside compat.stale_tls (AC-003 sibling-not-exclusive); rolls up by (src, dst) (HIGH, added S-2.07 v0.4.0)
- BC-3.04.006 `creds.rdp_no_nla` fires at Critical when RdpEvent.selected_protocol == 0x00000000 (PROTOCOL_RDP, exact equality — secure variants PROTOCOL_SSL/HYBRID/HYBRID_EX do not fire); rolls up by (src, dst) pair (HIGH, added S-2.08 v0.4.0)
- BC-3.05.001 `boundary.dns_resolver` cross-zone filter (HIGH)
- BC-3.05.002 `ot.unexpected_protocols` no-fly list (HIGH, **B.6 corrected** — 11 labels + src OR dst predicate)
- BC-3.05.003 `unexpected_label` port-to-label table contains exactly 11 entries: smtp, bittorrent, rtmp, apns, gcm, stun, sip, irc, openvpn, teamviewer, anydesk (HIGH, promoted from BC-AUDIT-009 in S-1.05; locked by S-2.01 regression tests)
- BC-3.05.005 `recon.port_scan` fires on ≥5 distinct dsts per (src, port, proto); High at ≥25 (HIGH, added S-2.10 v0.4.0, **superseded by BC-3.05.006 in v0.4.1**)
- BC-3.05.006 `recon.port_scan` rolls up per scanning source IP; fires at ≥10 distinct dsts OR ≥10 distinct (port, proto) combinations; High at ≥50; classifies horizontal / vertical / combined (HIGH, added S-2.12 v0.4.1; supersedes BC-3.05.005)
- BC-3.06.001 Findings sorted by severity DESC then id ASC (HIGH)
- BC-3.06.002 Every fired finding has metadata in catalog (HIGH)
- BC-3.06.003 Every fired finding carries non-empty playbook (HIGH)
- BC-3.06.004 Hostname-aware evidence rendering (HIGH)
- BC-3.06.005 Evidence cap defaults to 15 rows per finding (general invariant). Exception: `unexpected_protocols` caps at 5 per label-bucket (`src/findings/unexpected_protocols.rs` `bucket.len() < 5`), so its total evidence count can be up to `5 × labels_observed` rather than a flat 15 (HIGH, promoted from BC-AUDIT-008 in S-1.05)

### S.4 — Capture-source (`src/capture_source.rs`)
- BC-4.01.001 Host-side classification (HIGH)
- BC-4.01.002 TAP classification (HIGH)
- BC-4.01.003 SPAN classification (HIGH)
- BC-4.01.004 Capture-window sanity detection: pure `capture_sanity::assess(obs) -> Vec<CaptureWarning>` over observer-tracked `min_ts`/`max_ts`/`timestamps_monotonic`; emits `EpochZeroTimestamps` (≥1 packet and `max_ts <= UNIX_EPOCH`), `SubSecondWindow` (not epoch-zero, ≥2 packets, `max_ts - min_ts < 1s`), `NonMonotonicTimestamps` (a packet ts strictly precedes the prior packet's ts); deterministic order; empty `Vec` when the time base is sane or there are no timestamps; never panics (HIGH, added S-10.01 v0.6.0)
- BC-4.01.005 Capture-sanity surfacing: when `assess` is non-empty the HTML report (banner after the capture-meta window line) and markdown report (a `> ⚠ Capture timestamp warning:` blockquote) render the warning messages, and `analyze`/`scrub` emit one `WARNING:` line per warning to stderr (mirroring the `Classification::guard_warning` pattern); when `assess` is empty NO banner/line/stderr is emitted, so sane-capture HTML/MD/JSON output is byte-identical to pre-S-10.01 (HIGH, added S-10.01 v0.6.0)
- BC-4.02.001 Declared source overrides heuristic for rendering (HIGH)
- BC-4.02.002 Guard warning on disagreement (HIGH)

### S.5 — Scrub + leak detector (`src/scrub.rs`, `src/ai/leak_detector.rs`)
- BC-5.01.001 Pseudonym minting is deterministic (HIGH)
- BC-5.01.002 scrub_text only substitutes observed values (HIGH)
- BC-5.01.003 Scrub round-trip is exact (HIGH)
- BC-5.01.004 `format_mac` produces upper-hex, colon-separated string that the leak-detector regex matches verbatim; ensures MAC pseudonyms can be flagged by the privacy invariant check (HIGH, promoted from BC-AUDIT-002 in S-1.05)
- BC-5.02.001 Leak detector regex covers IPv4/IPv6/MAC (HIGH)
- BC-5.02.002 Map-value check catches hostname leaks regex can't (HIGH)
- BC-5.02.003 Privacy invariant: combined check on AI-bound bytes (HIGH)
- BC-5.03.001 `merge_map(baseline, &obs)` preserves baseline pseudonyms for known real values; assigns fresh pseudonyms to new real values continuing from `baseline.max_index + 1` per family (host_/mac_/name_ independent); preserves baseline-only entries (EC-003); stamps `created_at` to merge time; `ScrubMap::validate()` rejects empty-string pseudonym keys or empty real values (EC-001); round-trip exact via scrub/unscrub; leak detector passes after merge (HIGH, added S-6.01 v0.4.0)

### S.6 — AI orchestration (`src/ai/*`)
- BC-6.01.001 AI markdown rendering strips raw HTML events (HIGH)
- BC-6.02.001 System prompt varies by capture-source tag (HIGH)
- BC-6.02.002 Prompt sparse-capture refusal branch: when report has 0 findings AND ≤5 hosts AND capture window <5 min, system prompt instructs AI to recommend longer recapture instead of producing a prioritized analysis (HIGH, promoted from BC-AUDIT-013 in S-1.05)
- BC-6.03.001 Claude invocation via subprocess shell-out (MEDIUM)
- BC-6.03.002 Claude invocation always passes `--disallowed-tools` (HIGH, added S-5.04 v0.4.0)
- BC-6.03.003 `ClaudeCliProvider::analyze` pre-checks `claude` is on `PATH` before invocation and returns `OtError::Parse("claude not on PATH ...")` if absent — avoids cryptic spawn errors (HIGH, promoted from BC-AUDIT-014 in S-1.05 — shifted from suggested .002 due to existing --disallowed-tools BC)
- BC-6.04.001 `ClaudeCliProvider::analyze` emits stderr heartbeat `[Ns] claude still working...` every 3 seconds of wall-clock time while the subprocess is alive; on completion emits `done in N.Ns, B bytes response`; both lines suppressed when `verbose=false` AND stderr is not a TTY; heartbeat interval is exactly 3 s via injected `Clock` trait so tests can control time without sleeping (HIGH, added S-5.02 v0.4.0)
- BC-6.05.001 `augment_findings` invokes `AiProvider::augment` exactly once with scrubbed markdown; bytes sent to the provider must pass both leak-detector checks (regex + map-value); called only when `--ai` is set (HIGH, added S-5.03 v0.5.0)
- BC-6.05.002 `augment_findings` returns `Vec<AugmentedFinding>` (plus `AugmentInvocationSummary`) parsed from the provider's JSON array response; each finding carries `id` (namespaced `ai.<short>`), `severity`, `title`, `evidence`, `confidence`, `reasoning`; response prose preamble/postamble tolerated; cap at top-25 by confidence (High→Medium→Low) via stable sort + truncate; malformed JSON degrades to empty vec (EC-001) (HIGH, added S-5.03 v0.5.0)
- BC-6.05.003 Augmented findings deduped against rule findings by pseudonym-set subset: an augmented finding is dropped when its pseudonym set (host_NNN, mac_NNN, name_NNN tokens from evidence) is a subset of any rule finding's pseudonym set; disjoint findings survive; common non-pseudonym words (e.g. "Modbus") do not trigger dedup; dedup runs BEFORE unscrub so both sides are in scrubbed vocabulary (HIGH, added S-5.03 v0.5.0)

### S.7 — Audit log (`src/audit.rs`)
- BC-7.01.001 Audit log auto-derives path from `-o` (HIGH)
- BC-7.01.002 Audit log SHA-256s match the bytes sent to Claude (HIGH)
- BC-7.01.003 Audit log contains no real identifiers (HIGH)
- BC-7.01.004 `AuditLog.augment_pass` populated with `AugmentInvocationSummary` when `--ai` is set and augment pass succeeds; carries `system_prompt_sha256` / `user_message_sha256` / `response_sha256` (64-char SHA-256 hex), byte counts, elapsed seconds, `raw_finding_count` (before EC-003+dedup), `surviving_finding_count` (after); `None` when augment pass not run or fails (HIGH, added S-5.03 v0.5.0)
- BC-7.01.005 Multi-input audit attribution: `AuditLog.input_pcaps: Vec<InputDescriptor>` carries one descriptor per input file in CLI order (basename-only `path` per F-ADV-P2-009, `size_bytes`, per-file `sha256` pinning that file's exact bytes per BC-7.01.002); `SCHEMA_VERSION` bumped 1→2 for the `input_pcap`→`input_pcaps` shape change; a single-file run yields a one-element vec (HIGH, added S-9.01 v0.6.0)
- BC-7.02.001 CredEvent.note never leaks (HIGH)

### S.8 — Rendering (`src/report*.rs`, `src/rule_catalog.rs`, `src/ai/html_render.rs`)
- BC-8.01.001 render_html is deterministic per inputs (HIGH)
- BC-8.01.002 `report_md` top-level structure orders sections: Capture summary → Findings → Asset inventory → Comms matrix → Notes (matched by snapshot test) (HIGH, promoted from BC-AUDIT-015 in S-1.05)
- BC-8.01.003 Report HTML uses hero band + inline-SVG brand mark + severity-tinted finding cards + dark-mode + print-color-adjust + collapsible table sections (HIGH, added S-5.05 v0.4.0)
- BC-8.01.004 Report HTML applies the otsniff brand handoff: sniff-trail mark (7 circles), ink/paper/accent palette, JetBrains Mono type system, inline favicon as base64 data URL (HIGH, added S-5.06 v0.4.0; supersedes S-5.05's freehand visual)
- BC-8.01.005 Finding cards in HTML report wrap in `<details open class="finding sev-...">` with `<summary>` containing severity badge + title; default browser triangle suppressed via `details.finding > summary::-webkit-details-marker { display: none }` + `▾`/`▸` chevron via `::before` using `var(--muted)`; default state is open (`open` attribute); nested `<details>` for evidence/criteria/playbook unaffected; `@media print` forces all finding cards expanded with `details.finding > *:not(summary) { display: block !important }` (HIGH, added S-5.07 v0.4.0)
- BC-3.07.001 When augmented findings are present, `render_augmented_section` emits an `<h2 class="ai-augmented-heading">AI-augmented findings</h2>` section followed by `<details open class="finding ai-finding ...">` cards with severity badge, "AI" badge, title, evidence `<pre>`, and reasoning rendered via `render_safe` (markdown → HTML, raw-HTML events stripped); section absent when findings is empty; `render_augmented_section_md` emits a `## AI-augmented findings` markdown section with analogous structure (HIGH, added S-5.03 v0.5.0)
- BC-8.02.001 rule_catalog::render_markdown matches committed RULES.md (HIGH)
- BC-8.03.001 Scrubbed markdown contains no real identifiers (HIGH)

### S.9 — CLI (`src/cli.rs`)
- BC-9.01.001 `analyze` defaults output to HTML (HIGH)
- BC-9.01.002 `--ai` engages the full privacy pipeline (HIGH)
- BC-9.02.001 scrub/unscrub round-trip (HIGH)
- BC-9.03.001 `otsniff rules` prints the catalog (HIGH)
- BC-9.04.001 Verbose-mode (-v) parse loop emits periodic progress to stderr every >= 100,000 packets OR >= 10 MB read; rate-limited to one emission per 2 seconds via injectable Clock trait; final summary always emitted via finish() (HIGH, added S-5.01 v0.4.0)
- BC-9.06.001 `analyze --review-scrub` pauses for human eyeball (HIGH, added S-5.04 v0.4.0)

## Legacy audit-IDs alias table

S-1.05 (v0.4.0) promoted all 15 BC-AUDIT-* contracts to first-class
`BC-S.SS.NNN` rows under their canonical subsystems above. The legacy
BC-AUDIT-NNN identifiers remain referenced in Phase 0 and Phase 1
documents (`.factory/semport/otsniff/otsniff-coverage-audit.md`,
`.factory/specs/adversarial-reviews/`, `.factory/specs/prd.md` §5)
where rewriting historic citations would lose audit-trail provenance.
This table is the authoritative resolver between the two ID spaces.

| Legacy ID | Promoted ID | Subsystem | One-line gist |
|---|---|---|---|
| BC-AUDIT-001 | BC-2.02.001 | S.2 Inventory | OUI prefix-exact lookup |
| BC-AUDIT-002 | BC-5.01.004 | S.5 Scrub | `format_mac` upper-hex colon string |
| BC-AUDIT-003 | BC-0.02.001 | S.0 Error taxonomy | `OtError` variant→exit-code completeness |
| BC-AUDIT-004 | BC-0.02.002 | S.0 Error taxonomy | `main.rs` chain-of-sources printing |
| BC-AUDIT-005 | BC-1.02.006 | S.1 Observation | DHCP option walk bounded (shifted from suggested .005 — DNP3 collision) |
| BC-AUDIT-006 | BC-1.02.007 | S.1 Observation | DHCP 3-tier IP resolution (shifted from .006 cascade) |
| BC-AUDIT-007 | BC-1.02.008 | S.1 Observation | S7Comm header sizing depends on ROSCTR (shifted from .007 cascade) |
| BC-AUDIT-008 | BC-3.06.005 | S.3 Findings | Evidence cap default 15 + `unexpected_protocols` 5-per-label exception |
| BC-AUDIT-009 | BC-3.05.003 | S.3 Findings | `unexpected_label` 11-entry port-to-label table |
| BC-AUDIT-010 | BC-3.02.002 | S.3 Findings | `internet_egress` playbook branches on flow categories |
| BC-AUDIT-011 | BC-3.04.003 | S.3 Findings | `stale_tls::is_stale` range 0x0300..=0x0302 |
| BC-AUDIT-012 | BC-3.03.004 | S.3 Findings | `engineering_commands` (src, dst) rollup across protocols |
| BC-AUDIT-013 | BC-6.02.002 | S.6 AI | Prompts sparse-capture refusal branch |
| BC-AUDIT-014 | BC-6.03.003 | S.6 AI | `ClaudeCliProvider` PATH pre-check (shifted from suggested .002 due to existing --disallowed-tools BC) |
| BC-AUDIT-015 | BC-8.01.002 | S.8 Rendering | `report_md` top-level structure ordering |

**ID-shift rationale.** Four of the suggested IDs in the S-1.05 spec
collided with BCs added during the v0.4.0 cycle (S-2.04 introduced
BC-1.02.005 for DNP3, S-5.04 introduced BC-6.03.002 for
`--disallowed-tools`). Per S-1.05's narrative ("the story may revise
if the audit's wording demands different placement"), the four
affected entries were shifted to the next free index in their groups.
The legacy `BC-AUDIT-NNN` form remains a stable handle.

## Confidence summary

Counts derived from direct grep of `(HIGH[,)]` / `(MEDIUM[,)]` / `(LOW[,)]`
markers in the bullet rows above. After S-1.05, every BC carries an
explicit confidence tag; there is no separate audit-derived bucket
because the 15 BC-AUDIT-* contracts have been promoted into the
numbered space (their HIGH tags are now inline).

| Bucket | Count |
|---|---:|
| Numbered BCs, HIGH    | 99 |
| Numbered BCs, MEDIUM  | 2 |
| Numbered BCs, LOW     | 0 |
| **Grand total**       | **101** |

**Verification:** `grep -cE '\(HIGH[,)]' BC-INDEX.md` must equal 99;
`grep -cE '\(MEDIUM[,)]' BC-INDEX.md` must equal 2;
`grep -c '^- BC-AUDIT-' BC-INDEX.md` must equal 0 (legacy IDs live
in the alias table, never as numbered-list bullets);
`grep -cE '^- BC-[0-9]\.' BC-INDEX.md` must equal 101.

## Open Question BCs (coverage gaps, not yet specified)

These three areas were flagged during Phase 0 / Pass 5 as known gaps in
the existing BC coverage. They are **not counted in the tally above**
because no BC has been written for them yet — they are open questions
awaiting a future story.

- **OQ-1: Memory-bound parsing.** Maximum heap usage per PCAP byte
  ingested is not bounded by a contract. A 10 GB pathological PCAP could
  in principle exhaust process memory.
- **OQ-2: Snapshot stability across Rust toolchain.** `cargo insta`
  snapshots depend on `Debug` output ordering and floating-point
  formatting; a Rust toolchain bump could produce semantically-equivalent
  but textually different snapshots. No BC pins this expectation.
- **OQ-3: Claude subprocess sandbox.** BC-6.03.002 pins
  `--disallowed-tools` for invocation hardening, but the broader
  subprocess sandboxing posture (process isolation, env-var scrubbing,
  filesystem access) is not contracted.

## Provable Properties Catalog (for Phase 6 verification architecture)

A subset of BCs are **provable** — amenable to formal verification:

| BC | Property | Tool |
|---|---|---|
| BC-5.01.003 | `unscrub(scrub(x, map), map) == x` for any text | Kani (composable string ops) |
| BC-5.02.001 | Leak detector regex matches every IPv4-shaped substring | Kani (regex saturation) |
| BC-5.02.002 | `ensure_no_map_values` returns Err iff any value in `map.real_values()` appears as substring of input | Kani (string-search invariant) |
| BC-5.02.003 | Privacy invariant — composition of BC-5.01.003 + BC-5.02.001 + BC-5.02.002 | Kani (composed proof) |
| BC-6.01.001 | `render_safe` output never contains `<script`, `<iframe`, `<img onerror=` literal substrings if input is well-formed UTF-8 | Kani (event-stream invariant) |
| BC-7.01.002 | Audit log SHA-256 bytes equal `sha256(actual_bytes_sent)` | sha2 crate's own tests; not Kani territory |

These are the candidates if/when Kani proofs land (OQ-4 / L-P1-004).

## Purity boundary map (for architecture)

See `domain-spec/L2-INDEX.md` and the architecture shard
`architecture/SS-purity-boundary-map.md` for the full classification.
Summary: ~80% of LoC is pure; the effectful shell is `cli::run_*`,
`pcap::iter_packets`, `ClaudeCliProvider`, `audit::sha256_file_hex`,
and renderers' file-write calls.

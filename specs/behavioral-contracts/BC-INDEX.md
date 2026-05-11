---
artifact_type: behavioral-contract-index
project: otsniff
generated: 2026-05-11
status: draft (brownfield-recovered)
total_bcs: 60
origin: recovered
canonical_source: .factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md
deviations:
  - Per-BC sharding (.factory/specs/behavioral-contracts/ss-{subsystem}/BC-{bc-id}.md)
    skipped for brownfield retrofit on a small project. 60 trivially-different
    files would outweigh the benefit at this project size. If a customer-grade
    traceability matrix is needed later, this index expands into the canonical
    pattern.
---

# Behavioral Contracts — Master Index

60 BCs across 10 subsystems (S.0–S.9). Full text in
`.factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md`
with B.6 corrections applied in `.factory/specs/prd.md` §5.

## Index by subsystem

### S.0 — PCAP iteration (`src/pcap.rs`)
- BC-0.01.001 Iterate packets from valid PCAP/PCAPNG (HIGH)
- BC-0.01.002 Reject non-PCAP input (HIGH)
- BC-0.01.003 Reject missing input (HIGH)
- BC-0.01.004 Owned packet payloads (MEDIUM)

### S.1 — Observation + protocol parsing (`src/observe.rs`, `src/parse/*`)
- BC-1.01.001 Single-pass accumulator (HIGH)
- BC-1.01.002 Logical flow keying drops src_port (HIGH)
- BC-1.02.001 Modbus PDU recognition + engineering classification (HIGH, **B.6 corrected**)
- BC-1.02.002 ENIP/CIP engineering service recognition (HIGH)
- BC-1.02.003 S7Comm function code classification (HIGH, **B.6 corrected**)
- BC-1.02.004 DHCP option-12 hostname extraction (HIGH)
- BC-1.03.001 FTP credential observation (HIGH)
- BC-1.03.002 Telnet session observation (HIGH)
- BC-1.03.003 HTTP Basic credential observation (HIGH)
- BC-1.03.004 SNMPv1/v2c credential observation (HIGH)
- BC-1.04.001 SMBv1 packet observation (HIGH)
- BC-1.04.002 TLS ClientHello version capture (HIGH)
- BC-1.05.001 External egress aggregation (HIGH)
- BC-1.05.002 Default OT subnets = RFC1918 (HIGH)

### S.2 — Inventory (`src/inventory.rs`)
- BC-2.01.001 Asset per host with role inference (HIGH)
- BC-2.01.002 Hostname lookup on Asset (HIGH)

### S.3 — Findings (`src/findings/*`)
- BC-3.01.001 `creds.ftp` fires on FtpAuth events (HIGH)
- BC-3.01.002 `creds.{telnet,http_basic,snmp}` fire analogously (HIGH)
- BC-3.01.003 Credential findings dedupe across destinations (HIGH)
- BC-3.02.001 `egress.ot_to_internet` fires on non-empty external_flows (HIGH)
- BC-3.03.001 `ics.modbus_writes` fires on engineering-class modbus events (HIGH)
- BC-3.03.002 `ics.cip_engineering` fires (HIGH)
- BC-3.03.003 `ics.s7_engineering` fires (HIGH)
- BC-3.04.001 `compat.smbv1` fires on SMBv1 observations (HIGH)
- BC-3.04.002 `compat.stale_tls` filters by legacy_version (HIGH)
- BC-3.05.001 `boundary.dns_resolver` cross-zone filter (HIGH)
- BC-3.05.002 `ot.unexpected_protocols` no-fly list (HIGH, **B.6 corrected** — 11 labels + src OR dst predicate)
- BC-3.06.001 Findings sorted by severity DESC then id ASC (HIGH)
- BC-3.06.002 Every fired finding has metadata in catalog (HIGH)
- BC-3.06.003 Every fired finding carries non-empty playbook (HIGH)
- BC-3.06.004 Hostname-aware evidence rendering (HIGH)

### S.4 — Capture-source (`src/capture_source.rs`)
- BC-4.01.001 Host-side classification (HIGH)
- BC-4.01.002 TAP classification (HIGH)
- BC-4.01.003 SPAN classification (HIGH)
- BC-4.02.001 Declared source overrides heuristic for rendering (HIGH)
- BC-4.02.002 Guard warning on disagreement (HIGH)

### S.5 — Scrub + leak detector (`src/scrub.rs`, `src/ai/leak_detector.rs`)
- BC-5.01.001 Pseudonym minting is deterministic (HIGH)
- BC-5.01.002 scrub_text only substitutes observed values (HIGH)
- BC-5.01.003 Scrub round-trip is exact (HIGH)
- BC-5.02.001 Leak detector regex covers IPv4/IPv6/MAC (HIGH)
- BC-5.02.002 Map-value check catches hostname leaks regex can't (HIGH)
- BC-5.02.003 Privacy invariant: combined check on AI-bound bytes (HIGH)

### S.6 — AI orchestration (`src/ai/*`)
- BC-6.01.001 AI markdown rendering strips raw HTML events (HIGH)
- BC-6.02.001 System prompt varies by capture-source tag (HIGH)
- BC-6.03.001 Claude invocation via subprocess shell-out (MEDIUM)

### S.7 — Audit log (`src/audit.rs`)
- BC-7.01.001 Audit log auto-derives path from `-o` (HIGH)
- BC-7.01.002 Audit log SHA-256s match the bytes sent to Claude (HIGH)
- BC-7.01.003 Audit log contains no real identifiers (HIGH)
- BC-7.02.001 CredEvent.note never leaks (HIGH)

### S.8 — Rendering (`src/report*.rs`, `src/rule_catalog.rs`, `src/ai/html_render.rs`)
- BC-8.01.001 render_html is deterministic per inputs (HIGH)
- BC-8.02.001 rule_catalog::render_markdown matches committed RULES.md (HIGH)
- BC-8.03.001 Scrubbed markdown contains no real identifiers (HIGH)

### S.9 — CLI (`src/cli.rs`)
- BC-9.01.001 `analyze` defaults output to HTML (HIGH)
- BC-9.01.002 `--ai` engages the full privacy pipeline (HIGH)
- BC-9.02.001 scrub/unscrub round-trip (HIGH)
- BC-9.03.001 `otsniff rules` prints the catalog (HIGH)

## Audit-derived BCs (from Phase 0 B.5)

- BC-AUDIT-001 OUI prefix-exact lookup
- BC-AUDIT-002 format_mac upper-hex colon string for leak-detector match
- BC-AUDIT-003 OtError variant-to-exit-code mapping completeness
- BC-AUDIT-004 OtError chain-of-sources printing in main.rs
- BC-AUDIT-005 DHCP 3-tier IP resolution (yiaddr / ciaddr / option 50)
- BC-AUDIT-006 DHCP bounded option walk after magic-cookie validation
- BC-AUDIT-007 S7 ROSCTR-driven header sizing
- BC-AUDIT-008 dns_resolver evidence cap is 15
- BC-AUDIT-009 unexpected_label port-to-label table (11 entries, see L-P0-001)
- BC-AUDIT-010 internet_egress evidence cap is 15
- BC-AUDIT-011 stale_tls evidence cap is 15
- BC-AUDIT-012 engineering_commands evidence cap is 15
- BC-AUDIT-013 ai::prompts sparse-capture refusal branch
- BC-AUDIT-014 ClaudeCliProvider PATH pre-check
- BC-AUDIT-015 report_md top-level structure ordering

## Confidence summary

| Confidence | Count |
|---|---:|
| HIGH | 54 |
| MEDIUM | 5 |
| LOW (gaps) | 3 (memory bound, snapshot stability across Rust toolchain, claude subprocess sandbox) |
| AUDIT (BC-AUDIT-* from B.5, all HIGH) | 15 |

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

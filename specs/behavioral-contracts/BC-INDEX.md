---
artifact_type: behavioral-contract-index
project: otsniff
generated: 2026-05-14
status: draft (brownfield-recovered)
total_bcs: 69  # numbered BCs across S.0..S.9; +15 BC-AUDIT-* tracked separately
origin: recovered
canonical_source: .factory/semport/otsniff/otsniff-pass-3-behavioral-contracts.md
deviations:
  - Per-BC sharding (.factory/specs/behavioral-contracts/ss-{subsystem}/BC-{bc-id}.md)
    skipped for brownfield retrofit on a small project. 69 trivially-different
    files would outweigh the benefit at this project size. If a customer-grade
    traceability matrix is needed later, this index expands into the canonical
    pattern.
---

# Behavioral Contracts — Master Index

69 numbered BCs across 10 subsystems (S.0–S.9), plus 15 BC-AUDIT-*
contracts derived from the brownfield code audit. Full text in
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
- BC-1.02.005 DNP3 frame recognition + engineering classification (HIGH, added S-2.04 v0.4.0)
- BC-1.03.001 FTP credential observation (HIGH)
- BC-1.03.002 Telnet session observation (HIGH)
- BC-1.03.003 HTTP Basic credential observation (HIGH)
- BC-1.03.004 SNMPv1/v2c credential observation (HIGH)
- BC-1.04.001 SMBv1 packet observation (HIGH)
- BC-1.04.002 TLS ClientHello version capture (HIGH)
- BC-1.05.001 External egress aggregation (HIGH)
- BC-1.05.002 Default OT subnets = RFC1918 (HIGH)
- BC-1.05.004 Distinct-dst counting per (src, dst_port, proto) group for port-scan recognition (HIGH, added S-2.10 v0.4.0)

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
- BC-3.03.005 `ics.dnp3_engineering` fires on engineering-class DNP3 events (HIGH, added S-2.04 v0.4.0)
- BC-3.04.001 `compat.smbv1` fires on SMBv1 observations (HIGH)
- BC-3.04.002 `compat.stale_tls` filters by legacy_version (HIGH)
- BC-3.05.001 `boundary.dns_resolver` cross-zone filter (HIGH)
- BC-3.05.002 `ot.unexpected_protocols` no-fly list (HIGH, **B.6 corrected** — 11 labels + src OR dst predicate)
- BC-3.05.005 `recon.port_scan` fires on ≥5 distinct dsts per (src, port, proto); High at ≥25 (HIGH, added S-2.10 v0.4.0, **superseded by BC-3.05.006 in v0.4.1**)
- BC-3.05.006 `recon.port_scan` rolls up per scanning source IP; fires at ≥10 distinct dsts OR ≥10 distinct (port, proto) combinations; High at ≥50; classifies horizontal / vertical / combined (HIGH, added S-2.12 v0.4.1; supersedes BC-3.05.005)
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
- BC-6.03.002 Claude invocation always passes `--disallowed-tools` (HIGH, added S-5.04 v0.4.0)

### S.7 — Audit log (`src/audit.rs`)
- BC-7.01.001 Audit log auto-derives path from `-o` (HIGH)
- BC-7.01.002 Audit log SHA-256s match the bytes sent to Claude (HIGH)
- BC-7.01.003 Audit log contains no real identifiers (HIGH)
- BC-7.02.001 CredEvent.note never leaks (HIGH)

### S.8 — Rendering (`src/report*.rs`, `src/rule_catalog.rs`, `src/ai/html_render.rs`)
- BC-8.01.001 render_html is deterministic per inputs (HIGH)
- BC-8.01.003 Report HTML uses hero band + inline-SVG brand mark + severity-tinted finding cards + dark-mode + print-color-adjust + collapsible table sections (HIGH, added S-5.05 v0.4.0)
- BC-8.01.004 Report HTML applies the otsniff brand handoff: sniff-trail mark (7 circles), ink/paper/accent palette, JetBrains Mono type system, inline favicon as base64 data URL (HIGH, added S-5.06 v0.4.0; supersedes S-5.05's freehand visual)
- BC-8.02.001 rule_catalog::render_markdown matches committed RULES.md (HIGH)
- BC-8.03.001 Scrubbed markdown contains no real identifiers (HIGH)

### S.9 — CLI (`src/cli.rs`)
- BC-9.01.001 `analyze` defaults output to HTML (HIGH)
- BC-9.01.002 `--ai` engages the full privacy pipeline (HIGH)
- BC-9.02.001 scrub/unscrub round-trip (HIGH)
- BC-9.03.001 `otsniff rules` prints the catalog (HIGH)
- BC-9.06.001 `analyze --review-scrub` pauses for human eyeball (HIGH, added S-5.04 v0.4.0)

## Audit-derived BCs (from Phase 0 B.5)

- BC-AUDIT-001 OUI prefix-exact lookup
- BC-AUDIT-002 format_mac upper-hex colon string for leak-detector match
- BC-AUDIT-003 OtError variant-to-exit-code mapping completeness
- BC-AUDIT-004 OtError chain-of-sources printing in main.rs
- BC-AUDIT-005 DHCP option walk is bounded and length-checked
- BC-AUDIT-006 DHCP 3-tier IP resolution (yiaddr / ciaddr / option 50)
- BC-AUDIT-007 S7Comm header sizing depends on ROSCTR
- BC-AUDIT-008 Evidence cap of 15 rows per finding (general invariant). Exception: `unexpected_protocols` caps at 5 per label (`src/findings/unexpected_protocols.rs` `bucket.len() < 5`), so total evidence rows can be up to `5 × labels_observed`
- BC-AUDIT-009 unexpected_label port-to-label table (11 entries, see L-P0-001)
- BC-AUDIT-010 internet_egress playbook branches on flow categories (DNS, NTP, tunnel ports)
- BC-AUDIT-011 stale_tls is_stale range is 0x0300..=0x0302
- BC-AUDIT-012 engineering_commands rolls up by (src, dst) pair
- BC-AUDIT-013 ai::prompts sparse-capture refusal branch
- BC-AUDIT-014 ClaudeCliProvider PATH pre-check
- BC-AUDIT-015 report_md top-level structure ordering

## Confidence summary

Counts derived from direct grep of `(HIGH[,)]` / `(MEDIUM[,)]` / `(LOW[,)]`
markers in the bullet rows above. BC-AUDIT-* rows are uniformly HIGH per
the audit source (`.factory/semport/otsniff/otsniff-coverage-audit.md`)
even though the bullet form omits the per-row tag; they're counted
separately to preserve the numbered/audit-derived split.

| Bucket | Count |
|---|---:|
| Numbered BCs, HIGH    | 67 |
| Numbered BCs, MEDIUM  | 2 |
| Numbered BCs, LOW     | 0 |
| **Numbered subtotal** | **69** |
| BC-AUDIT-* (all HIGH) | 15 |
| **Grand total**       | **84** |

**Verification:** `grep -cE '\(HIGH[,)]' BC-INDEX.md` must equal 67;
`grep -cE '\(MEDIUM[,)]' BC-INDEX.md` must equal 2;
`grep -c '^- BC-AUDIT-' BC-INDEX.md` must equal 15;
`grep -cE '^- BC-[0-9]\.' BC-INDEX.md` must equal 69.

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

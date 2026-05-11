---
artifact_type: architecture-shard
shard: verification-coverage-matrix
project: otsniff
traces_to:
  - ARCH-INDEX.md
  - SS-verification-architecture.md
---

# Verification Coverage Matrix

Per-BC mapping of "what verifies this." Sentinel tests, snapshot
tests, and unit tests cited by their function name.

## Subsystem S.0 — PCAP iteration

| BC | Verified by | Type |
|---|---|---|
| BC-0.01.001 Iterate packets from valid PCAP | `analyze_valid_pcap_produces_html_and_exits_0` | CLI smoke |
| BC-0.01.002 Reject non-PCAP input | `analyze_malformed_input_exits_2` | CLI smoke |
| BC-0.01.003 Reject missing input | `analyze_nonexistent_input_exits_2` | CLI smoke |
| BC-0.01.004 Owned packet payloads | Type signature check (impl detail; no direct test) | Compile-time |

## Subsystem S.1 — Observation + parsing

| BC | Verified by | Type |
|---|---|---|
| BC-1.01.001 Single-pass accumulator | Implicit in every snapshot fixture | Snapshot (implicit) |
| BC-1.01.002 Logical flow keying drops src_port | `tests/snapshot.rs` fixture has multiple connections aggregating to one flow | Snapshot |
| BC-1.02.001 Modbus PDU recognition | `src/parse/modbus.rs::tests` | Unit |
| BC-1.02.002 ENIP/CIP engineering | `src/parse/enip.rs::tests` | Unit |
| BC-1.02.003 S7Comm function code | `src/parse/s7comm.rs::tests` | Unit |
| BC-1.02.004 DHCP option-12 | `src/parse/dhcp.rs::tests` (7 unit tests) | Unit |
| BC-1.03.001–.004 Credential observation | `src/findings/plaintext_creds.rs::tests` + fixture | Unit + snapshot |
| BC-1.04.001 SMBv1 magic | `src/observe.rs::tests::smb1_magic_at_offset_*` | Unit |
| BC-1.04.002 TLS ClientHello version | Snapshot fixture (`tests/snapshot.rs::build_fixture` includes ClientHello) | Snapshot |
| BC-1.05.001 External egress | Snapshot fixture exercises | Snapshot |
| BC-1.05.002 Default OT = RFC1918 | `src/cli.rs::ot_or_default` literal check | Implicit (no direct test) |

## Subsystem S.2 — Inventory

| BC | Verified by | Type |
|---|---|---|
| BC-2.01.001 Asset + role inference | `src/inventory.rs::tests::infer_role_*` | Unit |
| BC-2.01.002 Hostname lookup | `finding_evidence_surfaces_hostnames_when_we_know_them` | Sentinel |

## Subsystem S.3 — Findings

| BC | Verified by | Type |
|---|---|---|
| BC-3.01.001 `creds.ftp` fires | `findings_json_snapshot` + fixture | Snapshot |
| BC-3.01.002 `creds.{telnet,http_basic,snmp}` | Same | Snapshot |
| BC-3.01.003 Credential dedup | `src/findings/plaintext_creds.rs::tests::rolls_up_one_finding_per_kind_across_many_hosts` | Unit |
| BC-3.02.001 `egress.ot_to_internet` fires | Snapshot fixture | Snapshot |
| BC-3.03.001–.003 `ics.*` fires | Snapshot fixture | Snapshot |
| BC-3.04.001 `compat.smbv1` fires | Snapshot fixture | Snapshot |
| BC-3.04.002 `compat.stale_tls` filters | Snapshot fixture (legacy_version=0x0301 included) | Snapshot |
| BC-3.05.001 `boundary.dns_resolver` cross-zone | Snapshot fixture | Snapshot |
| BC-3.05.002 `ot.unexpected_protocols` | Snapshot fixture (note B.6 correction; current test fixture may not exercise all 11 labels) | Snapshot (partial) |
| BC-3.06.001 Sort order | Implicit in every snapshot output | Snapshot (implicit) |
| BC-3.06.002 Catalog membership | `every_finding_id_appears_in_the_rule_catalog` | Sentinel |
| BC-3.06.003 Non-empty playbook | `every_finding_has_a_non_empty_playbook` | Sentinel |
| BC-3.06.004 Hostname rendering | `finding_evidence_surfaces_hostnames_when_we_know_them` | Sentinel |

## Subsystem S.4 — Capture-source

| BC | Verified by | Type |
|---|---|---|
| BC-4.01.001 Host-side | `src/capture_source.rs::tests::host_side_dominance_classifies_correctly` | Unit |
| BC-4.01.002 TAP | `src/capture_source.rs::tests::tap_pattern_classifies_correctly` | Unit |
| BC-4.01.003 SPAN | `src/capture_source.rs::tests::span_pattern_classifies_correctly` | Unit |
| BC-4.02.001 Declared authoritative | `src/capture_source.rs::tests::declared_source_is_authoritative_for_report_line` | Unit |
| BC-4.02.002 Guard warning | `src/capture_source.rs::tests::declared_source_disagreeing_with_heuristic_produces_warning` | Unit |

## Subsystem S.5 — Privacy

| BC | Verified by | Type |
|---|---|---|
| BC-5.01.001 Deterministic minting | `src/scrub.rs::tests::build_map_assigns_pseudonyms_deterministically` | Unit |
| BC-5.01.002 Only-observed substitution | `src/scrub.rs::tests::scrub_does_not_touch_unobserved_values` | Unit |
| BC-5.01.003 Scrub round-trip exact | `src/scrub.rs::tests::unscrub_reverses_scrub` | Unit |
| BC-5.02.001 Leak detector regex | `src/ai/leak_detector.rs::tests::flags_*` (4 tests) | Unit |
| BC-5.02.002 Map-value catches hostnames | `src/ai/leak_detector.rs::tests::ensure_no_map_values_catches_hostname_leak_that_regex_misses` | Unit |
| BC-5.02.003 Privacy invariant on AI-bound bytes | `invariant_no_real_values_reach_ai_provider` | Sentinel |

## Subsystem S.6 — AI

| BC | Verified by | Type |
|---|---|---|
| BC-6.01.001 AI HTML strips raw | `ai_section_in_html_strips_script_tags_from_claude_response` + `src/ai/html_render.rs::tests::strips_raw_html_*` | Sentinel + unit |
| BC-6.02.001 System prompt per tag | `system_prompt_for_each_source_tag_snapshots` | Snapshot |
| BC-6.03.001 Claude subprocess | (no e2e test; documented as MEDIUM confidence) | None |

## Subsystem S.7 — Audit log

| BC | Verified by | Type |
|---|---|---|
| BC-7.01.001 Path auto-derives | `src/cli.rs::default_audit_log_path` (implicit; no direct test) | Implicit |
| BC-7.01.002 SHA-256 match | `src/audit.rs::tests::sha256_hex_is_stable` + populated in CLI | Unit + integration |
| BC-7.01.003 No real identifiers | `audit_log_rendered_for_an_analyze_run_carries_no_real_identifiers` | Sentinel |
| BC-7.02.001 CredEvent.note containment | `cred_event_note_must_not_reach_any_rendered_output` | Sentinel |

## Subsystem S.8 — Rendering

| BC | Verified by | Type |
|---|---|---|
| BC-8.01.001 render_html deterministic | `html_report_snapshot` | Snapshot |
| BC-8.02.001 Catalog matches RULES.md | `rule_catalog_matches_committed_rules_md` | Sentinel |
| BC-8.03.001 Scrubbed markdown no leaks | `scrubbed_markdown_snapshot_does_not_leak_real_values` | Sentinel + snapshot |

## Subsystem S.9 — CLI

| BC | Verified by | Type |
|---|---|---|
| BC-9.01.001 `analyze` defaults to HTML | `analyze_valid_pcap_produces_html_and_exits_0` | CLI smoke |
| BC-9.01.002 `--ai` full pipeline | (privacy invariant test exercises components; no end-to-end test) | Partial |
| BC-9.02.001 scrub/unscrub round-trip | `scrub_round_trip_via_pcap` + `unscrub_strict_mode_fails_on_unknown_token` | CLI smoke |
| BC-9.03.001 `otsniff rules` prints | (no direct test; `rule_catalog_matches_committed_rules_md` exercises catalog rendering) | Indirect |

## Coverage summary

| Type | BC count |
|---|---:|
| Unit tests | 27 BCs directly |
| Snapshot tests | 21 BCs (via shared snapshot fixture) |
| Sentinel tests | 9 BCs |
| CLI smoke | 7 BCs |
| Compile-time / implicit | 5 BCs (type signatures, literal constants) |
| Untested (documented gap) | 3 BCs (BC-6.03.001, BC-9.01.002 partial, BC-9.03.001 indirect) |

| Audit BCs (BC-AUDIT-*) | 15 — all flagged for future test coverage |

## Untested BC remediation

- **BC-6.03.001 (Claude subprocess shell-out):** Requires `claude` CLI in CI. Punted — `claude` is an external dependency not part of the Rust toolchain.
- **BC-9.01.002 (`--ai` full pipeline):** Partial coverage via component tests. A real e2e test would require Claude credentials in CI; alternative is a fake `AiProvider` that exercises the orchestration without invoking real AI.
- **BC-9.03.001 (`otsniff rules` prints to stdout):** Indirect coverage via `rule_catalog_matches_committed_rules_md`. A direct CLI smoke test would be ~10 LoC; worth adding.

These three are candidates for the next test sweep.

# S-9.01 Demo Evidence Report

Story: Multi-PCAP / rotated-capture analyze (P0-10)
Branch: `feature/S-9.01-multi-pcap-analyze`
Recorded: 2026-06-30

## Summary

Two VHS terminal recordings against synthetic PCAP fixtures cover the
story's primary behaviors. The fixtures are hand-crafted with the Python
stdlib only (`struct`, no scapy) — two single-packet Ethernet captures plus
one LINUX_SLL capture. All tape files and the fixture generator are free of
absolute paths (POL-12 compliant; the `/tmp` output paths are not user paths).

---

## AC Coverage

### AC-001 / AC-002 / AC-005 (BC-1.01.003) — ordered multi-file ingestion

**Demo:** `AC-001-002-multi-pcap-union` (success path)

`capture-part1.pcap` carries hosts `192.168.10.10`/`.20`; `capture-part2.pcap`
carries `192.168.10.30`/`.40`. Running:

```
otsniff analyze .../capture-part1.pcap .../capture-part2.pcap -o report.html --json findings.json
```

emits a single report (`0 findings across 4 hosts`), and the JSON inventory is
the **union** of both captures:

```
192.168.10.10
192.168.10.20
192.168.10.30
192.168.10.40
```

No `mergecap` step — the two rotated captures are treated as one logical
capture in command-line order. Per-packet timestamps are preserved, so the
capture window spans both files.

### AC-003 / EC-003 (BC-1.01.004) — link-layer homogeneity guard

**Demo:** `EC-003-link-type-guard` (refusal path)

Merging the Ethernet `capture-part1.pcap` with the LINUX_SLL `sll.pcap` is
refused before any report is written:

```
otsniff: cannot merge captures with differing link-layer types: \
  capture-part1.pcap=ETHERNET, sll.pcap=LINUX_SLL; \
  merge only captures that share the same link-layer type
exit-code=65
```

The error names both files and both link types and exits `65` (`EX_DATAERR`)
— no silent misparse of incompatible L2 framing.

### AC-004 (BC-7.01.005) — per-file audit attribution

Covered by unit/integration tests (`audit.rs::input_pcaps_serializes_as_array_with_schema_v2`,
`tests/snapshot.rs`) rather than a recording (the audit log is only written
with `--ai`, which needs the local `claude` CLI). `AuditLog.input_pcaps` is an
array with one basename-only descriptor per input file; `schema_version` is `2`.

### AC-001 single-file parity

`otsniff analyze capture-part1.pcap -o report.html` continues to exit `0` and
produce a report (`0 findings across 2 hosts`) — byte-identical to the
pre-S-9.01 single-file path (locked by
`cli::tests::source_labels_single_file_identical_and_multi_file_capped` and the
unchanged single-file report/MD/JSON snapshots).

---

## Fixtures

| File | Link type | Contents |
|------|-----------|----------|
| `fixtures/capture-part1.pcap` | ETHERNET (1) | `192.168.10.10 → .20`, Modbus/TCP (port 502) |
| `fixtures/capture-part2.pcap` | ETHERNET (1) | `192.168.10.30 → .40`, Modbus/TCP (port 502) |
| `fixtures/sll.pcap` | LINUX_SLL (113) | one packet — drives the homogeneity-guard refusal |

Regenerate with: `python3 docs/demo-evidence/S-9.01/fixtures/make_pcaps.py`

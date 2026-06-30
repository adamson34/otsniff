---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-06-30T00:00:00Z
phase: 2
inputs: [stories/S-9.01-multi-pcap-analyze.md, behavioral-contracts/BC-INDEX.md]
traces_to: "P0-10"
id: "HS-010"
category: "integration-boundaries"
must_pass: "true"
priority: "must-pass"
wave: 2
epic_id: "E-9"
behavioral_contracts: ["BC-1.01.003", "BC-1.01.004", "BC-7.01.005"]
lifecycle_status: active
introduced: v0.6.0-feature
---

# HS-010: Multi-PCAP analyze unions captures, guards link types, attributes per file

> **NOT FOR IMPLEMENTERS.**

You are a black-box evaluator. You see only the `otsniff` CLI and its
outputs — never the source. Construct your own inputs; do not assume any
particular internal function exists.

## Scenario

`otsniff analyze` accepts more than one positional PCAP, treats the set as one
logical capture in command-line order, refuses to merge captures with
incompatible link layers, and (with `--ai`) records one audit descriptor per
input file.

### Setup (build your own fixtures — do not rely on gitignored fixtures)

From any single Ethernet capture you can obtain (or one you synthesize), make
two non-overlapping time slices, e.g.:

```
editcap -A "<start>" -B "<mid>" whole.pcap part1.pcap
editcap -A "<mid+1s>" -B "<end>" whole.pcap part2.pcap
```

If you have no capture at all, synthesize two minimal single-packet Ethernet
PCAPs (e.g. with a 5-line Python/scapy script) named `a.pcap`, `b.pcap`, where
`a.pcap`'s packet timestamp precedes `b.pcap`'s.

### Checks

1. **Union ingestion (BC-1.01.003).**
   - `otsniff analyze part1.pcap part2.pcap -o multi.html` exits `0` and writes
     one report.
   - The host set in `multi.html` (or `--json multi.json`) is the **union** of
     the host sets from `otsniff analyze part1.pcap` and
     `otsniff analyze part2.pcap` run separately. No host present in either
     single-file report is missing from the multi-file report.
   - The reported capture window of `multi.html` starts no later than part1's
     window start and ends no earlier than part2's window end (the files were
     sliced in chronological order).

2. **CLI-order, not sorted.** Reversing the argument order
   (`analyze part2.pcap part1.pcap`) still exits `0` and still yields the same
   host union (order affects only processing order, not which hosts appear).

3. **Zero-input rejection (BC-1.01.003 precondition).**
   - `otsniff analyze` with no positional file exits non-zero and prints a
     usage / "required" message. (Exit code 2 is acceptable — clap default.)

4. **Link-layer guard (BC-1.01.004).**
   - Synthesize a non-Ethernet capture `sll.pcap` (LINKTYPE_LINUX_SLL = 113;
     a tiny hand-written global header is enough — no packets required).
   - `otsniff analyze part1.pcap sll.pcap -o x.html` exits **non-zero**, writes
     no report, and the stderr message names BOTH files and mentions
     differing/incompatible link-layer types.

5. **Per-file audit attribution (BC-7.01.005)** — only if a local `claude` CLI
   is available for `--ai`; otherwise mark this check `n/a`, not failed.
   - `otsniff analyze part1.pcap part2.pcap -o m.html --ai --audit-log m.audit.json`
   - `m.audit.json` contains an **array** of input descriptors with exactly two
     elements; each element's `path` is a **basename only** (no `/` directory
     component) and carries a 64-hex-char `sha256`. `schema_version` is `2`.

6. **Single-file parity.** `otsniff analyze part1.pcap -o single.html` produces
   a report whose findings + inventory match what the tool produced for that
   same file before multi-file support (no behavioral regression for the
   one-file case).

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-1.01.003 | ordered concatenation, union window, zero-input rejection |
| BC-1.01.004 | mixed link types refused with a file-naming error |
| BC-7.01.005 | audit log carries one basename-only descriptor per input file; schema_version 2 |

## Verification Approach

- Diff the host/finding sets of separate single-file runs against the
  multi-file run (checks 1–2).
- Assert non-zero exit + no output file for the guard and zero-input cases
  (checks 3–4).
- Parse `m.audit.json` and assert the `input_pcaps` array shape (check 5).
- Compare single-file output against the pre-feature baseline if available
  (check 6).

## Evaluation Rubric

- Functional correctness (0.6): union ingestion + per-file audit attribution
  correct.
- Edge case handling (0.3): link-type guard + zero-input rejection behave as
  specified (no panic, clear error, no partial report).
- Performance (0.1): multi-file run completes within roughly the sum of the
  single-file run times.

## Failure Guidance

"HOLDOUT LOW: HS-010 (satisfaction: 0.XX) — multi-PCAP analyze failed to union
captures, did not guard mismatched link layers, or audit attribution was not
per-file."

---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-05-11T20:50:00Z
phase: 2
inputs: [stories/, behavioral-contracts/, prd.md]
traces_to: ""
id: "HS-006"
category: "edge-case-combinations"
must_pass: "true"
priority: "must-pass"
wave: 2
epic_id: "E-3"
behavioral_contracts: ["BC-0.01.002"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-006: 60-second fuzz of every parser produces no panics

> **NOT FOR IMPLEMENTERS.**

## Scenario

After S-3.04 lands, running each fuzz target for 60 seconds on the
evaluator's machine produces zero crashes.

1. **Precondition:** Wave-2 post-merge of S-3.04. `cargo-fuzz` installed.
2. **Action:** `cargo +nightly fuzz run parse_modbus -- -max_total_time=60`
   repeated for each parser target (modbus, enip, s7comm, dhcp, dnp3,
   scrub_text).
3. **Expected:**
   - Zero panics, zero unwinds.
   - Zero new artifacts written to `fuzz/artifacts/<target>/`.
   - libfuzzer reports "covered" code lines > a baseline (≥ 50% of parser
     LoC) per target — soft check, not a fail.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-0.01.002 | reject non-PCAP input — parsers must reject without panic |

## Verification Approach

- Run each target.
- Inspect `fuzz/artifacts/` after run.
- Capture libfuzzer's "stat::number_of_executed_units" + coverage report.

## Evaluation Rubric

- Functional correctness (0.7): no panic
- Edge case handling (0.2): coverage threshold reached
- Performance (0.1): runs within wall budget

## Failure Guidance

"HOLDOUT LOW: HS-006 (satisfaction: 0.XX) — fuzz target produced a crash or coverage below threshold"

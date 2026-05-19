---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-05-19T00:00:00Z
phase: 3
inputs:
  - .factory/stories/S-3.01-criterion-benchmarks.md
  - benches/parse_modbus.rs
  - benches/parse_enip.rs
  - benches/parse_s7comm.rs
  - benches/parse_dhcp.rs
  - benches/observe_pipeline.rs
  - benches/findings_run.rs
  - Cargo.toml
  - .github/workflows/perf.yml
  - docs/PERF.md
  - tests/memory_bound.rs
input-hash: "[computed at write time]"
traces_to: "NFR-PERF.001,NFR-PERF.002,L-P1-003"
stub_architect_agent: "n/a (facade story — no Rust stubs)"
stub_compile_verified: true
test_writer_agent: "claude-sonnet-4-6"
red_gate_verified: true
---

# Red Gate Log: S-3.01 — Criterion benchmarks + hyperfine CI for perf regression detection

## Summary

| Story  | Tests Written | All Fail (Red)? | Gate |
|--------|---------------|-----------------|------|
| S-3.01 | 1 shell script (16 AC checks across 11 ACs) | Yes — exit 1 | PASSED (correctly red) |

## Stubs Created

None. This is a `tdd_mode: facade` story. Deliverables are bench files,
Cargo.toml sections, workflow YAML, a PCAP fixture, and a baseline doc.
The acceptance check is a shell script asserting structural properties
and the presence of real (non-stub) content.

## Red Gate Verification

### S-3.01

Acceptance script: `scripts/check-s-3-01-acceptance.sh`

| AC | Description | Result |
|----|-------------|--------|
| AC-001a | all 6 bench files exist | PASS |
| AC-001b | cargo bench --no-run exits 0 | PASS |
| AC-001c | all 6 benches in Cargo.toml with harness = false | PASS |
| AC-001d [parse_modbus] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-001d [parse_enip] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-001d [parse_s7comm] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-001d [parse_dhcp] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-001d [observe_pipeline] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-001d [findings_run] | no black_box(0u8) stub marker | FAIL (expected) |
| AC-002a | .github/workflows/perf.yml exists | PASS |
| AC-002b | perf.yml has cron, labeled trigger, and hyperfine on non-comment line | FAIL (expected) |
| AC-002c | tests/fixtures/synthetic-1mb.pcap exists | FAIL (expected) |
| AC-002d | synthetic fixture is not gitignored | FAIL (expected — fixture missing) |
| AC-003 | docs/PERF.md contains regression/threshold/2x | PASS (stub skeleton already contains prose) |
| AC-004 | tests/memory_bound.rs exists with peak < assertion | PASS |
| AC-005 | docs/PERF.md has filled-in baseline timing table | FAIL (expected — stubs only) |

Script exit code: **1** (correctly red).

Note on AC-003: The stub PERF.md already contains a filled-in "Regression
Threshold" section with "2x" and "regression" prose. This AC passes in the
stub state — it represents documentation already supplied by the stub
architect. The discriminating checks are AC-001d (stub marker removal),
AC-002b (hyperfine in a run: step), AC-002c/d (fixture creation), and
AC-005 (filled baseline table).

## Regression Check

| Existing Tests | Status |
|----------------|--------|
| 256 pre-existing tests (cargo test --all-features) | all pass — 0 broken |
| scripts/lint-no-user-paths.sh | exit 0 — 267 files scanned, 0 violations |

## Hand-Off to Implementer

Stories ready for implementation: S-3.01

Implementation guidance:
1. Replace each `black_box(0u8)` stub in all 6 bench files with real
   workloads — parse actual byte slices for protocol benches; run the
   full pipeline for observe_pipeline and findings_run.
2. Create `tests/fixtures/synthetic-1mb.pcap` — a deterministic synthetic
   PCAP (~1MB, 10k packets) and add a `.gitignore` exception so it is
   tracked. The fixture is needed by AC-002c/d and AC-002 CI job.
3. Replace the `cargo bench --no-run` stub in `.github/workflows/perf.yml`
   with a real criterion run + a `hyperfine` end-to-end timing step per
   the AC-002 spec. The `hyperfine` call must appear on a non-comment line.
4. After the first real `cargo bench` run, paste the criterion output table
   and hyperfine summary into `docs/PERF.md`, replacing the `—` stub cells
   with real timing values (AC-005 checks for digit+unit patterns).
5. After each change, re-run `bash scripts/check-s-3-01-acceptance.sh`
   until exit 0.

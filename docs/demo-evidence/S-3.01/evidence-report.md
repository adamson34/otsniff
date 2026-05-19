# Evidence Report: S-3.01

| Field | Value |
|-------|-------|
| Story ID | S-3.01 |
| Title | Criterion benchmarks + hyperfine CI for perf regression detection |
| Worktree HEAD | 450e805e52106dd02055c9de84f49162f68e52cf |
| Date | 2026-05-19 |
| Behavioral Contracts | (none — `behavioral_contracts: []`) |
| Pattern | Facade perf-infra story (no VHS/Playwright recordings; evidence is captured command output) |

## AC Coverage

| AC | Description | Evidence File | Status |
|----|-------------|---------------|--------|
| AC-001 | 6 criterion bench files, real workloads, no stub markers | `AC-001-bench-files.md` | PASS |
| AC-002a | perf.yml CI workflow with cron + label trigger + hyperfine | `AC-002-perf-workflow.md` | PASS |
| AC-002b | synthetic-1mb.pcap committed (not gitignored), generator exists | `AC-002-synthetic-fixture.md` | PASS |
| AC-003 | 2x regression threshold documented in docs/PERF.md, soft alert | `AC-003-regression-threshold.md` | PASS |
| AC-004 | memory_bound test passes (peak heap < 100 MB invariant) | `AC-004-memory-bound.md` | PASS |
| AC-005 | Baseline timing table recorded in docs/PERF.md | `AC-005-baseline-timings.md` | PASS |

## Non-Standard Pattern Note

S-3.01 is a facade perf-infra story. There is no user-facing CLI surface to
record with VHS. Evidence consists of captured output from the acceptance
script (`scripts/check-s-3-01-acceptance.sh`), workflow file headers, file
metadata, test runs, and documentation excerpts. All ACs are satisfied by
the committed artifacts.

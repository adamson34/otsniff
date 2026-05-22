#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-3.01: Criterion benchmarks + hyperfine CI for perf regression detection
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CARGO_TOML="${REPO_ROOT}/Cargo.toml"
PERF_YML="${REPO_ROOT}/.github/workflows/perf.yml"
PERF_MD="${REPO_ROOT}/docs/PERF.md"
FIXTURE="${REPO_ROOT}/tests/fixtures/synthetic-1mb.pcap"
MEMORY_BOUND="${REPO_ROOT}/tests/memory_bound.rs"

BENCH_NAMES=(
  parse_modbus
  parse_enip
  parse_s7comm
  parse_dhcp
  observe_pipeline
  findings_run
)

PASS=0
FAIL=0
SKIP=0

check_pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

check_fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

check_skip() {
  echo "SKIP: $1"
  SKIP=$((SKIP + 1))
}

# ---------------------------------------------------------------------------
# AC-001a — bench files exist
# ---------------------------------------------------------------------------
ac001a_fail=0
for name in "${BENCH_NAMES[@]}"; do
  bench_file="${REPO_ROOT}/benches/${name}.rs"
  if [[ ! -f "${bench_file}" ]]; then
    check_fail "AC-001a: benches/${name}.rs does not exist"
    ac001a_fail=1
  fi
done
if [[ "${ac001a_fail}" -eq 0 ]]; then
  check_pass "AC-001a: all 6 bench files exist (parse_modbus, parse_enip, parse_s7comm, parse_dhcp, observe_pipeline, findings_run)"
fi

# ---------------------------------------------------------------------------
# AC-001b — benches compile (cargo bench --no-run)
# ---------------------------------------------------------------------------
bench_output=$(cd "${REPO_ROOT}" && cargo bench --no-run 2>&1)
bench_exit=$?
if [[ "${bench_exit}" -eq 0 ]]; then
  check_pass "AC-001b: cargo bench --no-run exits 0 — all bench files compile"
else
  check_fail "AC-001b: cargo bench --no-run exited ${bench_exit} — bench compilation failed"
  echo "${bench_output}" | tail -20
fi

# ---------------------------------------------------------------------------
# AC-001c — each bench is in Cargo.toml with harness = false
# ---------------------------------------------------------------------------
if [[ ! -f "${CARGO_TOML}" ]]; then
  check_fail "AC-001c: Cargo.toml does not exist"
else
  ac001c_fail=0
  for name in "${BENCH_NAMES[@]}"; do
    if ! grep -qF "name = \"${name}\"" "${CARGO_TOML}"; then
      check_fail "AC-001c: Cargo.toml missing [[bench]] entry for '${name}'"
      ac001c_fail=1
    fi
  done

  # Count [[bench]] sections that set harness = false
  bench_section_count=$(grep -cF '[[bench]]' "${CARGO_TOML}" || true)
  harness_false_count=$(grep -cF 'harness = false' "${CARGO_TOML}" || true)

  if [[ "${bench_section_count}" -ne "${harness_false_count}" ]]; then
    check_fail "AC-001c: Cargo.toml has ${bench_section_count} [[bench]] section(s) but only ${harness_false_count} with 'harness = false'"
    ac001c_fail=1
  fi

  if [[ "${ac001c_fail}" -eq 0 ]]; then
    check_pass "AC-001c: Cargo.toml has all 6 bench names and each [[bench]] sets harness = false"
  fi
fi

# ---------------------------------------------------------------------------
# AC-001d — benches have NON-STUB workload (no black_box(0u8))
# ---------------------------------------------------------------------------
ac001d_fail=0
for name in "${BENCH_NAMES[@]}"; do
  bench_file="${REPO_ROOT}/benches/${name}.rs"
  if [[ ! -f "${bench_file}" ]]; then
    check_fail "AC-001d [${name}]: file missing — cannot check for stub marker"
    ac001d_fail=1
    continue
  fi
  if grep -qF 'black_box(0u8)' "${bench_file}"; then
    check_fail "AC-001d [${name}]: benches/${name}.rs still contains stub marker 'black_box(0u8)'"
    ac001d_fail=1
  fi
done
if [[ "${ac001d_fail}" -eq 0 ]]; then
  check_pass "AC-001d: all 6 bench files have real workloads (no black_box(0u8) stub marker)"
fi

# ---------------------------------------------------------------------------
# AC-002a — perf.yml workflow exists
# ---------------------------------------------------------------------------
if [[ ! -f "${PERF_YML}" ]]; then
  check_fail "AC-002a: .github/workflows/perf.yml does not exist"
else
  check_pass "AC-002a: .github/workflows/perf.yml exists"
fi

# ---------------------------------------------------------------------------
# AC-002b — perf.yml has cron schedule + labeled trigger + hyperfine
# ---------------------------------------------------------------------------
if [[ ! -f "${PERF_YML}" ]]; then
  check_fail "AC-002b: .github/workflows/perf.yml does not exist — cannot check triggers and hyperfine"
else
  ac002b_fail=0

  if ! grep -qF 'cron:' "${PERF_YML}"; then
    check_fail "AC-002b: perf.yml does not contain 'cron:' schedule trigger"
    ac002b_fail=1
  fi

  if ! grep -qF 'labeled' "${PERF_YML}"; then
    check_fail "AC-002b: perf.yml does not contain 'labeled' pull_request trigger"
    ac002b_fail=1
  fi

  # hyperfine must appear in a run: step line, not just a comment.
  # The stub has hyperfine only in a # comment; the real implementation
  # must invoke it via 'run: ... hyperfine ...' (or a shell step that
  # calls it). We check for 'run:' and 'hyperfine' on the same line, or
  # for 'hyperfine' appearing on a non-comment line in the file.
  if grep -v '^\s*#' "${PERF_YML}" | grep -qF 'hyperfine'; then
    : # passes — hyperfine on a non-comment line
  else
    check_fail "AC-002b: perf.yml contains 'hyperfine' only in comments — implementer must add a real 'run: hyperfine ...' step (stub has only cargo bench --no-run)"
    ac002b_fail=1
  fi

  if [[ "${ac002b_fail}" -eq 0 ]]; then
    check_pass "AC-002b: perf.yml has cron schedule, labeled trigger, and hyperfine"
  fi
fi

# ---------------------------------------------------------------------------
# AC-002c — synthetic fixture exists
# ---------------------------------------------------------------------------
if [[ ! -f "${FIXTURE}" ]]; then
  check_fail "AC-002c: tests/fixtures/synthetic-1mb.pcap does not exist"
else
  check_pass "AC-002c: tests/fixtures/synthetic-1mb.pcap exists"
fi

# ---------------------------------------------------------------------------
# AC-002d — fixture is tracked by git (not ignored)
# ---------------------------------------------------------------------------
if [[ ! -f "${FIXTURE}" ]]; then
  check_fail "AC-002d: tests/fixtures/synthetic-1mb.pcap does not exist — cannot determine git tracking status"
else
  # git check-ignore exits 0 if the file IS ignored (bad), 1 if NOT ignored (good)
  if git -C "${REPO_ROOT}" check-ignore -q "${FIXTURE}" 2>/dev/null; then
    check_fail "AC-002d: tests/fixtures/synthetic-1mb.pcap is in .gitignore — must be tracked (add gitignore exception)"
  else
    check_pass "AC-002d: tests/fixtures/synthetic-1mb.pcap is not ignored by git (tracked)"
  fi
fi

# ---------------------------------------------------------------------------
# AC-003 — regression threshold doc in PERF.md
# ---------------------------------------------------------------------------
if [[ ! -f "${PERF_MD}" ]]; then
  check_fail "AC-003: docs/PERF.md does not exist"
else
  if grep -qF 'regression' "${PERF_MD}" || grep -qF 'threshold' "${PERF_MD}" || grep -qF '2x' "${PERF_MD}" || grep -qF '2×' "${PERF_MD}"; then
    check_pass "AC-003: docs/PERF.md contains regression/threshold/2x documentation"
  else
    check_fail "AC-003: docs/PERF.md does not contain 'regression', 'threshold', or '2x'/'2×' — implementer must fill in threshold documentation"
  fi
fi

# ---------------------------------------------------------------------------
# AC-004 — memory_bound test exists and asserts peak <
# ---------------------------------------------------------------------------
if [[ ! -f "${MEMORY_BOUND}" ]]; then
  check_fail "AC-004: tests/memory_bound.rs does not exist"
else
  if grep -qF 'peak <' "${MEMORY_BOUND}"; then
    check_pass "AC-004: tests/memory_bound.rs exists and contains a 'peak <' assertion"
  else
    check_fail "AC-004: tests/memory_bound.rs exists but does not contain a 'peak <' assertion"
  fi
fi

# ---------------------------------------------------------------------------
# AC-005 — baseline timing recorded in PERF.md
# PERF.md must have a markdown table header (|) AND mention at least one
# bench name — indicating the implementer has filled in the baseline table.
# A skeleton stub with only "—" cells does not satisfy the intent; we require
# that at least one bench name appears alongside non-placeholder content
# (i.e., a cell that is NOT "—" or "Stub").
# ---------------------------------------------------------------------------
if [[ ! -f "${PERF_MD}" ]]; then
  check_fail "AC-005: docs/PERF.md does not exist"
else
  has_table_header=0
  if grep -qF '|' "${PERF_MD}"; then
    has_table_header=1
  fi

  has_bench_name=0
  for name in "${BENCH_NAMES[@]}"; do
    if grep -qF "${name}" "${PERF_MD}"; then
      has_bench_name=1
      break
    fi
  done

  # Check that there is at least one table row with a real timing value
  # (a cell that is not "—", "Stub", or blank — i.e., contains digits)
  has_real_value=0
  if grep -E '^\|.*[0-9]+(\.[0-9]+)?.*(ms|µs|ns|s\b)' "${PERF_MD}" > /dev/null 2>&1; then
    has_real_value=1
  fi

  if [[ "${has_table_header}" -eq 1 && "${has_bench_name}" -eq 1 && "${has_real_value}" -eq 1 ]]; then
    check_pass "AC-005: docs/PERF.md has a markdown table with bench names and real timing values (baseline recorded)"
  else
    details=""
    [[ "${has_table_header}" -eq 0 ]] && details="${details} no-table-header"
    [[ "${has_bench_name}" -eq 0 ]]   && details="${details} no-bench-name"
    [[ "${has_real_value}" -eq 0 ]]   && details="${details} no-real-timing-values (only stubs/dashes)"
    check_fail "AC-005: docs/PERF.md does not yet contain a filled-in baseline timing table —${details}"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo ""
echo "Results: ${PASS}/${TOTAL} checks passed, ${FAIL} failed, ${SKIP} skipped."

if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi

exit 0

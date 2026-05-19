#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-3.05: Wire codecov coverage reporting into CI + add badge
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CI_YML="${REPO_ROOT}/.github/workflows/ci.yml"
CODECOV_YML="${REPO_ROOT}/codecov.yml"
README="${REPO_ROOT}/README.md"

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
# AC-001: coverage job exists in ci.yml with required steps
# Extract lines from the "  coverage:" job key to the next top-level job key.
# Assert the block contains codecov/codecov-action@v4 and cargo-llvm-cov.
# ---------------------------------------------------------------------------
if [[ ! -f "${CI_YML}" ]]; then
  check_fail "AC-001: .github/workflows/ci.yml does not exist"
else
  # Extract the coverage job block (2-space-indented job key)
  coverage_block=$(awk '
    /^  coverage:/{found=1; print; next}
    found && /^  [a-zA-Z][a-zA-Z0-9_-]*:/{exit}
    found{print}
  ' "${CI_YML}")

  if [[ -z "${coverage_block}" ]]; then
    check_fail "AC-001: no 'coverage:' job key found in ci.yml"
  else
    # Check for codecov action
    if echo "${coverage_block}" | grep -q 'codecov/codecov-action@v4'; then
      check_pass "AC-001a: coverage job contains codecov/codecov-action@v4"
    else
      check_fail "AC-001a: coverage job does not contain codecov/codecov-action@v4"
    fi

    # Check for cargo-llvm-cov
    if echo "${coverage_block}" | grep -q 'cargo-llvm-cov'; then
      check_pass "AC-001b: coverage job contains cargo-llvm-cov"
    else
      check_fail "AC-001b: coverage job does not contain cargo-llvm-cov"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# AC-002: no CODECOV_TOKEN secret in the coverage job
# Extract the codecov/codecov-action@v4 step sub-block (lines from the step
# start to the next "- " step at the same indent level or end of coverage
# block). Assert no "token:" appears in those lines.
# ---------------------------------------------------------------------------
if [[ ! -f "${CI_YML}" ]]; then
  check_fail "AC-002: .github/workflows/ci.yml does not exist"
else
  # Extract coverage job block first
  coverage_block=$(awk '
    /^  coverage:/{found=1; print; next}
    found && /^  [a-zA-Z][a-zA-Z0-9_-]*:/{exit}
    found{print}
  ' "${CI_YML}")

  if [[ -z "${coverage_block}" ]]; then
    # No coverage block at all — AC-001 already flags this.
    # AC-002 passes vacuously: there's no token: because there's no step.
    check_pass "AC-002: no coverage job exists — no token: input present (vacuous pass)"
  else
    # Extract the sub-block starting at the codecov action step to the next step
    codecov_step=$(echo "${coverage_block}" | awk '
      /codecov\/codecov-action/{found=1; print; next}
      found && /^      - /{exit}
      found{print}
    ')

    if echo "${codecov_step}" | grep -q 'token:'; then
      check_fail "AC-002: codecov/codecov-action step contains a 'token:' input — should use tokenless OIDC upload"
    else
      check_pass "AC-002: codecov/codecov-action step has no 'token:' input (tokenless upload)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# AC-003: codecov.yml exists with required configuration keys
# ---------------------------------------------------------------------------
if [[ ! -f "${CODECOV_YML}" ]]; then
  check_fail "AC-003: codecov.yml does not exist at repo root"
else
  ac003_fail=0

  for key in "coverage:" "status:" "comment:" "ignore:" "tests/**" "target: 70%"; do
    if grep -qF "${key}" "${CODECOV_YML}"; then
      : # found
    else
      check_fail "AC-003: codecov.yml missing required key/value: '${key}'"
      ac003_fail=1
    fi
  done

  if [[ "${ac003_fail}" -eq 0 ]]; then
    check_pass "AC-003: codecov.yml exists and contains all required keys (coverage:, status:, comment:, ignore:, tests/**, target: 70%)"
  fi
fi

# ---------------------------------------------------------------------------
# AC-004: README has codecov badge
# ---------------------------------------------------------------------------
if [[ ! -f "${README}" ]]; then
  check_fail "AC-004: README.md does not exist"
else
  if grep -q 'codecov.io/gh/adamson34/otsniff' "${README}"; then
    check_pass "AC-004: README.md contains codecov badge URL"
  else
    check_fail "AC-004: README.md does not contain 'codecov.io/gh/adamson34/otsniff'"
  fi
fi

# ---------------------------------------------------------------------------
# AC-005: existing CI job keys are still present (no regression)
# ---------------------------------------------------------------------------
if [[ ! -f "${CI_YML}" ]]; then
  check_fail "AC-005: .github/workflows/ci.yml does not exist"
else
  ac005_fail=0

  for job_key in "fmt:" "clippy:" "test:" "test-macos:" "msrv:" "no-user-paths:" "deny:"; do
    if grep -q "^  ${job_key}" "${CI_YML}"; then
      : # found
    else
      check_fail "AC-005: existing CI job key '${job_key}' not found in ci.yml (regression)"
      ac005_fail=1
    fi
  done

  if [[ "${ac005_fail}" -eq 0 ]]; then
    check_pass "AC-005: all 7 existing CI job keys are present (fmt, clippy, test, test-macos, msrv, no-user-paths, deny)"
  fi
fi

# ---------------------------------------------------------------------------
# AC-006: badge resolves (DEFERRED — requires live network + post-merge)
# ---------------------------------------------------------------------------
check_skip "AC-006: badge URL resolution check deferred — requires live network and post-merge codecov.io registration"

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

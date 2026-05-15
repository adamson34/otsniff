#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-3.06: Stop the recurring macOS rustup-init/cargo flake in CI
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DOC="${REPO_ROOT}/docs/ci-investigations/2026-05-macos-rustup-flake.md"
CI_YML="${REPO_ROOT}/.github/workflows/ci.yml"

PASS=0
FAIL=0

check_pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

check_fail() {
  echo "FAIL: $1"
  FAIL=$((FAIL + 1))
}

# ---------------------------------------------------------------------------
# AC-001-a: Investigation doc exists and contains zero TODO markers
# ---------------------------------------------------------------------------
if [[ ! -f "${DOC}" ]]; then
  check_fail "AC-001-a: docs/ci-investigations/2026-05-macos-rustup-flake.md does not exist"
else
  todo_count=$(grep -c 'TODO' "${DOC}" || true)
  if [[ "${todo_count}" -gt 0 ]]; then
    check_fail "AC-001-a: docs/ci-investigations/2026-05-macos-rustup-flake.md exists but contains ${todo_count} TODO marker(s)"
  else
    check_pass "AC-001-a: docs/ci-investigations/2026-05-macos-rustup-flake.md exists with zero TODO markers"
  fi
fi

# ---------------------------------------------------------------------------
# AC-001-b: Flake occurrences table has at least 3 data rows
# (lines starting with | that are not the header row, separator row, or
#  contain TODO)
# ---------------------------------------------------------------------------
if [[ ! -f "${DOC}" ]]; then
  check_fail "AC-001-b: investigation doc missing — cannot check table rows"
else
  # Count pipe-delimited lines that:
  #  - start with | (table rows)
  #  - do NOT match the separator pattern (|---|...)
  #  - do NOT contain the word TODO
  #  - do NOT contain the header labels (Date / Trigger / Run ID / Runner)
  data_rows=$(grep -E '^\|' "${DOC}" 2>/dev/null \
    | { grep -vE '^\|[-| ]*$' || true; } \
    | { grep -v 'TODO' || true; } \
    | { grep -v -E '^\| *(Date|Trigger|Run ID|Runner)' || true; } \
    | wc -l \
    | tr -d ' ')
  if [[ "${data_rows}" -ge 3 ]]; then
    check_pass "AC-001-b: Flake occurrences table has ${data_rows} non-TODO data row(s) (need >= 3)"
  else
    check_fail "AC-001-b: Flake occurrences table has ${data_rows} non-TODO data row(s) — need at least 3"
  fi
fi

# ---------------------------------------------------------------------------
# AC-001-c: Non-TODO "Root cause hypothesis" and "Chosen fix" sections
# A section is considered non-TODO if the heading is present AND at least
# one line of prose follows that does not contain the word TODO.
# ---------------------------------------------------------------------------
check_section() {
  local label="$1"
  local heading="$2"
  local doc="$3"

  if [[ ! -f "${doc}" ]]; then
    check_fail "${label}: investigation doc missing"
    return
  fi

  # Extract lines from the heading to the next ## heading (exclusive)
  local section_body
  section_body=$(awk "
    /^## ${heading}/{found=1; next}
    found && /^## /{exit}
    found{print}
  " "${doc}")

  if [[ -z "${section_body}" ]]; then
    check_fail "${label}: '## ${heading}' section not found or has no content"
    return
  fi

  # The section must contain zero TODO markers AND at least one non-blank line
  local todo_in_section
  todo_in_section=$(echo "${section_body}" | { grep -c 'TODO' || true; })
  local nonempty_lines
  nonempty_lines=$(echo "${section_body}" | { grep -c '[^[:space:]]' || true; })

  if [[ "${todo_in_section}" -gt 0 ]]; then
    check_fail "${label}: '## ${heading}' section contains TODO placeholder(s) — not yet filled in"
  elif [[ "${nonempty_lines}" -lt 1 ]]; then
    check_fail "${label}: '## ${heading}' section is empty"
  else
    check_pass "${label}: '## ${heading}' section present with non-TODO prose"
  fi
}

check_section "AC-001-c (root cause)" "Root cause hypothesis" "${DOC}"
check_section "AC-001-c (chosen fix)" "Chosen fix" "${DOC}"

# ---------------------------------------------------------------------------
# AC-002: test-macos job no longer contains Swatinem/rust-cache
# Ubuntu / clippy / MSRV jobs MUST still contain it.
# Strategy: extract the test-macos: block (from "test-macos:" to the next
# top-level job name or end of file) and grep within that block only.
# ---------------------------------------------------------------------------
if [[ ! -f "${CI_YML}" ]]; then
  check_fail "AC-002: .github/workflows/ci.yml does not exist"
else
  # Extract the test-macos job block.
  # Jobs in ci.yml are indented with 2 spaces under "jobs:".
  # We match "  test-macos:" and collect until the next 2-space-indented
  # job key (pattern: "  word-chars:") or end of file.
  macos_block=$(awk '
    /^  test-macos:/{found=1; print; next}
    found && /^  [a-zA-Z][a-zA-Z0-9_-]*:/{exit}
    found{print}
  ' "${CI_YML}")

  if [[ -z "${macos_block}" ]]; then
    check_fail "AC-002: could not locate test-macos: job block in ci.yml"
  else
    if echo "${macos_block}" | grep -q 'Swatinem/rust-cache'; then
      check_fail "AC-002: test-macos job still contains Swatinem/rust-cache (must be removed)"
    else
      # Verify that other jobs (test/clippy/msrv) still have it
      # Count Swatinem/rust-cache occurrences outside the test-macos block
      other_jobs_have_cache=$(awk '
        /^  test-macos:/{skip=1; next}
        skip && /^  [a-zA-Z][a-zA-Z0-9_-]*:/{skip=0}
        !skip{print}
      ' "${CI_YML}" \
        | { grep 'Swatinem/rust-cache' || true; } \
        | wc -l \
        | tr -d ' ')
      if [[ "${other_jobs_have_cache}" -ge 1 ]]; then
        check_pass "AC-002: test-macos job does not contain Swatinem/rust-cache; other jobs retain it"
      else
        check_fail "AC-002: test-macos job lacks Swatinem/rust-cache (good) but other jobs also lack it (bad — they must retain it)"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# AC-003: Non-TODO "Rollback plan" section in the investigation doc
# ---------------------------------------------------------------------------
check_section "AC-003" "Rollback plan" "${DOC}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo ""
echo "Results: ${PASS}/${TOTAL} checks passed, ${FAIL} failed."

if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi

exit 0

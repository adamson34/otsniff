#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-4.03: Kani proof — ensure_no_map_values substring invariant.
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LEAK_RS="${REPO_ROOT}/crates/otsniff-privacy/src/leak_detector.rs"
KANI_YML="${REPO_ROOT}/.github/workflows/kani.yml"
PROOF_MD="${REPO_ROOT}/docs/proofs/ensure-no-map-values.md"

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
# AC-001a — #[kani::proof] fn map_value_substring exists in leak_detector.rs
# ---------------------------------------------------------------------------
if grep -qF 'fn map_value_substring' "${LEAK_RS}"; then
  check_pass "AC-001a: #[kani::proof] fn map_value_substring declared in src/ai/leak_detector.rs"
else
  check_fail "AC-001a: fn map_value_substring NOT found in src/ai/leak_detector.rs"
fi

# ---------------------------------------------------------------------------
# AC-001b — map_value_substring body is NOT todo!()
# Extract from 'fn map_value_substring' to the next bare '}' at column 0.
# ---------------------------------------------------------------------------
fn_body=$(awk '/fn map_value_substring/,/^\}/' "${LEAK_RS}" || true)
if echo "${fn_body}" | grep -qF 'todo!()'; then
  check_fail "AC-001b: map_value_substring body still contains todo!() — implementer must fill in"
else
  check_pass "AC-001b: map_value_substring body does not contain todo!() (real implementation present)"
fi

# ---------------------------------------------------------------------------
# AC-001c — ensure_no_map_values is called inside the #[cfg(kani)] block
# on a non-comment line.
# Extract from the first '#[cfg(kani)]' to the first bare '^}' at column 0,
# then strip comment lines before searching for the call.
# ---------------------------------------------------------------------------
kani_block=$(awk '/#\[cfg\(kani\)\]/,/^\}/' "${LEAK_RS}" || true)
kani_code_only=$(echo "${kani_block}" | grep -v '^\s*//' || true)

if echo "${kani_code_only}" | grep -qF 'ensure_no_map_values'; then
  check_pass "AC-001c: ensure_no_map_values called on a non-comment line inside #[cfg(kani)] block"
else
  check_fail "AC-001c: ensure_no_map_values NOT called on a non-comment line inside #[cfg(kani)] block — harness must exercise the function"
fi

# ---------------------------------------------------------------------------
# AC-001d — kani.yml invokes 'cargo kani --harness map_value_substring'
# on a non-comment line (YAML comment lines start with '#').
# ---------------------------------------------------------------------------
if [[ ! -f "${KANI_YML}" ]]; then
  check_fail "AC-001d: .github/workflows/kani.yml does not exist — cannot check harness invocation"
else
  if grep -v '^\s*#' "${KANI_YML}" | grep -qE 'cargo kani( -p [A-Za-z0-9_-]+)? --harness map_value_substring\b'; then
    check_pass "AC-001d: kani.yml invokes 'cargo kani --harness map_value_substring' (optionally with -p <crate>) on a non-comment line"
  else
    check_fail "AC-001d: kani.yml does NOT invoke 'cargo kani --harness map_value_substring' on a non-comment line"
  fi
fi

# ---------------------------------------------------------------------------
# AC-002 — docs/proofs/ensure-no-map-values.md has no TODO markers AND
# contains "bidirectional" or "iff" (the invariant nature must be stated).
# ---------------------------------------------------------------------------
if [[ ! -f "${PROOF_MD}" ]]; then
  check_fail "AC-002: docs/proofs/ensure-no-map-values.md does not exist"
else
  todo_count=$(grep -c 'TODO' "${PROOF_MD}" || true)
  if [[ "${todo_count}" -eq 0 ]]; then
    check_pass "AC-002 (no-TODO): docs/proofs/ensure-no-map-values.md contains 0 TODO markers"
  else
    check_fail "AC-002 (no-TODO): docs/proofs/ensure-no-map-values.md still contains ${todo_count} TODO marker(s) — documentation is skeleton"
  fi

  if grep -qF 'bidirectional' "${PROOF_MD}" || grep -qF 'iff' "${PROOF_MD}"; then
    check_pass "AC-002 (invariant-stated): docs/proofs/ensure-no-map-values.md states 'bidirectional' or 'iff' invariant"
  else
    check_fail "AC-002 (invariant-stated): docs/proofs/ensure-no-map-values.md does not contain 'bidirectional' or 'iff' — invariant nature must be stated"
  fi
fi

# ---------------------------------------------------------------------------
# AC-003 — Bounds documented in ensure-no-map-values.md.
# Must contain at least one of: "≤ 32", "N = ", "K = ", "bounds"
# ---------------------------------------------------------------------------
if [[ ! -f "${PROOF_MD}" ]]; then
  check_fail "AC-003: docs/proofs/ensure-no-map-values.md does not exist — cannot check bounds"
else
  has_bounds=0
  for marker in '≤ 32' 'N = ' 'K = ' 'bounds'; do
    if grep -qF "${marker}" "${PROOF_MD}"; then
      has_bounds=1
      break
    fi
  done
  if [[ "${has_bounds}" -eq 1 ]]; then
    check_pass "AC-003: docs/proofs/ensure-no-map-values.md documents proof bounds (≤ 32 / N = / K = / bounds)"
  else
    check_fail "AC-003: docs/proofs/ensure-no-map-values.md does not document proof bounds — must contain '≤ 32', 'N = ', 'K = ', or 'bounds'"
  fi
fi

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

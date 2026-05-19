#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-4.01: Kani proof — unscrub(scrub(x, map), map) == x
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCRUB_RS="${REPO_ROOT}/src/scrub.rs"
KANI_YML="${REPO_ROOT}/.github/workflows/kani.yml"
PROOF_MD="${REPO_ROOT}/docs/proofs/scrub-roundtrip.md"

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
# AC-001a — Kani harness exists in code (BC-5.01.003)
# ---------------------------------------------------------------------------
if grep -qF '#[kani::proof]' "${SCRUB_RS}"; then
  check_pass "AC-001a: src/scrub.rs contains #[kani::proof] attribute"
else
  check_fail "AC-001a: src/scrub.rs does not contain #[kani::proof] — harness missing"
fi

# ---------------------------------------------------------------------------
# AC-001b — Harness has real body, not todo!()
# Extract the #[kani::proof] function body and check for todo!().
# While stub has todo!(), this check inverts: presence of todo!() = FAIL.
# ---------------------------------------------------------------------------
# Extract from #[kani::proof] to the closing } of the function (first top-level })
if awk '/#\[kani::proof\]/,/^}/' "${SCRUB_RS}" | grep -qF 'todo!()'; then
  check_fail "AC-001b: Kani proof body still contains todo!() — implementer must replace with real symbolic proof"
else
  check_pass "AC-001b: Kani proof body does not contain todo!() (real implementation present)"
fi

# ---------------------------------------------------------------------------
# AC-001c — Harness exercises round-trip property
# Heuristic: within the #[cfg(kani)] mod kani_proofs { ... } block,
# both scrub_text and unscrub_text must appear.
# ---------------------------------------------------------------------------
# Extract the #[cfg(kani)] block: from '#[cfg(kani)]' to a line that is
# just '}' at the start (closes the mod block).
kani_block=$(awk '/#\[cfg\(kani\)\]/,/^\}/' "${SCRUB_RS}" || true)
has_scrub=0
has_unscrub=0
if echo "${kani_block}" | grep -qF 'scrub_text'; then
  has_scrub=1
fi
if echo "${kani_block}" | grep -qF 'unscrub_text'; then
  has_unscrub=1
fi
if [[ "${has_scrub}" -eq 1 && "${has_unscrub}" -eq 1 ]]; then
  check_pass "AC-001c: #[cfg(kani)] block calls both scrub_text and unscrub_text (round-trip exercised)"
else
  details=""
  [[ "${has_scrub}" -eq 0 ]]   && details="${details} missing:scrub_text"
  [[ "${has_unscrub}" -eq 0 ]] && details="${details} missing:unscrub_text"
  check_fail "AC-001c: #[cfg(kani)] block does not exercise the round-trip —${details}"
fi

# ---------------------------------------------------------------------------
# AC-002a — Kani workflow exists
# ---------------------------------------------------------------------------
if [[ -f "${KANI_YML}" ]]; then
  check_pass "AC-002a: .github/workflows/kani.yml exists"
else
  check_fail "AC-002a: .github/workflows/kani.yml does not exist"
fi

# ---------------------------------------------------------------------------
# AC-002b — Workflow has real Kani invocation (not stub echo "TODO")
# Require 'cargo kani --harness' on a non-comment line.
# ---------------------------------------------------------------------------
if [[ ! -f "${KANI_YML}" ]]; then
  check_fail "AC-002b: .github/workflows/kani.yml does not exist — cannot check for real invocation"
else
  if grep -v '^\s*#' "${KANI_YML}" | grep -qF 'cargo kani --harness'; then
    check_pass "AC-002b: kani.yml contains 'cargo kani --harness' on a non-comment line"
  else
    check_fail "AC-002b: kani.yml does not contain 'cargo kani --harness' on a non-comment line — stub uses echo \"TODO\""
  fi
fi

# ---------------------------------------------------------------------------
# AC-002c — Workflow has weekly schedule
# ---------------------------------------------------------------------------
if [[ ! -f "${KANI_YML}" ]]; then
  check_fail "AC-002c: .github/workflows/kani.yml does not exist — cannot check for cron schedule"
else
  if grep -qF 'cron:' "${KANI_YML}"; then
    check_pass "AC-002c: kani.yml contains a cron: schedule (weekly)"
  else
    check_fail "AC-002c: kani.yml does not contain 'cron:' — weekly schedule missing"
  fi
fi

# ---------------------------------------------------------------------------
# AC-003a — Documentation exists
# ---------------------------------------------------------------------------
if [[ -f "${PROOF_MD}" ]]; then
  check_pass "AC-003a: docs/proofs/scrub-roundtrip.md exists"
else
  check_fail "AC-003a: docs/proofs/scrub-roundtrip.md does not exist"
fi

# ---------------------------------------------------------------------------
# AC-003b — Documentation is filled in (not skeleton)
# The stub table has rows like "| N | 32 | TODO |" — rationale is "TODO".
# Require: (a) "N = " AND "K = " appear (bounds are documented), AND
#          (b) no bounds table row contains "| TODO |" (rationale filled in).
# The skeleton fails (b) because both N and K rows have "| TODO |" as rationale.
# ---------------------------------------------------------------------------
if [[ ! -f "${PROOF_MD}" ]]; then
  check_fail "AC-003b: docs/proofs/scrub-roundtrip.md does not exist — cannot check bounds documentation"
else
  has_n=0
  has_k=0
  has_todo_in_bounds=0

  # Check for "N = " in the document
  if grep -qF 'N = ' "${PROOF_MD}"; then
    has_n=1
  fi
  # Check for "K = " in the document
  if grep -qF 'K = ' "${PROOF_MD}"; then
    has_k=1
  fi
  # Check if any bounds-table row still has "TODO" as the rationale entry
  # (pattern: a table row with a pipe-delimited TODO cell)
  if grep -E '^\|.*\|[[:space:]]*TODO[[:space:]]*\|' "${PROOF_MD}" > /dev/null 2>&1; then
    has_todo_in_bounds=1
  fi

  if [[ "${has_n}" -eq 1 && "${has_k}" -eq 1 && "${has_todo_in_bounds}" -eq 0 ]]; then
    check_pass "AC-003b: docs/proofs/scrub-roundtrip.md documents N = and K = bounds with filled-in rationale"
  else
    details=""
    [[ "${has_n}" -eq 0 ]]            && details="${details} missing:'N = '"
    [[ "${has_k}" -eq 0 ]]            && details="${details} missing:'K = '"
    [[ "${has_todo_in_bounds}" -eq 1 ]] && details="${details} bounds-table-has-TODO-rationale(skeleton)"
    check_fail "AC-003b: docs/proofs/scrub-roundtrip.md bounds documentation is incomplete or skeleton —${details}"
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

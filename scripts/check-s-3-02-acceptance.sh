#!/usr/bin/env bash
#
# scripts/check-s-3-02-acceptance.sh
#
# Structural acceptance checks for S-3.02 (prompt-eval harness).
# Prints PASS:/FAIL: per AC label; exits 0 if all pass, 1 if any fail.
#
# Usage: bash scripts/check-s-3-02-acceptance.sh

set -euo pipefail

EVALS_DIR="tests/prompt-evals"
EVAL_VARIANTS=(span host-side tap ambiguous)
PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# ---------------------------------------------------------------------------
# AC-001a — all 4 eval directories exist
# ---------------------------------------------------------------------------
all_dirs=1
for variant in "${EVAL_VARIANTS[@]}"; do
  dir="${EVALS_DIR}/${variant}"
  if [[ ! -d "$dir" ]]; then
    all_dirs=0
    echo "  missing directory: $dir"
  fi
done

if [[ "$all_dirs" -eq 1 ]]; then
  pass "AC-001a: all 4 eval directories exist (span, host-side, tap, ambiguous)"
else
  fail "AC-001a: one or more eval directories missing"
fi

# ---------------------------------------------------------------------------
# AC-001b — each eval directory contains observations.json, rubric.md, run.sh
# ---------------------------------------------------------------------------
all_files=1
for variant in "${EVAL_VARIANTS[@]}"; do
  dir="${EVALS_DIR}/${variant}"
  for required_file in observations.json rubric.md run.sh; do
    if [[ ! -f "${dir}/${required_file}" ]]; then
      all_files=0
      echo "  missing: ${dir}/${required_file}"
    fi
  done
done

if [[ "$all_files" -eq 1 ]]; then
  pass "AC-001b: each eval directory contains observations.json, rubric.md, run.sh"
else
  fail "AC-001b: one or more required eval files (observations.json, rubric.md, run.sh) missing"
fi

# ---------------------------------------------------------------------------
# AC-002a — run_all.sh contains real logic (not just exit 0 stub)
#   Heuristic: >20 lines OR contains a 'claude' invocation on a non-comment line
# ---------------------------------------------------------------------------
runner="${EVALS_DIR}/run_all.sh"
if [[ ! -f "$runner" ]]; then
  fail "AC-002a: tests/prompt-evals/run_all.sh does not exist"
else
  line_count=$(wc -l < "$runner")
  # grep -F "claude" on non-comment lines only (strip leading whitespace before #)
  if [[ "$line_count" -gt 20 ]] || grep -vE '^\s*#' "$runner" | grep -qF "claude"; then
    pass "AC-002a: run_all.sh contains real logic (lines=${line_count})"
  else
    fail "AC-002a: run_all.sh appears to be a stub (lines=${line_count}, no real 'claude' invocation)"
  fi
fi

# ---------------------------------------------------------------------------
# AC-002b — leak detector wired into runner
#   Heuristic: run_all.sh mentions "leak" on a non-comment line
# ---------------------------------------------------------------------------
if [[ ! -f "$runner" ]]; then
  fail "AC-002b: run_all.sh does not exist (cannot check leak-detector wiring)"
elif grep -vE '^\s*#' "$runner" | grep -qF "leak"; then
  pass "AC-002b: leak detector wired into run_all.sh"
else
  fail "AC-002b: run_all.sh does not reference leak detector on a non-comment line"
fi

# ---------------------------------------------------------------------------
# AC-003 — README.md contains non-flake documentation
#   Expected substrings: "90%" or "MUST" or "three runs"
# ---------------------------------------------------------------------------
readme="${EVALS_DIR}/README.md"
if [[ ! -f "$readme" ]]; then
  fail "AC-003: tests/prompt-evals/README.md does not exist"
elif grep -qF "90%" "$readme" || grep -qF "MUST" "$readme" || grep -qF "three runs" "$readme"; then
  pass "AC-003: README.md contains non-flake threshold documentation"
else
  fail "AC-003: README.md missing expected content ('90%', 'MUST', or 'three runs')"
fi

# ---------------------------------------------------------------------------
# AC-004 — .github/workflows/prompt-evals.yml exists AND has workflow_dispatch:
#          AND contains real logic (not stub echo)
#   Heuristic: >20 lines OR contains 'claude'
# ---------------------------------------------------------------------------
workflow=".github/workflows/prompt-evals.yml"
if [[ ! -f "$workflow" ]]; then
  fail "AC-004: .github/workflows/prompt-evals.yml does not exist"
elif ! grep -qF "workflow_dispatch:" "$workflow"; then
  fail "AC-004: prompt-evals.yml exists but has no workflow_dispatch: trigger"
else
  wf_lines=$(wc -l < "$workflow")
  if [[ "$wf_lines" -gt 20 ]] || grep -qF "claude" "$workflow"; then
    pass "AC-004: prompt-evals.yml has workflow_dispatch: and real logic (lines=${wf_lines})"
  else
    fail "AC-004: prompt-evals.yml has workflow_dispatch: but looks like a stub (lines=${wf_lines}, no 'claude' invocation)"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0

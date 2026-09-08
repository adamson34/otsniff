#!/usr/bin/env bash
set -euo pipefail

# Acceptance check for S-4.02: Kani proof — leak detector regex matches
# every IPv4/IPv6/MAC-shaped substring.
# Red Gate script — must FAIL before implementation, PASS after.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LEAK_RS="${REPO_ROOT}/crates/otsniff-privacy/src/leak_detector.rs"
KANI_YML="${REPO_ROOT}/.github/workflows/kani.yml"
PROOF_MD="${REPO_ROOT}/docs/proofs/leak-detector-regex.md"

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
# AC-001a — kani_proofs module exists in leak_detector.rs
# ---------------------------------------------------------------------------
if grep -qF '#[cfg(kani)]' "${LEAK_RS}"; then
  check_pass "AC-001a: src/ai/leak_detector.rs contains #[cfg(kani)] gate"
else
  check_fail "AC-001a: src/ai/leak_detector.rs does not contain #[cfg(kani)] — kani_proofs module missing"
fi

# ---------------------------------------------------------------------------
# AC-001b — three harnesses declared (each must appear as #[kani::proof] fn)
# ---------------------------------------------------------------------------
for harness in leak_regex_ipv4 leak_regex_ipv6 leak_regex_mac; do
  # We need #[kani::proof] and fn <harness> to both exist; a simple two-pass
  # check: look for the fn declaration inside the file (the #[kani::proof]
  # attribute appears on the preceding line in the stub).
  if grep -qF "fn ${harness}" "${LEAK_RS}"; then
    check_pass "AC-001b: harness '${harness}' declared in src/ai/leak_detector.rs"
  else
    check_fail "AC-001b: harness '${harness}' NOT declared in src/ai/leak_detector.rs"
  fi
done

# ---------------------------------------------------------------------------
# Extract the #[cfg(kani)] block once for the body checks below.
# awk from the first '#[cfg(kani)]' line to the first bare '^}' at column 0.
# ---------------------------------------------------------------------------
kani_block=$(awk '/#\[cfg\(kani\)\]/,/^\}/' "${LEAK_RS}" || true)

# ---------------------------------------------------------------------------
# AC-001c — IPv4 harness body filled in (must NOT contain todo!())
# ---------------------------------------------------------------------------
# Extract from 'fn leak_regex_ipv4' to the next bare '}' at column 0.
ipv4_body=$(awk '/fn leak_regex_ipv4/,/^\}/' "${LEAK_RS}" || true)
if echo "${ipv4_body}" | grep -qF 'todo!()'; then
  check_fail "AC-001c: leak_regex_ipv4 body still contains todo!() — implementer must fill in"
else
  check_pass "AC-001c: leak_regex_ipv4 body does not contain todo!() (real implementation present)"
fi

# ---------------------------------------------------------------------------
# AC-001d — IPv6 harness body filled in
# ---------------------------------------------------------------------------
ipv6_body=$(awk '/fn leak_regex_ipv6/,/^\}/' "${LEAK_RS}" || true)
if echo "${ipv6_body}" | grep -qF 'todo!()'; then
  check_fail "AC-001d: leak_regex_ipv6 body still contains todo!() — implementer must fill in"
else
  check_pass "AC-001d: leak_regex_ipv6 body does not contain todo!() (real implementation present)"
fi

# ---------------------------------------------------------------------------
# AC-001e — MAC harness body filled in
# ---------------------------------------------------------------------------
mac_body=$(awk '/fn leak_regex_mac/,/^\}/' "${LEAK_RS}" || true)
if echo "${mac_body}" | grep -qF 'todo!()'; then
  check_fail "AC-001e: leak_regex_mac body still contains todo!() — implementer must fill in"
else
  check_pass "AC-001e: leak_regex_mac body does not contain todo!() (real implementation present)"
fi

# ---------------------------------------------------------------------------
# AC-001f — Harness exercises the leak detector entry point
# Look for a call to scan(), ensure_clean(), or detect_leaks() on a
# non-comment, non-doc-comment line inside the #[cfg(kani)] block.
# Doc comments (///) mention `scan()` in backticks; strip those so we only
# match actual call-sites.
# ---------------------------------------------------------------------------
has_detector_call=0
# Strip lines that are purely doc-comment or line-comment lines before searching.
kani_code_only=$(echo "${kani_block}" | grep -v '^\s*//' || true)
for fn_name in 'scan(' 'ensure_clean(' 'detect_leaks('; do
  if echo "${kani_code_only}" | grep -qF "${fn_name}"; then
    has_detector_call=1
    break
  fi
done
if [[ "${has_detector_call}" -eq 1 ]]; then
  check_pass "AC-001f: #[cfg(kani)] block calls a leak-detector entry point on a non-comment line (scan/ensure_clean/detect_leaks)"
else
  check_fail "AC-001f: #[cfg(kani)] block does not call scan(), ensure_clean(), or detect_leaks() on a non-comment line — harness must exercise the detector"
fi

# ---------------------------------------------------------------------------
# AC-002a — Workflow contains all three cargo kani --harness invocations
# on non-comment lines.
# ---------------------------------------------------------------------------
if [[ ! -f "${KANI_YML}" ]]; then
  check_fail "AC-002a: .github/workflows/kani.yml does not exist — cannot check harness invocations"
else
  for harness in leak_regex_ipv4 leak_regex_ipv6 leak_regex_mac; do
    if grep -v '^\s*#' "${KANI_YML}" | grep -qE "cargo kani( -p [A-Za-z0-9_-]+)? --harness ${harness}\b"; then
      check_pass "AC-002a: kani.yml invokes 'cargo kani --harness ${harness}' (optionally with -p <crate>) on a non-comment line"
    else
      check_fail "AC-002a: kani.yml does NOT invoke 'cargo kani --harness ${harness}' on a non-comment line"
    fi
  done
fi

# ---------------------------------------------------------------------------
# AC-003 — Documentation is filled in (skeleton has multiple TODO markers)
# Heuristic: count occurrences of "TODO" in the file; must be 0.
# The stub has at least 5 TODO markers — a fully-implemented doc has 0.
# ---------------------------------------------------------------------------
if [[ ! -f "${PROOF_MD}" ]]; then
  check_fail "AC-003: docs/proofs/leak-detector-regex.md does not exist"
else
  todo_count=$(grep -c 'TODO' "${PROOF_MD}" || true)
  if [[ "${todo_count}" -eq 0 ]]; then
    check_pass "AC-003: docs/proofs/leak-detector-regex.md contains 0 TODO markers (fully filled in)"
  else
    check_fail "AC-003: docs/proofs/leak-detector-regex.md still contains ${todo_count} TODO marker(s) — documentation is skeleton"
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

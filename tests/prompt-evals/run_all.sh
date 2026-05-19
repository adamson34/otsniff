#!/usr/bin/env bash
#
# tests/prompt-evals/run_all.sh
#
# Prompt evaluation runner for otsniff.
#
# Usage:
#   bash tests/prompt-evals/run_all.sh              # run all evals
#   bash tests/prompt-evals/run_all.sh <name>       # run one eval by directory name
#   bash tests/prompt-evals/run_all.sh --dry-run    # parse rubrics only; no claude calls
#
# Exit codes:
#   0  — all evals passed (or dry-run completed without parse errors)
#   1  — one or more evals failed
#   2  — claude CLI not installed (EC-001)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVALS_BASE="$SCRIPT_DIR"

DRY_RUN=0
EVAL_FILTER=""

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --*) echo "Unknown flag: $arg" >&2; exit 1 ;;
        *)   EVAL_FILTER="$arg" ;;
    esac
done

# ---------------------------------------------------------------------------
# EC-001: check claude CLI is installed (skip check in dry-run mode)
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" -eq 0 ]] && ! command -v claude >/dev/null 2>&1; then
    echo "ERROR: claude CLI is not installed." >&2
    echo "  Install with: npm install -g @anthropic-ai/claude-code" >&2
    echo "  Or use --dry-run to validate rubric files without calling claude." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Discover eval directories
# ---------------------------------------------------------------------------
if [[ -n "$EVAL_FILTER" ]]; then
    eval_dirs=("$EVALS_BASE/$EVAL_FILTER")
    if [[ ! -d "${eval_dirs[0]}" ]]; then
        echo "ERROR: eval directory not found: ${eval_dirs[0]}" >&2
        exit 1
    fi
else
    mapfile -t eval_dirs < <(find "$EVALS_BASE" -mindepth 1 -maxdepth 1 -type d | sort)
fi

total=0
passed=0
failed=0

# ---------------------------------------------------------------------------
# Leak detector helper: scan text for real IP/MAC patterns (EC-002)
# ---------------------------------------------------------------------------
leak_check() {
    local text="$1"
    local name="$2"
    # IPv4 pattern
    if echo "$text" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}'; then
        echo "FAIL [$name]: leak detector tripped — response contains IPv4 address" >&2
        return 1
    fi
    # MAC address pattern
    if echo "$text" | grep -qE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'; then
        echo "FAIL [$name]: leak detector tripped — response contains MAC address" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Rubric scorer: check MUST assertions against response text
# ---------------------------------------------------------------------------
score_rubric() {
    local rubric_file="$1"
    local response="$2"
    local name="$3"

    local must_total=0
    local must_met=0
    local must_not_total=0
    local must_not_violated=0
    local should_total=0
    local should_met=0

    while IFS= read -r line; do
        # Skip blank lines and comments
        trimmed="${line#"${line%%[! ]*}"}"  # ltrim
        [[ -z "$trimmed" || "${trimmed:0:1}" == "#" ]] && continue

        # Strip leading number and dot: "1. MUST ..." -> "MUST ..."
        rest="${trimmed#*. }"
        if [[ "$rest" == "$trimmed" ]]; then
            # No ". " found — malformed line; skip
            continue
        fi

        if [[ "$rest" == MUST\ NOT\ * ]]; then
            pattern="${rest#MUST NOT }"
            must_not_total=$((must_not_total + 1))
            # MUST NOT: pattern should NOT appear in response
            if echo "$response" | grep -qi "$pattern"; then
                must_not_violated=$((must_not_violated + 1))
                echo "  MUST NOT violated [$name]: $pattern" >&2
            fi
        elif [[ "$rest" == MUST\ * ]]; then
            pattern="${rest#MUST }"
            must_total=$((must_total + 1))
            if echo "$response" | grep -qi "$pattern"; then
                must_met=$((must_met + 1))
            else
                echo "  MUST not met [$name]: $pattern" >&2
            fi
        elif [[ "$rest" == SHOULD\ * ]]; then
            pattern="${rest#SHOULD }"
            should_total=$((should_total + 1))
            if echo "$response" | grep -qi "$pattern"; then
                should_met=$((should_met + 1))
            fi
        fi
    done < "$rubric_file"

    # Compute pass: all MUST met (>=90% threshold) + no MUST NOT violated
    local total_must=$((must_total + must_not_total))
    local total_met=$((must_met))
    local total_violated=$((must_not_violated))

    if [[ "$total_must" -eq 0 ]]; then
        echo "  WARN [$name]: rubric has no MUST or MUST NOT assertions" >&2
        return 0
    fi

    # 90% threshold: (must_met * 100 / must_total) >= 90 AND must_not_violated == 0
    local pct=0
    if [[ "$must_total" -gt 0 ]]; then
        pct=$(( must_met * 100 / must_total ))
    else
        pct=100
    fi

    if [[ "$pct" -ge 90 && "$total_violated" -eq 0 ]]; then
        echo "  MUST: ${must_met}/${must_total} (${pct}%), MUST NOT: ${must_not_violated} violations, SHOULD: ${should_met}/${should_total}"
        return 0
    else
        echo "  MUST: ${must_met}/${must_total} (${pct}%), MUST NOT violations: ${must_not_violated}, SHOULD: ${should_met}/${should_total}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Main eval loop
# ---------------------------------------------------------------------------
for eval_dir in "${eval_dirs[@]}"; do
    name="$(basename "$eval_dir")"
    obs_file="$eval_dir/observations.json"
    rubric_file="$eval_dir/rubric.md"

    total=$((total + 1))

    # Validate required files exist
    if [[ ! -f "$obs_file" ]]; then
        echo "FAIL [$name]: observations.json missing"
        failed=$((failed + 1))
        continue
    fi
    if [[ ! -f "$rubric_file" ]]; then
        echo "FAIL [$name]: rubric.md missing"
        failed=$((failed + 1))
        continue
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        # Dry-run: just validate rubric parses (non-empty, has assertions)
        assertion_count=0
        while IFS= read -r line; do
            trimmed="${line#"${line%%[! ]*}"}"
            [[ -z "$trimmed" || "${trimmed:0:1}" == "#" ]] && continue
            rest="${trimmed#*. }"
            [[ "$rest" == "$trimmed" ]] && continue
            if [[ "$rest" == MUST\ NOT\ * || "$rest" == MUST\ * || "$rest" == SHOULD\ * ]]; then
                assertion_count=$((assertion_count + 1))
            fi
        done < "$rubric_file"

        if [[ "$assertion_count" -gt 0 ]]; then
            echo "PASS [$name]: rubric parsed ok ($assertion_count assertions, dry-run)"
            passed=$((passed + 1))
        else
            echo "FAIL [$name]: rubric.md contains no recognized assertions"
            failed=$((failed + 1))
        fi
        continue
    fi

    # Invoke claude CLI with the scrubbed observations as stdin
    # System prompt: analyze this scrubbed otsniff report and produce a prioritized triage.
    response=$(claude -p "$(cat <<'PROMPT'
You are an OT security analyst. Analyze the following scrubbed otsniff network observation report
and produce a concise prioritized triage. Focus on:
1. Critical findings (engineering commands, plaintext credentials, internet egress from OT subnets)
2. Asset inventory summary
3. Topology observations appropriate to the capture source type
4. Recommended follow-up actions

Note: All IP addresses and hostnames have been replaced with pseudonyms (e.g., host_001).
Do not attempt to reverse the pseudonyms. Only use the pseudonym labels in your response.
PROMPT
)" < "$obs_file" 2>&1) || true

    # EC-002: run leak detector on response
    if ! leak_check "$response" "$name"; then
        echo "FAIL [$name]: leak detector tripped on claude response"
        failed=$((failed + 1))
        continue
    fi

    # Score response against rubric
    if score_rubric "$rubric_file" "$response" "$name"; then
        echo "PASS [$name]"
        passed=$((passed + 1))
    else
        echo "FAIL [$name]: rubric assertions not met (see above)"
        failed=$((failed + 1))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${passed} passed, ${failed} failed of ${total}"

[[ "$failed" -eq 0 ]] && exit 0 || exit 1

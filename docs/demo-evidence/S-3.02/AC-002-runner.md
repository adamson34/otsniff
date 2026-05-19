# AC-002 Runner — Evidence

## head -40 tests/prompt-evals/run_all.sh

```bash
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
```

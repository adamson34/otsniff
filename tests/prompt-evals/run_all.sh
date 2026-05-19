#!/usr/bin/env bash
set -euo pipefail

# TODO: implementer wires this in step 3.
# Expected behavior:
#   - Accept optional --dry-run flag (no actual claude CLI calls).
#   - Iterate over each eval subdirectory (span, host-side, tap, ambiguous).
#   - For each eval: invoke claude CLI with observations.json + system prompt.
#   - Capture response and run leak-detector invariant check.
#   - Score response against rubric.md using pattern matching.
#   - Print pass/fail per eval and overall summary.
#   - Exit 0 on all pass; exit 1 on any fail.

exit 0

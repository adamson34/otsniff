#!/usr/bin/env bash
#
# scripts/lint-no-user-paths.sh
#
# Enforces .factory/policies.yaml POL-12 (no_user_paths_in_committed_artifacts).
#
# Scans tracked files for absolute paths under /Users/<u>/ or /home/<u>/
# that would leak a contributor's local home directory into the public
# repo. Fails the build with exit 1 on any hit.
#
# Origin: 2026-05-12 history rewrite after S-1.04 + S-5.04 demo recordings
# baked the path /Users/<u>/.../otsniff/.worktrees/... into VHS tape
# scripts and the rendered gif/webm output.
#
# Usage:
#   scripts/lint-no-user-paths.sh           # scan all tracked files
#   scripts/lint-no-user-paths.sh <files>   # scan a specific list (pre-commit hook)
#
# CI invocation: see .github/workflows/ci.yml job `no-user-paths`.

set -euo pipefail

# Pattern: absolute paths to a user-named home dir.
# Matches /Users/<name>/ and /home/<name>/ where <name> has no slash.
PATTERN='(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/)'

# Files explicitly allowed to mention the pattern (this script, the CI
# workflow that runs it, contributor docs that show the syntax). Keep
# this list small and intentional.
ALLOWLIST=(
  "scripts/lint-no-user-paths.sh"
  ".github/workflows/ci.yml"
  "CONTRIBUTING.md"
)

# Build the file list. If args given, scan only those; otherwise scan
# all tracked files in the repo.
if [[ $# -gt 0 ]]; then
  FILES=("$@")
else
  mapfile -d '' -t FILES < <(git ls-files -z)
fi

violations=()
for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then continue; fi
  mime=$(file --mime-encoding -b "$f" 2>/dev/null || echo binary)
  if [[ "$mime" == "binary" ]]; then continue; fi

  skip=0
  for a in "${ALLOWLIST[@]}"; do
    if [[ "$f" == "$a" ]]; then skip=1; break; fi
  done
  if [[ "$skip" == 1 ]]; then continue; fi

  if hits=$(grep -nE "$PATTERN" "$f" 2>/dev/null); then
    while IFS= read -r line; do
      violations+=("$f:$line")
    done <<< "$hits"
  fi
done

if [[ ${#violations[@]} -gt 0 ]]; then
  echo "POL-12 violation: absolute user paths found in committed files." >&2
  echo "These leak the local home directory. Use repo-relative paths or" >&2
  echo "environment variables (e.g., \$PWD, \$HOME) instead." >&2
  echo >&2
  for v in "${violations[@]}"; do
    echo "  $v" >&2
  done
  echo >&2
  echo "Check failed: ${#violations[@]} violation(s) across ${#FILES[@]} files scanned." >&2
  exit 1
fi

# POL-11 (positive-coverage assertion): emit a runtime-computed
# success line on green.
echo "Check passed: ${#FILES[@]} files scanned, 0 user-path violations."
exit 0

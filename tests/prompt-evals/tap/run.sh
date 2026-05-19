#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash tests/prompt-evals/run_all.sh "$(basename "$(dirname "$(realpath "$0")")")"

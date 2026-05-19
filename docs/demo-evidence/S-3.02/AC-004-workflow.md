# AC-004 CI Workflow — Evidence

## cat .github/workflows/prompt-evals.yml

```yaml
name: Prompt Evals (opt-in)
# AC-004: opt-in only — not run in PR CI (cost + flake risk).
# Trigger manually from the Actions tab after merging to develop.

on:
  workflow_dispatch:

jobs:
  evals:
    name: Run prompt evals
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Check claude CLI availability
        id: claude_check
        run: |
          if command -v claude >/dev/null 2>&1; then
            echo "available=true" >> "$GITHUB_OUTPUT"
            echo "claude CLI found: $(claude --version 2>&1 | head -1)"
          else
            echo "available=false" >> "$GITHUB_OUTPUT"
            echo "claude CLI not installed — running in dry-run mode (EC-001)"
          fi

      - name: Run prompt evals (live, claude CLI present)
        if: steps.claude_check.outputs.available == 'true'
        run: bash tests/prompt-evals/run_all.sh

      - name: Run prompt evals (dry-run, no claude CLI)
        if: steps.claude_check.outputs.available != 'true'
        run: |
          echo "No claude CLI available; validating rubric files in dry-run mode."
          bash tests/prompt-evals/run_all.sh --dry-run

      - name: Cargo test — prompt_evals unit tests
        run: cargo test --test prompt_evals
```

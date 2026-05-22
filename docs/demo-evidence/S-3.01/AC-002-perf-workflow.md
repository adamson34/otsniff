# AC-002: Perf CI workflow

## `.github/workflows/perf.yml` (first 30 lines)

```yaml
name: Perf

on:
  schedule:
    - cron: "0 12 * * 0"  # Sunday noon UTC
  pull_request:
    types: [labeled]

jobs:
  bench:
    name: Benchmarks
    if: ${{ github.event_name == 'schedule' || (github.event_name == 'pull_request' && contains(github.event.label.name, 'perf')) }}
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable

      - uses: Swatinem/rust-cache@v2

      - name: Install hyperfine
        run: sudo apt-get install -y hyperfine

      - name: Build release binary
        run: cargo build --release

      - name: Run hyperfine end-to-end
        run: |
```

Workflow triggers on weekly cron (Sunday noon UTC) and on PRs labeled `perf`.
Hyperfine step runs the end-to-end binary against `tests/fixtures/synthetic-1mb.pcap`.

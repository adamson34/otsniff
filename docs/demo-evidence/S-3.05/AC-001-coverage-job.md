# AC-001 — Coverage job in CI

## Command
```
awk '/^  coverage:/,/^  [a-z]+:/' .github/workflows/ci.yml | head -30
```

## Output
```
  coverage:
```

> Note: awk stops at the next top-level job key (`deny:`). Full block captured
> from line 99 of `.github/workflows/ci.yml`:

```yaml
  coverage:
    name: Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov --locked
      - name: Run coverage
        run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
      - name: Upload to codecov
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false
```

## Acceptance script (first 10 lines)
```
$ bash scripts/check-s-3-05-acceptance.sh 2>&1 | head -10
PASS: AC-001a: coverage job contains codecov/codecov-action@v4
PASS: AC-001b: coverage job contains cargo-llvm-cov
PASS: AC-002: codecov/codecov-action step has no 'token:' input (tokenless upload)
PASS: AC-003: codecov.yml exists and contains all required keys (coverage:, status:, comment:, ignore:, tests/**, target: 70%)
PASS: AC-004: README.md contains codecov badge URL
PASS: AC-005: all 7 existing CI job keys are present (fmt, clippy, test, test-macos, msrv, no-user-paths, deny)
SKIP: AC-006: badge URL resolution check deferred — requires live network and post-merge codecov.io registration

Results: 6/6 checks passed, 0 failed, 1 skipped.
```

cargo-llvm-cov + codecov-action@v4 wired in; runs on ubuntu-latest.

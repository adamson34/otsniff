# AC-002: CI Workflow

**Command:** `cat .github/workflows/kani.yml`

```yaml
name: Kani
on:
  schedule:
    - cron: '0 6 * * 0'  # Sunday 06:00 UTC
  workflow_dispatch:

jobs:
  proofs:
    name: Kani proofs
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install kani
        run: cargo install --locked kani-verifier
      - name: Setup kani
        run: cargo kani setup
      - name: Run scrub round-trip proof
        run: cargo kani --harness scrub_roundtrip_bounded
        timeout-minutes: 30
```

**Status:** PASS — file exists, contains `cargo kani --harness` on a non-comment line, contains `cron:` schedule (weekly, Sunday 06:00 UTC), and supports `workflow_dispatch` for manual triggering.

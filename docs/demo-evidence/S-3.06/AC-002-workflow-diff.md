# AC-002 Evidence (Pre-Merge): Swatinem/rust-cache Removed from test-macos Job

**Acceptance criterion:** `Swatinem/rust-cache@v2` step removed from the macOS test
job only; the Linux clippy, test, and msrv jobs retain their cache steps unchanged.

---

## Command: `git diff 89168bd..HEAD -- .github/workflows/ci.yml`

```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index a71a576..2658ecc 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -70,7 +70,9 @@ jobs:
           echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
           echo "Resolved cargo: $(which cargo || true)"
           cargo --version
-      - uses: Swatinem/rust-cache@v2
+      # Cache step omitted per S-3.06 option (b''): the rust-cache action's
+      # restore on macOS replaces ~/.cargo/bin/* with rustup-init bytes.
+      # Trade-off: +90s cold compile; eliminates the cache-corruption vector.
       - run: cargo test --all-features
 
   msrv:
```

**Result: exactly one `Swatinem/rust-cache@v2` line removed, from the `test-macos` job only. PASS.**

---

## Command: `grep -n "Swatinem" .github/workflows/ci.yml`

```
30:      - uses: Swatinem/rust-cache@v2
39:      - uses: Swatinem/rust-cache@v2
89:      - uses: Swatinem/rust-cache@v2
```

**Expected: 3 lines remaining, none in the test-macos block.**

Cross-referencing against the workflow structure: lines 30 and 39 fall in the Linux
`test` and `clippy` jobs respectively; line 89 falls in the `msrv` job. None of these
line numbers are inside the `test-macos` block (which spans approximately lines 61–78
in the current file). PASS.

---

## Command: `awk '/^  test-macos:/,/^  msrv:/' .github/workflows/ci.yml`

```yaml
  test-macos:
    name: Test (macos-14)
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - name: Force rustup-managed cargo to front of PATH
        run: |
          echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
          echo "Resolved cargo: $(which cargo || true)"
          cargo --version
      # Cache step omitted per S-3.06 option (b''): the rust-cache action's
      # restore on macOS replaces ~/.cargo/bin/* with rustup-init bytes.
      # Trade-off: +90s cold compile; eliminates the cache-corruption vector.
      - run: cargo test --all-features

  msrv:
```

**Result: no `Swatinem` reference inside the `test-macos` block. PASS.**

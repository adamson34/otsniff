# AC-003 Evidence: Rollback Plan Documented

**Acceptance criterion:** The investigation note documents how to roll back the chosen
fix and identifies the next fallback option.

---

## Command: `grep -A 20 "^## Rollback plan" docs/ci-investigations/2026-05-macos-rustup-flake.md`

```
## Rollback plan

If this fix introduces a different macOS regression, revert it with a single commit:

```
git revert <SHA-of-feat(S-3.06)-commit>
```

After reverting, the preferred next attempt is option (c) from AC-002: replace
`dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2` with
`actions-rust-lang/setup-rust-toolchain@v1`, which manages its own caching strategy
and reportedly avoids this failure mode. Option (c) replaces both toolchain install and
caching in a single action swap, making regression attribution harder than option (b''),
which is why it was held as the fallback rather than the first choice.
```

**Result: Rollback plan section present. Documents:**
- Single-commit revert path: `git revert <SHA>`. PASS.
- Next fallback option identified: option (c) — `actions-rust-lang/setup-rust-toolchain@v1`. PASS.
- Rationale for why option (c) was held as fallback rather than first choice. PASS.

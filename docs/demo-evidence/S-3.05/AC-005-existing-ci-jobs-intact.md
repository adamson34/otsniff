# AC-005 — Existing CI jobs intact

## Command
```
grep -E "^  [a-z-]+:" .github/workflows/ci.yml
```

## Output
```
  push:
  fmt:
  clippy:
  test:
  test-macos:
  msrv:
  no-user-paths:
  coverage:
  deny:
```

> `push:` is part of the `on:` trigger block, not a job key. The 7 pre-existing
> job keys are: fmt, clippy, test, test-macos, msrv, no-user-paths, deny.

7 pre-existing jobs untouched; coverage is purely additive.

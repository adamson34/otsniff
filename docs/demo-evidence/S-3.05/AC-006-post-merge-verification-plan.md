# AC-006 — Post-merge verification plan (deferred)

AC-006 requires manual verification after the PR merges to develop.

## Steps

1. User signs the repo into codecov.io via GitHub OAuth (one-time setup on
   codecov.io's dashboard — required before the first CI run uploads data).

2. After merge, the GitHub Actions `coverage` job runs automatically on the
   develop branch push trigger. It uploads `lcov.info` to codecov.io via
   the `codecov/codecov-action@v4` step.

3. Subsequent PR runs will report coverage deltas against the develop baseline.

## Verification command

```bash
curl -sI https://codecov.io/gh/adamson34/otsniff/graph/badge.svg | head -3
```

Expected: `HTTP/2 200` (not 404 or redirect to an "unknown" placeholder).
A 200 response with a real percentage confirms the first upload succeeded.

## Placeholder

Initial coverage % after first successful upload: **TBD** (record here after merge).

## Status

DEFERRED — cannot be verified pre-merge; requires live codecov.io registration
and at least one completed CI run on develop after PR merge.

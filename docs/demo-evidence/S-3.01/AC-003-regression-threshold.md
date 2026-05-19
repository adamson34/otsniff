# AC-003: Regression threshold

## Relevant section from `docs/PERF.md`

```
## Regression Threshold

Alert (soft, non-blocking) fires when criterion reports a measured median
more than **2x** the baseline for any individual bench. The threshold is
configurable per benchmark — see AC-003 in
`S-3.01-criterion-benchmarks.md`.

The perf.yml CI workflow emits a `::warning::` annotation (visible in
GitHub Actions) but does **not** fail the build when a regression is
detected. This avoids noisy CI failures from cloud runner variance while
still surfacing slowdowns for human review.

To record a new baseline after an intentional optimization:
```

Threshold is 2× the baseline median (soft alert, non-blocking build). Configurable
per benchmark. Alerts via GitHub Actions `::warning::` annotation without failing CI.

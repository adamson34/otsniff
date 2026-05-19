# BC-8.01.005 Registration

## BC-INDEX.md grep

```
6:total_bcs: 98  # all numbered BCs across S.0..S.9 — ... S-5.07 added BC-8.01.005
135:- BC-8.01.005 Finding cards in HTML report wrap in `<details open class="finding sev-...">` with `<summary>` containing severity badge + title; default browser triangle suppressed via `details.finding > summary::-webkit-details-marker { display: none }` + `▾`/`▸` chevron via `::before` using `var(--muted)`; default state is open (`open` attribute); nested `<details>` for evidence/criteria/playbook unaffected; `@media print` forces all finding cards expanded with `details.finding > *:not(summary) { display: block !important }` (HIGH, added S-5.07 v0.4.0)
```

## Factory git log (`.factory` worktree, last 3 commits)

```
a74d846 factory(phase-3): register BC-8.01.005 (S-5.07)
f850cc1 factory(phase-3): S-5.07 Red Gate log (PASSED red-state)
a14706f factory(phase-3): S-5.07 promoted draft→ready
```

`total_bcs` went 97 → 98 with BC-8.01.005 registration.

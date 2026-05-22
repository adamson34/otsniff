# BC-5.03.001 Registration

## BC-INDEX entry

```
6:total_bcs: 99  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006; S-2.11 added BC-1.02.009 and BC-3.03.006; S-5.01 added BC-9.04.001; S-5.02 added BC-6.04.001; S-5.07 added BC-8.01.005; S-6.01 added BC-5.03.001
114:- BC-5.03.001 `merge_map(baseline, &obs)` preserves baseline pseudonyms for known real values; assigns fresh pseudonyms to new real values continuing from `baseline.max_index + 1` per family (host_/mac_/name_ independent); preserves baseline-only entries (EC-003); stamps `created_at` to merge time; `ScrubMap::validate()` rejects empty-string pseudonym keys or empty real values (EC-001); round-trip exact via scrub/unscrub; leak detector passes after merge (HIGH, added S-6.01 v0.4.0)
```

Command: `grep -n "BC-5.03.001" .factory/specs/behavioral-contracts/BC-INDEX.md`

## Factory log

```
b4586f1 factory(phase-3): register BC-5.03.001 (S-6.01)
eb050f7 factory(phase-3): S-6.01 Red Gate log (PASSED red-state)
ba1de7d factory(phase-3): S-6.01 promoted draft->ready
```

Command: `git -C .factory log --oneline -3`

## Note

`total_bcs` went 98 -> 99 when BC-5.03.001 was registered by the factory during
the S-6.01 red-gate phase. The BC captures the full merge contract including the
EC-001 validation requirement and the EC-003 baseline-only-preserved guarantee.

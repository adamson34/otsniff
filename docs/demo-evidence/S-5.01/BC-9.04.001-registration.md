# BC-9.04.001 Registration

## BC-INDEX entry

```
$ grep -n "BC-9.04.001" .factory/specs/behavioral-contracts/BC-INDEX.md
6:total_bcs: 96  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006; S-2.11 added BC-1.02.009 and BC-3.03.006; S-5.01 added BC-9.04.001
142:- BC-9.04.001 Verbose-mode (-v) parse loop emits periodic progress to stderr every >= 100,000 packets OR >= 10 MB read; rate-limited to one emission per 2 seconds via injectable Clock trait; final summary always emitted via finish() (HIGH, added S-5.01 v0.4.0)
```

## Factory git log

```
$ git -C .factory log --oneline -3
053edef factory(phase-3): register BC-9.04.001 (S-5.01)
2dbb7d5 factory(phase-3): S-5.01 Red Gate log (PASSED red-state)
91d056b factory(phase-3): S-5.01 promoted draft->ready
```

## total_bcs delta

`total_bcs` went from 95 to 96 when S-5.01 registered BC-9.04.001.

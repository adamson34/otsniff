# BC-6.04.001 Registration

## BC-INDEX.md Entry

```
grep -n "BC-6.04.001" .factory/specs/behavioral-contracts/BC-INDEX.md
```

```
6:total_bcs: 97  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006; S-2.11 added BC-1.02.009 and BC-3.03.006; S-5.01 added BC-9.04.001; S-5.02 added BC-6.04.001
122:- BC-6.04.001 `ClaudeCliProvider::analyze` emits stderr heartbeat `[Ns] claude still working...` every 3 seconds of wall-clock time while the subprocess is alive; on completion emits `done in N.Ns, B bytes response`; both lines suppressed when `verbose=false` AND stderr is not a TTY; heartbeat interval is exactly 3 s via injected `Clock` trait so tests can control time without sleeping (HIGH, added S-5.02 v0.4.0)
```

## .factory log

```
git -C .factory log --oneline -3
```

```
60b79c8 factory(phase-3): register BC-6.04.001 (S-5.02)
d60beed factory(phase-3): S-5.02 Red Gate log (PASSED red-state)
bcdf331 factory(phase-3): S-5.02 promoted draft->ready
```

## Note

`total_bcs` went 96 → 97 with S-5.02 registering BC-6.04.001.

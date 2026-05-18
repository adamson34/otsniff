# BC-INDEX Registration

## BC-INDEX.md grep output

```
6:total_bcs: 89  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004
53:- BC-1.03.006 NTLMSSP NEGOTIATE recognized in TCP payloads on ports 445/139/80/443/8080/135; signature scan via `windows(8)` then full recognizer validates MessageType=1 and flags; classified V1 if NTLM bit (0x00000200) set and NTLM2_KEY (0x00080000) unset, V2 if NTLM2_KEY set; emits NtlmEvent (HIGH, added S-2.06 v0.4.0)
81:- BC-3.04.004 `compat.ntlmv1` fires at High for NTLMv1 events; not for V2 (EC-001); rolls up by `(src, dst)` pair; evidence capped at 5 samples per finding (HIGH, added S-2.06 v0.4.0)
```

Command: `grep -nE "BC-(1.03.006|3.04.004)" .factory/specs/behavioral-contracts/BC-INDEX.md`

## .factory git log

```
0c5bcd6 factory(phase-3): register BC-1.03.006 + BC-3.04.004 (S-2.06)
df40937 factory(phase-3): S-2.06 Red Gate log (PASSED red-state)
2cf455a factory(phase-3): S-2.06 promoted draft→ready
```

Command: `git -C .factory log --oneline -3`

## Note

`total_bcs` incremented from 87 to 89 when S-2.06 added BC-1.03.006
(NTLM recognizer) and BC-3.04.004 (`compat.ntlmv1` detector).

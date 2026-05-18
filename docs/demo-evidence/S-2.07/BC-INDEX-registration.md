# BC-INDEX Registration

## Matching entries in BC-INDEX.md

```
$ grep -nE "BC-(1.04.003|3.04.005)" .factory/specs/behavioral-contracts/BC-INDEX.md
6:total_bcs: 91  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005
57:- BC-1.04.003 TLS ClientHello cipher_suites captured by observer; bounds-checked variable-offset walk (session_id_len at payload[43], cs_offset = 44 + session_id_len); appended across multiple ClientHellos on the same (src, dst, dst_port) flow (HIGH, added S-2.07 v0.4.0)
83:- BC-3.04.005 `compat.weak_tls_cipher` fires at Medium when any of (0x0001, 0x0002, 0x0004, 0x0005, 0x0009, 0x000A) appears in cipher_suites; GREASE values skipped (EC-001); fires alongside compat.stale_tls (AC-003 sibling-not-exclusive); rolls up by (src, dst) (HIGH, added S-2.07 v0.4.0)
```

## Factory repo log

```
$ git -C .factory log --oneline -3
4a0150c factory(phase-3): register BC-1.04.003 + BC-3.04.005 (S-2.07)
8b19f57 factory(phase-3): S-2.07 Red Gate log (PASSED red-state)
71708cc factory(phase-3): S-2.07 promoted draft->ready
```

## Note

`total_bcs` went 89 → 91 with S-2.07 registering BC-1.04.003 and BC-3.04.005.

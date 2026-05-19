# BC-INDEX Registration

## BC-INDEX Entries

```
$ grep -nE "BC-(1.04.004|3.04.006)" .factory/specs/behavioral-contracts/BC-INDEX.md

6:total_bcs: 93  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006
58:- BC-1.04.004 RDP X.224 Connection Confirm recognized on tcp/3389 with TPKT header + PDU type 0xD0 + optional RDP_NEG_RSP at offset 11; selectedProtocol read as little-endian u32 at offset 15; bounds-checked; TPKT length must match payload length (HIGH, added S-2.08 v0.4.0)
85:- BC-3.04.006 `creds.rdp_no_nla` fires at Critical when RdpEvent.selected_protocol == 0x00000000 (PROTOCOL_RDP, exact equality — secure variants PROTOCOL_SSL/HYBRID/HYBRID_EX do not fire); rolls up by (src, dst) pair (HIGH, added S-2.08 v0.4.0)
```

## Factory Git Log

```
$ git -C .factory log --oneline -3

ad7a5a2 factory(phase-3): register BC-1.04.004 + BC-3.04.006 (S-2.08)
48f81e8 factory(phase-3): S-2.08 Red Gate log (PASSED red-state)
00cae5c factory(phase-3): S-2.08 promoted draft→ready
```

## Note

`total_bcs` advanced from 91 to 93 when S-2.08 registered BC-1.04.004 and
BC-3.04.006 (previous pair BC-1.04.003 + BC-3.04.005 were added by S-2.07).

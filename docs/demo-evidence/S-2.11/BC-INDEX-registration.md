# BC-INDEX Registration — BC-1.02.009 + BC-3.03.006

## BC-INDEX Entries

```
$ grep -nE "BC-(1.02.009|3.03.006)" .factory/specs/behavioral-contracts/BC-INDEX.md

6:total_bcs: 95  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005; S-2.06 added BC-1.03.006 and BC-3.04.004; S-2.07 added BC-1.04.003 and BC-3.04.005; S-2.08 added BC-1.04.004 and BC-3.04.006; S-2.11 added BC-1.02.009 and BC-3.03.006
48:- BC-1.02.009 Modbus per-(src, dst) unit-id aggregation: observer accumulates pdu.unit_id into modbus_flow_summary keyed by (src, dst); BTreeSet dedupes within flow; unit IDs 0 (broadcast) and 0xFF (gateway) are counted (HIGH, added S-2.11 v0.4.0)
81:- BC-3.03.006 `ics.modbus_unit_id_sweep` fires at Medium when modbus_flow_summary[src,dst].unit_ids.len() >= 5; escalates to High at >= 50; evidence lists count + first 10 unit IDs sorted ascending (HIGH, added S-2.11 v0.4.0)
```

## Factory Git Log

```
$ git -C .factory log --oneline -5

c650b15 factory(phase-3): move BC-1.02.009 to correct section in BC-INDEX
54d547d factory(phase-3): register BC-1.02.009 + BC-3.03.006 (S-2.11)
9f3edaa factory(phase-3): S-2.11 Red Gate log (PASSED red-state)
6505d65 factory(phase-3): S-2.11 promoted draft→ready (fix BC-1.02.006→1.02.009 collision)
26b0ad1 factory(phase-3): S-2.08 delivered (#71, 387b239)
```

## Note

`total_bcs` advanced from 93 to 95 with the registration of BC-1.02.009 and BC-3.03.006.
Two factory commits were required: the initial registration commit (`54d547d`) and a
follow-up ordering-fix commit (`c650b15`) to place BC-1.02.009 in the correct
section of the BC-INDEX.

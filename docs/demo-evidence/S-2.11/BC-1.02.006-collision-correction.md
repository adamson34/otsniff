# BC-1.02.006 Collision Correction — Rename to BC-1.02.009

## Summary

Story S-2.11 originally declared `BC-1.02.006` for the Modbus per-`(src, dst)`
unit-id aggregation contract. Pre-flight review discovered that ID was already
assigned to the DHCP option-walk behavioral contract introduced by S-1.05
(as part of the BC-AUDIT-005 fold into the numbered space).

The contract was renamed to `BC-1.02.009` — the next free identifier in the
BC-1.02 series. No semantic change was made to the contract itself. The companion
detector contract `BC-3.03.006` was unaffected (that ID was free). The story
body carries a spec-correction note at the top of the frontmatter.

The story-writer landed the rename pre-flight; no implementation work referenced
`BC-1.02.006` for S-2.11's feature.

## Confirmation — BC-INDEX entries

```
$ grep -nE "BC-(1\.02\.009|3\.03\.006)" .factory/specs/behavioral-contracts/BC-INDEX.md

6:total_bcs: 95  # ... S-2.11 added BC-1.02.009 and BC-3.03.006
48:- BC-1.02.009 Modbus per-(src, dst) unit-id aggregation: observer accumulates pdu.unit_id into
    modbus_flow_summary keyed by (src, dst); BTreeSet dedupes within flow; unit IDs 0 (broadcast)
    and 0xFF (gateway) are counted (HIGH, added S-2.11 v0.4.0)
81:- BC-3.03.006 `ics.modbus_unit_id_sweep` fires at Medium when modbus_flow_summary[src,dst].unit_ids.len()
    >= 5; escalates to High at >= 50; evidence lists count + first 10 unit IDs sorted ascending
    (HIGH, added S-2.11 v0.4.0)
```

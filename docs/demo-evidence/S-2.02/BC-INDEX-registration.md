# BC-INDEX Registration — BC-1.03.007

**Story:** S-2.02  
**Evidence:** BC-1.03.007 is registered in the factory BC-INDEX.

---

## Factory git log search

Command:

```
git -C /Users/lukeadamson/1898/otsniff/.factory log --oneline -5 | grep -i "BC-1.03.007"
```

Output:

```
daced54 factory(phase-3): register BC-1.03.007 (S-2.02)
```

---

## BC-INDEX grep

Command:

```
grep -n "BC-1.03.007" /Users/lukeadamson/1898/otsniff/.factory/specs/behavioral-contracts/BC-INDEX.md
```

Output:

```
6:total_bcs: 85  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007
52:- BC-1.03.007 `cred_events` deduplicated at observation time by `(src, dst, dst_port, kind)`; duplicate increments `count: u32` (saturating); entry not appended (HIGH, added S-2.02 v0.4.0)
```

BC-1.03.007 appears on line 52 in BC-INDEX.md (entry) and is also referenced in the
`total_bcs` header comment (line 6), confirming it was added as part of S-2.02 v0.4.0.

# BC-INDEX Registration

## BC-INDEX grep

```
6:total_bcs: 87  # all numbered BCs across S.0..S.9 — S-1.05 folded the 15 BC-AUDIT-* contracts into the numbered space (alias table preserved for legacy refs); S-2.02 added BC-1.03.007; S-2.05 added BC-1.03.005 and BC-3.01.005
52:- BC-1.03.005 LDAP simple-bind observation: BER-encoded BindRequest on tcp/389 or tcp/3268 with version 3 and SimpleAuthentication choice (tag 0x80); `anonymous: bool` set when DN + password are both empty (EC-003); STARTTLS state tracked per flow by observer (HIGH, added S-2.05 v0.4.0)
69:- BC-3.01.005 `creds.ldap_simple_bind` fires at Critical for plaintext LDAP bind; suppressed by prior STARTTLS on the same flow (`used_starttls == true`) or anonymous bind (`anonymous == true`); rolls up by `(src, dst)` pair (HIGH, added S-2.05 v0.4.0)
```

Command: `grep -nE "BC-(1\.03\.005|3\.01\.005)" .factory/specs/behavioral-contracts/BC-INDEX.md`

## .factory git log (recent 3 commits)

```
03226af factory(phase-3): register BC-1.03.005 + BC-3.01.005 (S-2.05)
6bb1505 factory(phase-3): S-2.05 Red Gate log refresh (green-by-design stub)
36249ed factory(phase-3): S-2.05 Red Gate log (PASSED red-state)
```

Command: `git -C .factory log --oneline -3`

## total_bcs increment

The `total_bcs` counter moved from 85 to 87 as part of the S-2.05 registration
commit (`03226af`). The two new contracts are:

- **BC-1.03.005** — observation-layer contract for LDAP simple-bind (subsystem S.1)
- **BC-3.01.005** — finding-layer contract for `creds.ldap_simple_bind` (subsystem S.3)

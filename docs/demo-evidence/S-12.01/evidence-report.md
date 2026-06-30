# S-12.01 Demo Evidence Report

Story: MITRE ATT&CK for ICS technique mapping (P1-6)
Branch: `feature/S-12.01-mitre-ics-mapping`
Recorded: 2026-06-30

## Summary

One VHS recording shows per-finding MITRE technique surfacing (markdown + JSON)
and the completed catalog coverage. It uses the committed
`tests/fixtures/synthetic-1mb.pcap` (no new fixture). POL-12 compliant.

---

## AC Coverage

### AC-002 / AC-003 / AC-004 (BC-8.05.001) — per-finding MITRE surfacing

**Demo:** `AC-001-004-mitre-mapping` (first half)

`otsniff analyze tests/fixtures/synthetic-1mb.pcap --md r.md --json r.json` fires
`ics.modbus_writes`. The markdown finding shows:

```
**MITRE ATT&CK for ICS.** [T0836 — Modify Parameter](https://attack.mitre.org/techniques/T0836/), [T0855 — Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/)
```

and the JSON carries the same per finding:

```
$ jq -c '.findings[].mitre_techniques' r.json
[{"label":"T0836 — Modify Parameter","url":"https://attack.mitre.org/techniques/T0836/"},{"label":"T0855 — Unauthorized Command Message","url":"https://attack.mitre.org/techniques/T0855/"}]
```

The HTML report renders the same techniques as `<a href="https://attack.mitre.org/techniques/T0XXX/">` links in the finding card (verified by the `report_html` snapshot).

### AC-001 (BC-3.06.006) — completed catalog coverage

**Demo:** `AC-001-004-mitre-mapping` (second half)

`otsniff rules | grep MITRE | sort -u` shows every detection rule now carries a
MITRE ATT&CK for ICS technique — including the **7 newly-mapped** rules:

| Rule(s) | Technique |
|---|---|
| plaintext creds (ftp/telnet/http_basic/snmp), LDAP simple-bind | T0859 — Valid Accounts |
| SMBv1 | T0866 — Exploitation of Remote Services (supporting) |
| stale TLS, weak TLS cipher | T0830 — Adversary-in-the-Middle (supporting) |
| DNS to non-OT resolver, NTP external | T0884 — Connection Proxy (supporting) |

The 3 policy-gated `zonewarden.*` conformance verdicts are MITRE-exempt (IEC
62443 controls, not adversary techniques — ADR-0014). All four distinct
technique IDs (T0859/T0866/T0830/T0884) were WebFetch-verified against
attack.mitre.org during implementation.

---

## Notes

MITRE technique labels/URLs are static catalog data (constant English, no asset
identifiers) — the privacy invariant (`invariant_no_real_values_reach_ai_provider`)
holds even though the MITRE line now enters the scrubbed AI-bound markdown.

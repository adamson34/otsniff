# Red-Gate Log — S-12.01 (MITRE ATT&CK for ICS technique mapping)

Branch: `feature/S-12.01-mitre-ics-mapping`
TDD mode: strict.

Commit ordering (verified `git log develop..HEAD`):

| Order | Commit | Kind |
|---|---|---|
| 1 | `0b33229` | **test**(findings): MITRE catalog coverage (AC-001) |
| 2 | `6745e19` | feat(findings): map 7 detection rules to MITRE (AC-001) |
| 3 | `51864ce` | **test**(report): per-finding MITRE surfacing HTML/MD/JSON (AC-002/003/004) |
| 4 | `8012a45` | feat(report): surface per-finding MITRE HTML/MD/JSON (AC-002..005) |
| 5 | `8846dfa` | docs(adr): 0014 — MITRE mapping lives in the catalog (AC-006) |

## MITRE URL verification (WebFetch, by the implementer; all real ICS techniques)

- T0859 → "Valid Accounts" (Persistence / Lateral Movement)
- T0866 → "Exploitation of Remote Services" (Initial Access / Lateral Movement)
- T0830 → "Adversary-in-the-Middle" (Collection)
- T0884 → "Connection Proxy" (Command and Control)

## Red gate

**Coverage test (at `0b33229`, before mapping data):**
```
rule creds.ftp has no MITRE ATT&CK for ICS reference (AC-001)
test result: FAILED. 0 passed; 1 failed
```

**Rendering assertions (at `51864ce`, before render code):**
```
html_report_snapshot ... FAILED — HTML finding card must render the MITRE ATT&CK for ICS technique link
scrubbed_markdown ... FAILED — MD MITRE line assert
findings_json ... FAILED — missing mitre_techniques
rule_catalog_matches_committed_rules_md ... FAILED — docs/RULES.md is stale
```

## Green (post-implementation, independently re-verified by orchestrator)

- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets --workspace -- -D warnings` → clean
- `cargo test --workspace` → 669 passed, 0 failed — incl. `every_rule_has_a_well_formed_mitre_reference`, `rule_catalog_matches_committed_rules_md`, and `invariant_no_real_values_reach_ai_provider` (MITRE strings are constant English, no leak)
- Snapshots: only finding-MITRE (report_html, scrubbed_markdown, findings_json + the capture-warning variants) + `docs/RULES.md`; no inventory/comms/summary churn. No `Cargo.toml` / `.factory` change. ADR-0014 created.
- Live check: `analyze synthetic-1mb.pcap` → `ics.modbus_writes` surfaces T0836 + T0855 in JSON `mitre_techniques` and the MD `**MITRE ATT&CK for ICS.**` line with attack.mitre.org links.

## Accepted scope judgment (implementer)

The coverage test exempts the 3 policy-gated `zonewarden.*` rules: they are IEC
62443 segmentation-conformance verdicts, not adversary-behaviour detections —
ATT&CK for ICS models adversary techniques (segmentation is a mitigation, M0930,
not a technique). Recorded in the test, ADR-0014, BC-3.06.006, and the story.

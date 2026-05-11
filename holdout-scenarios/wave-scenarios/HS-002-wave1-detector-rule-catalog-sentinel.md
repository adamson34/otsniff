---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-05-11T20:50:00Z
phase: 2
inputs: [stories/, behavioral-contracts/, prd.md]
traces_to: ""
id: "HS-002"
category: "integration-boundaries"
must_pass: "true"
priority: "must-pass"
wave: 1
epic_id: "E-2"
behavioral_contracts: ["BC-3.06.002"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-002: Every new Wave-1 detector appears in the catalog and fires once

> **NOT FOR IMPLEMENTERS.**

## Scenario

1. **Precondition:** post-Wave-1 build.
2. **Action:** Run `otsniff rules --format json`. Then run
   `otsniff analyze <fixture-with-all-rules-firing>.pcap -o out.html --json out.json`.
3. **Expected:**
   - Every new finding ID introduced in Wave 1 (creds.ldap_simple_bind,
     compat.ntlmv1, compat.weak_tls_cipher, creds.rdp_no_nla,
     boundary.ntp_external, recon.port_scan, ics.modbus_unit_id_sweep,
     ics.dnp3_engineering) appears in the JSON catalog output.
   - All eight new finding IDs fire exactly once against the fixture.
   - Each fired finding carries non-empty `playbook` per BC-3.06.003.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-3.06.002 | every fired finding has metadata in catalog |
| BC-3.06.003 | every fired finding has non-empty playbook |

## Verification Approach

- Construct a synthetic mixed-protocol fixture with one trigger per new rule.
- Compare catalog list to finding list.
- Assert symmetric set membership.

## Evaluation Rubric

- Functional correctness (0.6): all eight rules registered + fired
- Edge case handling (0.2): empty playbook → fail
- Other dimensions: standard weights

## Failure Guidance

"HOLDOUT LOW: HS-002 (satisfaction: 0.XX) — new detector(s) missing from catalog or fired more than once on single-trigger fixture"

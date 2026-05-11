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
id: "HS-003"
category: "security-probes"
must_pass: "true"
priority: "must-pass"
wave: 1
epic_id: "E-2"
behavioral_contracts: ["BC-5.02.003"]
lifecycle_status: active
introduced: v0.4.0-feature
---

# HS-003: Privacy invariant survives all new Wave-1 extractor surfaces

> **NOT FOR IMPLEMENTERS.**

## Scenario

A new detector or parser introduced in Wave 1 (LDAP, NTLMv1, weak TLS
cipher, RDP, NTP, port-scan, modbus unit-id-sweep, DNP3, expanded OUI)
exposes a new field shape to the scrub layer. The evaluator verifies
that the privacy invariant — no real IP, MAC, hostname, or vendor
name escapes to the AI-bound payload — still holds across this expanded
surface.

1. **Precondition:** post-Wave-1 build; `claude` CLI is replaced by
   a mock that captures its stdin (no actual AI call).
2. **Action:** Run `otsniff analyze fixture.pcap -o out.html --ai`
   against a mixed-protocol fixture that triggers ≥ 5 of the new rules.
3. **Expected:**
   - The captured stdin contains zero real IPs (regex
     `(\d{1,3}\.){3}\d{1,3}` returns no matches with all-octet<256).
   - Zero IPv6 substrings.
   - Zero MAC substrings (`[0-9a-f]{2}(:[0-9a-f]{2}){5}`).
   - Zero hostname substrings from the fixture's DHCP option 12.
   - Zero vendor-name substrings from the fixture's OUI hits, except
     those documented as Low-BCSI per `docs/audits/scrub-audit-cip011.md`.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-5.02.003 | invariant: combined check on AI-bound bytes; load-bearing |

## Verification Approach

- Mock provider records stdin bytes.
- Run leak-detector standalone against the bytes.
- Run the supplementary check from `tests/snapshot.rs::invariant_no_real_values_reach_ai_provider`.

## Evaluation Rubric

- Functional correctness (0.7): leak-check returns Ok for the captured bytes
- Edge case handling (0.2): hostname from DHCP fixture must be pseudonymized
- Performance (0.1): scrub+leak-check < 1s

## Failure Guidance

"HOLDOUT LOW: HS-003 (satisfaction: 0.XX) — privacy invariant breached by a Wave-1 extractor surface"

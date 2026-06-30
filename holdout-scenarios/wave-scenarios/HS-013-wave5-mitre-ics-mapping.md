---
document_type: holdout-scenario
project: otsniff
level: ops
version: "1.0"
status: draft
producer: phase-2-story-decomposition
timestamp: 2026-06-30T00:00:00Z
phase: 2
inputs: [stories/S-12.01-mitre-attack-ics-mapping.md, behavioral-contracts/BC-INDEX.md]
traces_to: "P1-6"
id: "HS-013"
category: "integration-boundaries"
must_pass: "true"
priority: "must-pass"
wave: 5
epic_id: "E-12"
behavioral_contracts: ["BC-3.06.006", "BC-8.05.001"]
lifecycle_status: active
introduced: v0.6.0-feature
---

# HS-013: Every finding carries a MITRE ATT&CK for ICS technique, surfaced in HTML/MD/JSON

> **NOT FOR IMPLEMENTERS.**

Black-box evaluator: judge only from the CLI and its outputs. Do NOT read `src/`.

## Scenario

Every detector rule maps to at least one MITRE ATT&CK for ICS technique, and
every fired finding surfaces its technique(s) — as a link to attack.mitre.org —
in the HTML report, the markdown report, and the JSON output.

### Setup

Use a real or synthetic PCAP that triggers several distinct findings (e.g. one
that fires a credential rule, an SMBv1 rule, a TLS rule, and an ICS engineering
rule — or analyze any capture that produces ≥3 findings of different ids). You
may also consult `otsniff rules` for the full catalog.

### Checks

1. **Catalog coverage (BC-3.06.006).** `otsniff rules --format json` (or
   `otsniff rules`): EVERY rule entry has at least one MITRE ATT&CK for ICS
   reference whose URL is of the form `https://attack.mitre.org/techniques/T0…/`.
   Spot-check the 7 historically-unmapped rules — credential (plaintext/LDAP),
   SMBv1, stale-TLS, weak-TLS-cipher, DNS-to-non-OT, NTP-external — each now
   shows a `T0…` technique. (Some carry a "(supporting)" qualifier.)

2. **Technique IDs are real.** Each distinct `T0…` ID referenced resolves to a
   real ATT&CK-for-ICS technique page (the URL path matches
   `/techniques/T0\d+/`). At minimum confirm the IDs are well-formed and unique
   per label; if you have network access, a couple of HEAD/GET requests to the
   URLs should not 404.

3. **HTML surfacing (BC-8.05.001).** `analyze <pcap> -o r.html`: for a finding
   whose rule has a MITRE technique, `r.html` contains an anchor
   `<a href="https://attack.mitre.org/techniques/T0…/">…</a>` within (or adjacent
   to) that finding's card.

4. **Markdown surfacing.** `analyze <pcap> --md r.md`: the finding shows a
   `MITRE ATT&CK for ICS` line with a markdown link `[T0… — …](https://attack.mitre.org/techniques/T0…/)`.

5. **JSON surfacing.** `analyze <pcap> --json r.json`: each finding object carries
   a `mitre_techniques` array; for a mapped finding it is non-empty, each element
   has a `label` (containing a `T0…` id) and a `url`.

6. **No regression.** The asset inventory, comms matrix, and capture-summary
   sections are unchanged in spirit (the only additions are the MITRE
   lines/links on findings). `analyze` still exits 0.

## Behavioral Contract Linkage

| BC ID | Clause Tested |
|-------|--------------|
| BC-3.06.006 | every rule has ≥1 MITRE ICS technique; the 7 unmapped rules now covered |
| BC-8.05.001 | per-finding techniques surfaced as attack.mitre.org links in HTML, MD, JSON |

## Verification Approach

- Parse `otsniff rules --format json` and assert every rule has a MITRE
  reference (checks 1–2).
- Grep `r.html` / `r.md` for `attack.mitre.org/techniques/T0` near findings
  (checks 3–4).
- Parse `r.json` for `mitre_techniques` per finding (check 5).

## Evaluation Rubric

- Functional correctness (0.6): full catalog coverage + per-finding surfacing in
  all three formats.
- Edge case handling (0.3): "(supporting)" mappings present and labeled; real,
  well-formed technique IDs; no malformed/empty URLs.
- Performance (0.1): analyze completes promptly.

## Failure Guidance

"HOLDOUT LOW: HS-013 (satisfaction: 0.XX) — a rule lacks a MITRE ICS technique,
a technique ID/URL is malformed, or per-finding techniques are not surfaced in
HTML/MD/JSON."

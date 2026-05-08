# Security policy

## Reporting a vulnerability

Please **do not** file a public issue for security-relevant bugs.

Use GitHub's private vulnerability reporting:
https://github.com/adamson34/otsniff/security/advisories/new

Expect an initial response within 7 days. If the issue is confirmed, we'll
coordinate disclosure timing with you.

## What counts as security-relevant

- **Privacy / scrub layer regressions** — anything that could cause
  un-scrubbed identifiers to reach an AI provider, or cause the leak
  detector to fail open. The fail-closed kill switch is the project's
  load-bearing privacy claim; bugs there are top priority.
- **Memory safety** — `unsafe` blocks (we have none today; please flag any
  introduction).
- **Supply-chain** — unexpected dependencies pulled in, advisories on
  existing crates, or anything `cargo deny` should have caught and didn't.
- **Information disclosure in normal output** — fields the report leaks
  that aren't in the documented output schema.

## Out of scope

- False positives or false negatives in heuristic findings — report those
  as regular issues.
- Feature requests for additional detectors / protocols / providers — see
  the [roadmap](docs/ROADMAP.md).
- Compliance certification gaps — the project aligns with NERC CIP-011 /
  IEC 62443 handling principles but does not undergo formal certification.
  See "Explicitly not in scope" in the roadmap.

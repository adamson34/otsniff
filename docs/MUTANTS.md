# Mutation Testing for otsniff

This document captures mutation testing strategy, baseline, and triage guidance for the otsniff project.

## Scope (in-scope modules)

<!-- TODO(S-3.03 step 4): write the actual content describing why these modules matter and their security criticality -->

In-scope modules per AC-001:
- `src/findings/` — detection rules for security findings
- `src/parse/` — protocol parsers (Modbus, EtherNet/IP, S7Comm)
- `src/scrub.rs` — privacy-critical pseudonym minting and scrubbing
- `src/ai/leak_detector.rs` — fail-closed leak detection for AI-assisted triage

## Kill-rate baseline

<!-- TODO(S-3.03 step 4): populate with actual kill-rate once Step 3 baseline run is complete -->

| Module | Kill Rate | Total Mutants | Runnable | Notes |
|--------|-----------|---------------|----------|-------|
| `src/findings/` | — | — | — | — |
| `src/parse/` | — | — | — | — |
| `src/scrub.rs` | — | — | — | — |
| `src/ai/leak_detector.rs` | — | — | — | — |
| **Overall** | — | — | — | — |

Initial baseline established: <!-- TODO(S-3.03 step 4): add date of Step 3 run -->

## Interpreting a missed mutation

<!-- TODO(S-3.03 step 4): write guidance on how to read mutation reports and triage missed mutations -->

A missed mutation indicates:
- ...

## Common false-positives

<!-- TODO(S-3.03 step 4): document mutations that are expected to survive in this codebase -->

Known irrelevant mutations:
- Metadata strings (e.g., finding rule names, category labels)
- Log levels and verbosity settings
- Evidence sample ordering (findings are order-independent for reporting)

## Triage workflow

<!-- TODO(S-3.03 step 4): write the process for responding to a failed kill-rate ratchet (AC-003) -->

When mutation kill-rate drops > 5%:
1. ...
2. ...
3. ...

See also: `.cargo-mutants.toml` for configuration and skip-list.

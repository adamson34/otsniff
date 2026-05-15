---
document_type: ci-investigation
story_id: S-3.06
status: stub
timestamp: 2026-05-15T00:00:00Z
---

# macOS CI Flake: rustup-init invoked instead of cargo proxy

## Summary

TODO: One paragraph describing the observed failure mode (cargo resolves to rustup-init bytes
after Swatinem/rust-cache@v2 cache restore on macOS), the investigation timeline, the confirmed
root cause, and the chosen remediation (drop Swatinem/rust-cache@v2 from the macOS job only).

## Flake occurrences

| Date | Trigger (PR / develop push) | Run ID | Runner image label |
|------|-----------------------------|--------|--------------------|
| TODO | TODO                        | TODO   | TODO               |

## Runner image correlation

TODO: Document whether the macOS 14 → 15 runner image transition correlates with flake
occurrences. Pull the runner image label from the "Set up runner" or "Runner Image" step
in each failing run and note whether the version changed between clean and flaky runs.

## Upstream issue search

TODO: Search and link relevant upstream issues in:

- `dtolnay/rust-toolchain` — TODO
- `actions/runner-images` — TODO
- `rust-lang/rustup` — TODO

## Root cause hypothesis

TODO: One sentence stating the confirmed (or most probable) root cause.

## Chosen fix

TODO: One sentence identifying the chosen option (e.g., option b'' — drop
Swatinem/rust-cache@v2 from the macOS job) and its primary justification.

## Rollback plan

TODO: Describe the single-commit revert plan. Identify which commit (or PR) to revert,
the `git revert` command to run, and which fallback option from the story's AC-002 list
is the preferred next attempt if the rollback is needed.

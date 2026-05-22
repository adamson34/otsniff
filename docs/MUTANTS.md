# Mutation Testing for otsniff

This document captures mutation testing strategy, baseline, and triage
guidance for the otsniff project.  It is the authoritative reference for
interpreting cargo-mutants output and responding to kill-rate regressions.

## Scope

Mutation testing is scoped to four modules where a weakly-tested mutation
would represent a real security regression:

| Module | Why in scope |
|--------|--------------|
| `src/findings/` | Detection rules for security findings. A mutation that silences a finding could cause a real attack to go unnoticed. All condition branches and severity assignments must be tested. |
| `src/parse/` | Protocol parsers for Modbus, EtherNet/IP, and S7Comm. Wrong function-code handling produces false-negative findings; every encoding branch must be covered. |
| `src/scrub.rs` | Privacy-critical pseudonym minting and scrub/unscrub round-trip. A missed mutation here could leak real IP addresses or MAC addresses to the AI provider, violating the privacy invariant enforced by ADR-0006. |
| `src/ai/leak_detector.rs` | Fail-closed kill switch that sits between scrub output and any AI call. It must fail closed on any unrecognised address pattern; mutations here are the highest-risk category. |

Modules **excluded** from scope:

- `src/main.rs` — entry point; exit-code mapping only, covered by CLI smoke tests.
- `src/cli.rs` — clap argument parsing; integration-tested via assert_cmd.
- `src/observe.rs` — accumulator; high mutation count relative to security impact.
- `src/inventory.rs` — role-inference heuristics; best validated by integration tests with real PCAPs.
- `src/oui.rs` — static lookup table; no branches to mutate meaningfully.
- `src/report.rs`, `src/report_md.rs` — HTML/Markdown rendering; output format, not security logic.
- `tests/**`, `benches/**`, `examples/**` — not production code.

This scope is codified in `.cargo-mutants.toml` at the repo root.

## Kill-rate baseline

The wave-1 baseline was established on 2026-05-22 against commit `4680e66`
with cargo-mutants 27.0.0.  The numbers below reflect the **effective kill
rate after disposition**: surviving mutants were classified and recorded as:

- **A** — requires a new test (added to backlog)
- **B** — dead-code-equivalent (the surviving mutation is not reachable under
  any valid input)
- **C** — explicit waiver (the mutation is in a code path intentionally left
  untested; see the waiver comments in `.cargo-mutants.toml`)

Per BC-6.21.002, only A-class survivors count against the kill rate.

| Module | Kill Rate | Total Mutants | Killed | A-class survivors | B/C waivers |
|--------|-----------|---------------|--------|-------------------|-------------|
| `src/findings/` | 86.2% | 58 | 50 | 4 | 4 |
| `src/parse/` | 83.3% | 48 | 40 | 5 | 3 |
| `src/scrub.rs` | 82.1% | 39 | 32 | 3 | 4 |
| `src/ai/leak_detector.rs` | 85.7% | 35 | 30 | 2 | 3 |
| **Overall** | **84.1%** | **180** | **152** | **14** | **14** |

Baseline established: 2026-05-22  
Baseline commit: `4680e66`  
cargo-mutants version: 27.0.0

**Ratchet policy:** A future PR that drops kill-rate by > 5% (i.e. below
79.1%) is flagged for review as a soft signal.  The workflow posts the
current kill rate to `$GITHUB_STEP_SUMMARY` on every weekly run so the
team can track drift.  A drop of > 5% is not an automatic block, but it
must be acknowledged in the PR description with one of: a new test that
re-kills the escaped mutant, a B/C waiver with justification, or a comment
explaining why the drop is acceptable.

## Interpreting a missed mutation

A missed mutation means cargo-mutants replaced a piece of logic (e.g.
`&&` → `||`, `> 0` → `== 0`, a return value) and **all tests still
passed**.  This indicates at least one of:

1. **No test exercises that branch.** The most actionable outcome. Add a unit
   test that forces execution through the mutated path and asserts the correct
   behaviour.  For findings detectors, this usually means constructing an
   `Observations` fixture that triggers the exact condition and asserting
   the expected `Finding` is present.

2. **The branch is dead code.** The mutation is reachable only by inputs
   that the real system never produces (e.g. an enum variant that no parser
   emits).  Classify as B and add an `exclude_re` entry or a comment in
   `.cargo-mutants.toml` with justification.

3. **The test exists but does not assert the right thing.** The test calls
   the function but only checks a side effect that is not affected by the
   mutation.  Tighten the assertion.

4. **The mutation is semantically equivalent.** Occasionally cargo-mutants
   produces a mutation that does not change observable behaviour (e.g.
   changing `format!("{}", x)` to `format!("{:?}", x)` on a type where
   both are identical).  Classify as C and document the waiver.

To inspect a missed mutation locally:

```sh
cargo mutants --config .cargo-mutants.toml --no-shuffle 2>&1 | grep -A5 "MISSED"
```

The output shows the file, line, and the exact replacement made.

## Common false-positives

These mutation categories consistently survive in otsniff but are not
meaningful security gaps.  They are either already in the `skip_calls`
list in `.cargo-mutants.toml` or are classified as B/C on sight during
triage:

| Pattern | Example | Classification | Reason |
|---------|---------|----------------|--------|
| Metadata strings | Finding rule names (`"modbus_engineering"`) | B | Changing the string changes report output but not detection logic; covered by snapshot tests, not mutation tests. |
| Log level constants | `Level::Warn` → `Level::Info` | C | Log verbosity is not a security property; changing it does not affect findings or the privacy invariant. |
| Evidence sample ordering | Changing `take(5)` to `take(4)` | C | The findings layer caps evidence to ~5 samples for readability; the exact count is not a correctness invariant. |
| `unwrap` / `expect` call replacements | Mutating the message string in `expect("...")` | C | Covered by the `skip_calls` list; panic messages are diagnostic, not security properties. |
| Error formatting strings | `format!("could not write {path}")` | B | Error message text is not tested by any assertion; output stability is enforced by integration tests separately. |
| OUI lookup miss path | `None` → `Some("")` in OUI table | B | The OUI table is a best-effort lookup; a missed entry degrades vendor attribution, not security findings. |

When you encounter a new category of false-positive, add it to this table
and consider adding it to the `skip_calls` or `exclude_re` list in
`.cargo-mutants.toml` with a justification comment.

## Triage workflow

### Weekly run — normal case

1. The `Mutants (weekly)` workflow posts a kill-rate line to the GitHub
   Actions step summary.  Check it each Monday.
2. If kill rate ≥ 79.1% (within 5% of baseline), no action required.
3. Archive the outcomes artifact for historical comparison.

### Kill-rate drops > 5% below baseline

When the kill-rate falls more than 5% below 84.1% (i.e. below 79.1%):

1. **Download the `mutants-results` artifact** from the workflow run.
2. **Open `mutants-out/outcomes.json`** and filter for `"missed"` entries.
3. **For each missed mutation**, apply the classification rules from
   "Interpreting a missed mutation" above:
   - Class A: open a GitHub issue tagged `mutation-gap` with the file and
     line, and add a test in the same PR that introduced the regression.
   - Class B: add the mutation to `exclude_re` in `.cargo-mutants.toml`
     with a one-line comment explaining why it is unreachable.
   - Class C: add a comment in `.cargo-mutants.toml` under `skip_calls` or
     `exclude_re` with an explicit waiver and the date.
4. **Re-run cargo-mutants locally** after adding tests or waivers to confirm
   the kill rate recovers to ≥ 79.1%.
5. **Update the baseline table** in this document if the effective kill rate
   has materially changed (e.g. after a large refactor that removes modules
   from scope).
6. Open a PR with the test additions and/or waiver entries.  Reference the
   weekly run number in the PR description.

### Adding new code to in-scope modules

When adding new code to `src/findings/`, `src/parse/`, `src/scrub.rs`, or
`src/ai/leak_detector.rs`:

- The new code is automatically picked up by cargo-mutants on the next
  weekly run.
- Before merging, run `cargo mutants --config .cargo-mutants.toml` locally
  to check that your new tests kill the mutants you introduced.
- If the new code has a known-unreachable branch (e.g. a catch-all error arm),
  pre-emptively add an `exclude_re` waiver to avoid a false positive in the
  next weekly run.

See also: `.cargo-mutants.toml` for configuration and the `skip_calls`
and `exclude_re` skip-list entries.

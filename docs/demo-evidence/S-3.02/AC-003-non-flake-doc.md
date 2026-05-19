# AC-003 Non-Flake Handling — Evidence

## grep -B1 -A5 "90%|three runs|non-determinism" tests/prompt-evals/README.md

```
unexpected phrasing that causes a SHOULD assertion to miss. The harness
uses a **90% MUST threshold**: a pass requires at least 90% of MUST
assertions to be met across three runs of the same eval.

Concretely: if an eval has 4 MUST assertions, at least 4 must be met
(4/4 = 100%) each run. If an eval has 10 MUST assertions, at least 9
must be met (90%) across three runs.

### Escape Valve (EC-003)

When Claude produces a valid but structurally different analysis
(e.g., a novel format that still surfaces the same findings), SHOULD
assertions may fail. These are informational. If a SHOULD failure
recurs consistently across three runs, consider updating the rubric
to reflect the new valid behavior rather than treating it as a regression.

MUST NOT assertions have no threshold — a single violation is a failure.
These guard the privacy invariant (no real IPs/MACs/hostnames in the
response) and must never be relaxed.
```

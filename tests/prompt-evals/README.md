# Prompt Evaluation Harness

Rubric-based evals that measure whether the `analyze --ai` pipeline produces
sensible, privacy-safe OT triage output for each capture-source variant.

Each eval directory contains:
- `observations.json` — scrubbed `Observations` fixture (no real IPs/MACs/hostnames)
- `rubric.md` — numbered MUST/SHOULD/MUST NOT assertions the AI response must satisfy
- `run.sh` — convenience wrapper to run just this one eval

---

## Rubric Format

Rubric files use a numbered-list format. Each line is one of:

```
# comment or blank line (skipped)

1. MUST <pattern>       — response MUST contain text matching this pattern
2. SHOULD <pattern>     — informational; failure does not count against score
3. MUST NOT <pattern>   — response MUST NOT contain text matching this pattern
```

**Rules:**

- Check `MUST NOT` before `MUST` (the parser checks in that order)
- Pattern matching is case-insensitive substring / grep match
- Blank lines and lines starting with `#` are ignored
- Every rubric must contain at least one assertion

---

## How to Add a New Eval

1. Create a directory under `tests/prompt-evals/<name>/`
2. Generate `observations.json`: construct a representative `Observations` struct
   in Rust (or hand-author the JSON), run `otsniff scrub` if needed to ensure
   no real identifiers remain, then copy the scrubbed JSON.
3. Write `rubric.md`: 3–6 numbered MUST/SHOULD/MUST NOT assertions that capture
   the expected shape of Claude's analysis for this scenario.
4. Copy the `run.sh` template from an existing eval directory and verify it works:
   ```bash
   bash tests/prompt-evals/<name>/run.sh --dry-run
   ```

---

## Running Evals

### All evals (requires `claude` CLI)

```bash
bash tests/prompt-evals/run_all.sh
```

### Dry-run (validates rubric parsing, no AI calls)

```bash
bash tests/prompt-evals/run_all.sh --dry-run
```

### Single eval

```bash
bash tests/prompt-evals/span/run.sh
# or
bash tests/prompt-evals/run_all.sh span
```

---

## Non-Flake Discipline (AC-003)

LLM outputs are non-deterministic. A single run may produce valid but
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

---

## Leak Detector Wiring (EC-002)

`run_all.sh` runs a lightweight leak detector on every AI response before
scoring. If the response contains an IPv4 address or MAC address pattern,
the eval is marked FAIL regardless of rubric score. This mirrors the
compile-time invariant in `crates/otsniff-privacy/src/leak_detector.rs`
and ensures the eval harness itself cannot be used to exfiltrate real
identifiers.

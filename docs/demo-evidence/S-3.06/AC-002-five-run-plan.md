# AC-002 Evidence (Post-Merge): Five-Run Verification Plan

**Status: DEFERRED — requires PR to be merged to develop first.**

This document describes the post-merge verification procedure for AC-002. The
pre-merge evidence (workflow YAML diff) is captured in `AC-002-workflow-diff.md`.
This file must be updated with actual run IDs after the five runs complete.

---

## Procedure

After the feature branch merges to `develop`, run 5 consecutive macOS CI runs using
one of the two methods below:

**Method A — workflow_dispatch (preferred, no noise commits):**

```bash
# Repeat 5 times, waiting ~4 minutes between dispatches to avoid queue saturation
gh workflow run CI --ref develop
sleep 240
gh workflow run CI --ref develop
sleep 240
gh workflow run CI --ref develop
sleep 240
gh workflow run CI --ref develop
sleep 240
gh workflow run CI --ref develop
```

After each run completes, capture its ID:

```bash
gh run list --workflow=CI --branch=develop --limit=10 --json databaseId,conclusion,status
```

**Method B — empty commits (fallback if workflow_dispatch is not enabled):**

```bash
for i in 1 2 3 4 5; do
  git commit --allow-empty -m "ci: verification run $i/5 for S-3.06"
  git push origin develop
  sleep 60  # let the prior run clear the queue
done
```

Note: Method B creates 5 dummy commits on develop. Prefer Method A.

---

## Pass Criterion

All 5 macOS CI runs (`Test (macos-14)` job) must:

- Complete with conclusion `success`
- Require zero manual reruns
- Show no `rustup-init` error in the job logs

A single failure-without-rerun is an automatic FAIL for this criterion. A flake that
clears on the first rerun indicates the fix is insufficient; escalate to option (c)
per the rollback plan in `docs/ci-investigations/2026-05-macos-rustup-flake.md`.

---

## Who Executes

The next on-call maintainer after the PR merges to develop. Record results in the
"Results" section below and update the evidence-report.md status for AC-002-post-merge
from `DEFERRED` to `PASS` or `FAIL`.

---

## Results

| Run # | Workflow Run ID | Conclusion | macOS job result | Notes |
|-------|----------------|-----------|-----------------|-------|
| 1 | _pending merge_ | — | — | — |
| 2 | _pending merge_ | — | — | — |
| 3 | _pending merge_ | — | — | — |
| 4 | _pending merge_ | — | — | — |
| 5 | _pending merge_ | — | — | — |

**Final verdict:** DEFERRED (update to PASS/FAIL after all 5 runs)

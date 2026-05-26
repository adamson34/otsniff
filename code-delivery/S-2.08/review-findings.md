# Review Findings — S-2.08 `creds.rdp_no_nla`

## Convergence Table

| Cycle | Findings | Blocking | Fixed | Remaining | Verdict |
|-------|----------|----------|-------|-----------|---------|
| 1     | 2        | 0        | 0     | 0         | APPROVE |

## Cycle 1 Findings

### F-001 — Stale bit-test in module-level doc comment
- **Severity:** COSMETIC (non-blocking)
- **Category:** description
- **Location:** `src/findings/rdp_legacy.rs` line 4 (module-level `//!` comment)
- **Finding:** The module doc comment says `selectedProtocol & 0x01 == 0` but the actual implementation at line 88 correctly uses `!= 0x00000000`. The stale bit-test wording in the comment is inconsistent with the implementation and the corrected BC-3.04.006.
- **Impact:** No runtime impact. The implementation is correct. However a future reader could be confused if they trust the doc comment over the code.
- **Suggested fix:** Update the `//!` comment to read `selectedProtocol == 0x00000000` instead of `selectedProtocol & 0x01 == 0`.
- **Route:** pr-manager or implementer (cosmetic — non-blocking)
- **Status:** Does NOT block merge

### F-002 — Stale bit-test in pub function doc comment (line 62)
- **Severity:** COSMETIC (non-blocking)
- **Category:** description
- **Location:** `src/findings/rdp_legacy.rs` line 62 (first doc comment block on `build_findings`)
- **Finding:** The first `///` doc block at line 62 still states `selected_protocol & 0x01 == 0`. The second doc block at line 73 directly below it has the correct language. Both blocks are actually describing the same function — the first block appears to be a leftover from the stub phase that wasn't fully removed.
- **Impact:** No runtime impact. The corrected doc block at line 73 is authoritative.
- **Suggested fix:** Remove or merge the first (stale) doc block, keeping only the corrected language at line 73.
- **Route:** pr-manager or implementer (cosmetic — non-blocking)
- **Status:** Does NOT block merge

## Triage Routing

| Finding | Severity | Category | Route | Action |
|---------|----------|----------|-------|--------|
| F-001 | COSMETIC | description | pr-manager note | Non-blocking; correct implementation confirmed at line 88 |
| F-002 | COSMETIC | description | pr-manager note | Non-blocking; correct doc block present at line 73 |

## Verdict

**APPROVE**

All acceptance criteria are met:
- AC-001 (BC-1.04.004): Parser implemented, 9 unit tests pass, TPKT/X.224/RDP_NEG_RSP correctly decoded
- AC-002 (BC-3.04.006): Detector fires only on `selected_protocol == 0x00000000` (exact equality), 5 integration tests + 3 negative guards confirm correctness
- EC-001 / EC-002 / EC-003: All edge cases tested and passing
- 217/217 total tests pass, no regressions
- No new dependencies, no unsafe code, no lint suppressions
- Snapshot wiring test confirms zero regression on `run_all_findings`
- The AC-002 spec correction is well-documented (evidence file, inline in code, BC-3.04.006 registered with corrected condition)

The two cosmetic doc-comment inconsistencies (F-001, F-002) do not affect correctness — the firing logic at line 88 and the corrected doc block at line 73 are both accurate. These are tracked above for optional cleanup but do not block merge.

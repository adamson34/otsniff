# Evidence Report — S-2.02: Cap `cred_events` by deduping at observation time

| Field | Value |
|---|---|
| Story ID | S-2.02 |
| Worktree HEAD | `1de62ec11ec6d7db564de121f6f0084e5d4a9576` |
| Date | 2026-05-15 |
| BCs covered | BC-1.03.001, BC-1.03.002, BC-1.03.003, BC-1.03.004 (unchanged), BC-1.03.007 (new) |
| Recording tool | N/A — captured `cargo test` output (no CLI surface change) |

---

## AC Coverage

| AC | Description | Evidence file | Status |
|---|---|---|---|
| AC-001 | Same-key duplicates collapse; `count` reflects total; distinct kinds are independent | `AC-001-dedup-property.md` | PASS |
| AC-002 | All 50 existing snapshot tests produce no diff after dedup change | `AC-002-no-display-regression.md` | PASS |
| AC-003 | 1M duplicate ingestion: `cred_events.len() < 100`; peak heap < 50 MB (debug + release) | `AC-003-memory-bound.md` | PASS |
| BC reg | BC-1.03.007 registered in factory BC-INDEX | `BC-INDEX-registration.md` | PASS |

---

## Test result summary

| Test suite | Command | Result |
|---|---|---|
| Unit tests (3 dedup tests) | `cargo test --all-features test_bc_1_03_007_record_cred_event` | 3 passed, 0 failed |
| Snapshot regression (50 tests) | `cargo test --test snapshot` | 50 passed, 0 failed |
| Memory bound (debug) | `cargo test --test memory_bound -- --nocapture` | 1 passed, 0 failed |
| Memory bound (release) | `cargo test --test memory_bound --release -- --nocapture` | 1 passed, 0 failed |

---

## Limitations / Notes

- **No user-facing CLI surface.** S-2.02 is a pure internal observer change. There is no
  new subcommand, flag, or output format to demonstrate via VHS or Playwright. Evidence is
  captured `cargo test` output per codebase convention (see `docs/demo-evidence/S-2.09/`
  and `docs/demo-evidence/S-3.06/` for precedent).
- **BC-1.03.001..004** (credential observation BCs) are unchanged by this story. They are
  listed in the story frontmatter `behavioral_contracts` for traceability but no new
  evidence is required — existing snapshot tests cover them.
- **wrapping_add fix.** A debug-mode integer overflow in `CountingAllocator` was caught
  during evidence capture and fixed in commit `1de62ec` before this evidence was recorded.
  Both debug and release runs reflect the corrected allocator.

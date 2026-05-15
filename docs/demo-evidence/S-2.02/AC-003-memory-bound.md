# AC-003 — Memory bound: 1M duplicates, `cred_events.len() < 100`, peak heap < 50 MB

**Story:** S-2.02  
**Criterion:** Ingesting 1,000,000 synthetic Telnet packets from the same source yields
`cred_events.len() < 100` and peak heap < 50 MB.

---

## Debug-mode run

Command (relevant tail):

```
cargo test --test memory_bound -- --nocapture 2>&1 | tail -25
```

Output:

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running tests/memory_bound.rs (target/debug/deps/memory_bound-72b4954285f1a380)

running 1 test
test test_bc_1_03_007_cred_events_bounded_under_1m_duplicates ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.40s
```

---

## Release-mode run

Command (relevant tail):

```
cargo test --test memory_bound --release -- --nocapture 2>&1 | tail -25
```

Output:

```
   Compiling otsniff v0.4.0-dev.1 (/Users/lukeadamson/1898/otsniff/.worktrees/S-2.02)
    Finished `release` profile [optimized] target(s) in 2.38s
     Running tests/memory_bound.rs (target/release/deps/memory_bound-e94ae93843883cad)

running 1 test
test test_bc_1_03_007_cred_events_bounded_under_1m_duplicates ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
```

**Result: 1 passed, 0 failed — both debug and release.**

---

## Implementation note: CountingAllocator vs valgrind/massif

The story offered two candidate approaches for measuring peak heap: a `Drop`-based
`CountingAllocator` (a `#[global_allocator]` wrapper that tracks live bytes with
`AtomicUsize`) or `valgrind --tool=massif` in CI. The `CountingAllocator` approach was
chosen because it is self-contained in `tests/memory_bound.rs`, runs on all CI platforms
without toolchain additions, and produces a deterministic assertion rather than a massif
graph to interpret.

A debug-mode integer overflow was caught during verification: the allocator's byte counter
used wrapping arithmetic that silently underflowed to a large value in debug builds when
deallocations exceeded the tracked window. This was fixed in commit `1de62ec`
(`fix(S-2.02): use wrapping_add in CountingAllocator for debug-mode safety`), after which
both debug and release runs pass cleanly.

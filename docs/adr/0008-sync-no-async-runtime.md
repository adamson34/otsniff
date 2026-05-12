# ADR-0008: Sync throughout — no async runtime

## Status
Accepted (v0.1)

## Context
otsniff is a single-pass offline-analysis pipeline: open a PCAP file,
iterate packets, accumulate observations, derive inventory and findings,
render output, exit. There is no live capture, no concurrent network I/O,
no per-packet HTTP call, no watch loop, no daemon.

The question of whether to reach for an async runtime (Tokio, async-std)
comes up whenever subprocess calls are added — specifically when the
`analyze --ai` path was designed in v0.3. Two shapes were considered:

1. **Async runtime (Tokio)** — wrap the subprocess call in
   `tokio::process::Command`, `spawn`, `await`. Enables structured
   concurrency and easy heartbeat/timeout support via `select!`.

2. **Sync + background thread** — use `std::process::Command` with a
   background thread for progress reporting / heartbeat. No async executor.

## Decision
Stay synchronous throughout. No Tokio, no async-std, no async executor
of any kind. Every function in the pipeline is `fn`, not `async fn`.

Subprocess calls (the `claude -p` shell-out in ADR-0007) use
`std::process::Command::output()` — a blocking call. The AI heartbeat
display (S-5.02) uses a `std::thread::spawn` background thread, not an
async task.

## Rationale

- **Dependency budget.** ADR-0001 commits to a small dep tree and a
  single static binary. Tokio alone would add ~30 transitive crates (hyper,
  mio, socket2, tower, and friends) to the build graph. None of those crates
  are needed for offline PCAP analysis and all of them require audit.
- **No concurrent I/O.** The pipeline is strictly sequential: parse →
  accumulate → derive → render. There is nothing to run in parallel that
  would benefit from an async executor. A background thread for the AI
  progress indicator is the only concurrency the tool needs, and that is
  expressible in a few lines of `std::thread`.
- **Simpler reasoning.** Sync Rust code has no hidden await points,
  no executor panics, no Send/Sync constraint propagation through the
  call graph. The entire observation accumulator is a single `&mut Observations`
  reference passed down; that shape is incompatible with async without
  refactoring the core data model.
- **Binary size and startup time.** Removing the async runtime measurably
  shrinks the binary (~300KB on release builds) and eliminates the
  executor startup overhead — relevant because `otsniff` is invoked as a
  short-lived CLI, not a long-running service.
- **Supply-chain story.** Tokio's maintainer surface and release cadence
  are a separate upstream risk vector. Not depending on it means not
  tracking its security advisories.

## What this means for specific features

- **AI invocation (ADR-0007):** `std::process::Command::output()` blocks
  until the `claude` subprocess exits. This is acceptable: the user already
  knows AI analysis takes tens of seconds. A spinner/heartbeat runs on a
  background thread and is cancelled when the blocking call returns.
- **Heartbeat thread (S-5.02):** `std::thread::spawn` + a shared
  `Arc<AtomicBool>` stop flag. Cleaner than an async select loop for
  a single one-shot subprocess call.
- **Timeout (future):** Can be implemented with a background thread that
  sends `SIGKILL` after a deadline, or via the `wait_timeout` crate — no
  async runtime needed.

## Alternatives considered

- **Tokio for the AI subprocess only** — rejected because you can't
  easily pull in Tokio for one call without re-typing the surrounding
  call graph as async. The contamination would be wide.
- **smol / monoio (lighter runtimes)** — still add a runtime dependency
  and the associated audit cost; still contaminate function signatures.
- **async-std** — same concerns as Tokio.

## Consequences

- No `async fn` anywhere in the codebase. Any future feature that
  genuinely requires async (e.g., live capture with per-packet streaming)
  is an ADR-grade revisit that would touch the full call graph.
- Background-thread pattern for progress/heartbeat is the established
  idiom; any new feature that needs concurrency follows the same pattern
  until an async runtime is explicitly adopted.
- `std::process::Command` is the sole mechanism for shelling out;
  timeout must be managed at the OS level (`--timeout` flag passed to
  `claude`) or via background-thread watchdog.

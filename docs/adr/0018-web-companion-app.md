# ADR-0018: `otsniff-web` — a local web companion app

## Status
Accepted — in progress.

## Context

otsniff is CLI-only. That's the right default for the core tool (ADR-0001,
ADR-0008), but it's a real barrier for people who want to run an analysis,
look at a report, and compare it against a past run without opening a
terminal. The ask is a companion **app** — specifically a web app, because
a local server can also make outbound network calls in ways the CLI
deliberately doesn't (ADR-0007 has `analyze --ai` shell out to the
installed `claude` CLI precisely to avoid embedding an HTTP client/SDK in
the core tool). A local server is the natural place to add that later
(direct Anthropic API calls, threat-intel lookups) without touching the
CLI's dependency footprint at all.

## Decision

### D1 — New workspace crate `crates/otsniff-web`, not a feature flag on the root package

Same rationale as `zonewarden` (ADR-0013) and `otsniff-privacy` (ADR-0016):
a crate boundary keeps the web app's dependencies (`axum`, `tokio`,
`askama` for its own templates) completely out of the CLI binary's
dependency tree. `cargo build` for `otsniff` itself is unaffected —
`otsniff-web` is an opt-in binary someone builds and runs separately.
`otsniff-web` depends on the root `otsniff` crate as a library.

### D2 — Async runtime scoped to the new crate; the core pipeline stays sync

ADR-0008 rejected an async runtime for the CLI because a one-shot tool
reading one file doesn't need one. A web server genuinely does (handling
concurrent requests without one thread per connection). Rather than
reopening ADR-0008, `otsniff-web` adds its own `tokio` runtime and calls
the existing *synchronous* analyze pipeline (`pcap::iter_packets_multi` →
`observe::Observer` → `findings::run_all` → `report::render_html`, the
same functions `cli.rs`'s private `analyze()` helper already composes)
inside `tokio::task::spawn_blocking`. The core otsniff crate does not
gain an async fn anywhere; `otsniff-web` is just another synchronous
consumer of its public API, run off the async executor's blocking pool.

### D3 — In-process pipeline reuse, not shelling out to the `otsniff` binary

`otsniff-web` calls `otsniff::pcap`, `otsniff::observe`, `otsniff::inventory`,
`otsniff::findings`, `otsniff::capture_source`, and `otsniff::report`
directly — the same public modules the integration tests already use
(`src/lib.rs`'s own doc comment: "re-exports for integration tests"). No
subprocess, no need to locate the `otsniff` binary on `PATH`. `--ai`
support reuses `otsniff::ai::{claude_cli, ollama}` exactly as `cli.rs`
does — sync, blocking, same `spawn_blocking` wrapper.

### D4 — Local-only by default; JSON-file run index, not a database

`otsniff-web` binds to `127.0.0.1` by default. Runs are stored under a
data directory (default `./otsniff-web-data`, override via `--data-dir`)
as `<run-id>/` containing the same artifacts `analyze` already produces
(`report.html`, `report.json`, `report.audit.json` when `--ai` was used)
plus a small `meta.json`. The run list is a single `index.json` in the
data directory root, read/written on each request — no database
dependency for what's currently a single-operator, low-write-volume tool.
This can move to something heavier if/when otsniff-web needs concurrent
multi-writer access.

## Consequences

**We accept** a new, separate binary with its own release/versioning
story (starts unversioned/dev-only; not part of the `otsniff` CLI's
release process from ADR/roadmap P1-5 until it's ready to ship).

**We accept** that `--ai` inside the web app still requires the operator's
machine to have `claude` (or `ollama`) installed — v1 does not add a
direct Anthropic HTTP API integration. That's the natural v2 use of D2/D3
(the server can now hold an API key and make the call itself), deliberately
deferred so v1 ships the report-viewing/run-management core first.

**We accept** no authentication in v1 — `127.0.0.1`-only binding is the
security boundary. Multi-user or non-localhost deployment is out of scope
until there's a real need (mirrors the P2-4 "web playground" roadmap
entry's own "defer until demonstrated need" reasoning, though this is a
local single-operator tool, not a hosted multi-tenant one).

## Alternatives considered

**Desktop app (Tauri).** Rejected for v1: more packaging work (per-OS
bundles) for no functional gain over a local web server the operator
already has a browser for; a web app is also the more natural base if
outbound networking (the actual ask) becomes a first-class feature.

**Reuse `report.html`'s askama templates for the app's own UI.** The
report template is a single, self-contained document generated per-run;
the app's UI (dashboard, upload form) is a different, ongoing-navigation
surface. `otsniff-web` gets its own small template set rather than
stretching `report.html`'s templates to serve two purposes.

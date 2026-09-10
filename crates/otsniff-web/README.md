# otsniff-web

Local web companion app for [otsniff](../../README.md) (ADR-0018). Upload a
PCAP in a browser, get the same `analyze` report the CLI produces, browse
past runs — for anyone who doesn't want to run the CLI directly.

```bash
cargo run -p otsniff-web -- --port 7878 --data-dir ./otsniff-web-data
```

Then open <http://127.0.0.1:7878>.

## Scope (v1)

- Upload a PCAP/PCAPNG (with optional OT-subnet override), run the same
  rules-based `analyze` pipeline the CLI uses, view the rendered HTML
  report in the browser.
- Dashboard listing past runs with links to view/download each report and
  its JSON sidecar.

**Deliberately not in v1** (see ADR-0018 for why): `--ai` analysis,
diffing two past runs, anything beyond `127.0.0.1` binding / auth.

## Architecture

Binds `127.0.0.1` only — no auth, that's the v1 security boundary. Calls
straight into the core `otsniff` crate's existing public modules
(`pcap`, `observe`, `inventory`, `findings`, `capture_source`, `report`)
in-process; no subprocess, no shelling out to the `otsniff` binary. The
core pipeline stays fully synchronous (ADR-0008 is untouched) — this
crate's own `axum`/`tokio` async layer just calls it via
`tokio::task::spawn_blocking`. Runs are stored under `--data-dir` as
`runs/<id>/{report.html,report.json,<uploaded-file>}` plus a flat
`index.json` for the dashboard listing (no database).

Split into a lib (`src/lib.rs`, `pub fn build_router`/`open_state`) and a
thin `main.rs`, so `tests/http_smoke.rs` can start the real app in-process
on an ephemeral port and drive it with `reqwest` — the closest thing to a
browser test this environment can automate.

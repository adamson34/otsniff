# otsniff

One-shot OT-aware PCAP triage. A single Rust binary that ingests a PCAP/PCAPNG
and emits a self-contained HTML report with asset inventory + ranked security
findings. Binary name: `otsniff`.

## Scope

**v0.1 covers** Modbus/TCP and EtherNet/IP, plus four findings:
plaintext credentials, internet egress from OT subnets, ICS engineering-class
commands, and unexpected protocols on OT VLANs.

**Out of scope:** live capture, agent mode, dashboards, IDS/SIEM integration,
DNP3/S7Comm/OPC-UA/BACnet/IEC-104 (deferred to v0.2 if there's demand). See
`README.md` for the user-facing scope statement.

## Architecture

```
src/
├── main.rs            # Entry, maps OtError → exit code via ExitCode
├── lib.rs             # Crate root (re-exports for integration tests)
├── cli.rs             # clap derive + run() — single command, no subcommands
├── error.rs           # OtError enum + sysexits-style exit codes
├── pcap.rs            # PCAP/PCAPNG iterator (pcap-parser + etherparse)
├── parse/
│   ├── modbus.rs      # MBAP-framed Modbus PDU recognizer (function-code level)
│   └── enip.rs        # EtherNet/IP encapsulation header + CIP service heuristic
├── observe.rs         # Single-pass observer — accumulates hosts, flows, events
├── inventory.rs       # Derives Asset records with role inference
├── findings/
│   ├── plaintext_creds.rs
│   ├── internet_egress.rs
│   ├── engineering_commands.rs
│   └── unexpected_protocols.rs
├── oui.rs             # Embedded OT-vendor OUI lookup
└── report.rs          # askama HTML rendering (templates/report.html)

tests/
├── cli_smoke.rs       # End-to-end binary tests (assert_cmd + predicates)
├── snapshot.rs        # insta snapshots of HTML + JSON output
└── fixtures/          # Real PCAPs (gitignored — see fixtures/README.md)

docs/adr/              # Architecture Decision Records, numbered
```

The data flow is: PCAP → `Packet` stream → `Observer` accumulator →
`Observations` → (`build_inventory` + `run_all_findings`) → `render_html`.

## Build & Test

```bash
cargo build                        # debug build
cargo build --release              # optimized (LTO, strip, single codegen unit)
cargo test                         # all tests
cargo test --lib                   # unit tests only
cargo test --test '*'              # integration tests only
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                   # license + advisory audit (CI-only by default)

# Snapshot review after intentional output changes:
cargo insta review                 # requires `cargo install cargo-insta`
INSTA_UPDATE=always cargo test     # accept all on first creation
```

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`).
- **Branches:** `type/short-description` (e.g., `feat/dnp3-parser`, `fix/oui-table`). Default branch is `develop`. Feature branches → PR to `develop` → release PR to `main`.
- **Errors:** Add a variant to `OtError` with a sensible exit code mapping; don't reach for `anyhow`. Errors should suggest what to do next ("not a valid pcap/pcapng", "could not write output").
- **Output stability:** Any change to HTML or JSON output must be accepted via `cargo insta review`. Don't blindly `INSTA_UPDATE=always` in commits.
- **Findings layer:** Each detector is a free function in `src/findings/`. New detectors should: read `Observations`, return `Vec<Finding>`, use `BTreeMap` for grouping (deterministic iteration), cap evidence samples (~5 per finding) to keep reports readable.
- **Tests:** Unit tests inline (`#[cfg(test)] mod tests`), integration tests in `tests/`. New parsers must include round-trip unit tests with raw byte fixtures.
- **MSRV is 1.85** — bumped from 1.75 in early v0.1 because transitive deps (clap_lex via clap 4.5) started requiring `edition = "2024"`, which needs cargo 1.85+. If a future dep pushes us higher, bump again rather than pinning workarounds.
- **No unsafe code** without a `// SAFETY:` justification.
- **No lint suppression without refactoring.** If clippy warns, fix the root cause.

## Key Decisions

See `docs/adr/` for rationale:

- **ADR-0001** — Pure Rust, no Zeek dependency (single-binary UX over richer parsers)
- **ADR-0002** — Hand-rolled minimal protocol parsers (only function-code fidelity needed for v0.1 findings)
- **ADR-0003** — askama compile-time templating with pre-formatted view structs (avoids custom-filter fragility)
- **ADR-0004** — Owned packet payloads in `Packet` struct (simplicity > per-packet alloc savings)
- **ADR-0005** — Embedded OT-vendor OUI table (full IEEE registry is overkill for v0.1)

When adding a non-trivial feature or making an architectural decision, add a new ADR.

## Releases

Use the `/release` slash command (defined in `.claude/commands/release.md`).
Two flows: **dev release** from `develop` (pre-release, optimistic next minor)
and **stable release** through a `release/vX.Y.Z` branch into `main`.

## Testing against real captures

Real PCAPs live in `tests/fixtures/` (gitignored). Public sources:

- [4SICS ICS Lab](https://www.netresec.com/?page=PCAP4SICS)
- [ICS-pcap](https://github.com/automayt/ICS-pcap)
- [ICSNPP test traces](https://github.com/cisagov/icsnpp)

When adding a finding, also add a snapshot test in `tests/snapshot.rs` that
exercises it with a deterministic `Observations` fixture — don't rely solely
on real PCAPs, which may not be reproducible across machines.

---
pass: 0
name: inventory
project: otsniff
generated: 2026-05-11T18:55:00Z
source: /Users/lukeadamson/1898/test-project (self-reference — operating from project root)
---

# Pass 0 — Inventory

## Scope note

Source acquisition (Step 0) was a noop. otsniff is being analyzed
from inside its own worktree at `/Users/lukeadamson/1898/test-project`,
not from a separate `.reference/otsniff/` copy. The
`reference-manifest.yaml` file is intentionally absent — there's no
remote reference codebase to record. This is the supported
"self-reference" case per the brownfield-ingest protocol's third
condition ("If input is already in `.reference/`: no action needed.")
treated as also applying to "analysis of the current project."

## High-level numbers

| Metric | Value | Source |
|---|---:|---|
| Rust source files | 32 | `find src -name '*.rs' \| wc -l` |
| Rust LoC (with inline test modules) | 6,486 | `wc -l` total over `src/**/*.rs` |
| Integration test files | 2 | `find tests -name '*.rs' \| wc -l` |
| Integration LoC | 895 | `wc -l` over `tests/*.rs` |
| Tests passing | 100 | 69 unit + 11 CLI smoke + 20 snapshot |
| Direct dependencies | 11 | `Cargo.toml [dependencies]` |
| Direct dev-dependencies | 5 | `Cargo.toml [dev-dependencies]` |
| Public releases | 5 | v0.1.0, v0.2.0, v0.2.1, v0.3.0, v0.3.1 |
| ADRs | 7 | `docs/adr/0001-0007` |
| Per-feature specs | 9 | `docs/specs/*.md` |
| Detection rules | 12 | `docs/RULES.md` |

## File tree (Rust source, ordered by LoC asc)

```
src/parse/mod.rs                          4   re-exports for protocol parsers
src/main.rs                              16   entry: maps OtError → ExitCode
src/lib.rs                               19   crate root, re-exports for tests
src/ai/mod.rs                            30   AiProvider trait + module declarations
src/error.rs                             77   OtError enum, sysexits-style exit codes
src/oui.rs                               87   embedded OT-vendor OUI lookup
src/ai/prompts.rs                        91   committed system prompt + default task
src/ai/html_render.rs                    93   AI markdown → safe HTML via pulldown-cmark
src/ai/claude_cli.rs                    101   ClaudeCliProvider — shells out to `claude -p`
src/findings/smbv1.rs                   116   SMBv1 detection finding
src/findings/internet_egress.rs         123   egress.ot_to_internet finding
src/findings/dns_resolver.rs            137   boundary.dns_resolver finding
src/parse/modbus.rs                     151   Modbus/TCP function-code parser
src/inventory.rs                        152   Asset derivation + role inference
src/rule_catalog.rs                     154   md/json rendering of rule catalog
src/findings/stale_tls.rs               155   compat.stale_tls finding
src/findings/unexpected_protocols.rs    157   ot.unexpected_protocols finding
src/parse/enip.rs                       164   EtherNet/IP encapsulation + CIP service heuristic
src/findings/mod.rs                     173   Finding/RuleMetadata types, run_all dispatch
src/report.rs                           199   askama HTML rendering
src/ai/leak_detector.rs                 200   fail-closed leak detector (regex + map-value)
src/parse/dhcp.rs                       202   DHCPv4 option-12 parser
src/pcap.rs                             205   PCAP/PCAPNG iterator (pcap-parser + etherparse)
src/audit.rs                            211   AuditLog + sha256 helpers
src/parse/s7comm.rs                     215   S7Comm parser (Siemens TCP/102)
src/report_md.rs                        229   Markdown rendering
src/scrub.rs                            337   pseudonym minting + scrub/unscrub round-trip
src/findings/plaintext_creds.rs         354   creds.{ftp,telnet,http_basic,snmp} detector
src/findings/engineering_commands.rs    412   ics.{modbus_writes,cip_engineering,s7_engineering}
src/capture_source.rs                   606   capture-source heuristic + DeclaredSource
src/observe.rs                          629   single-pass Observer accumulator
src/cli.rs                              687   clap subcommands, run_analyze/run_scrub/run_unscrub/run_rules
```

## File prioritization (for VSDD downstream phases)

Per the brownfield-ingest protocol's "entry points → configs → core → API → tests → utils" guidance:

### Entry points (P0 — must understand)
| Path | Role |
|---|---|
| `src/main.rs` | Binary entry; maps `OtError` → `ExitCode` |
| `src/cli.rs` | clap subcommand definitions + `run_*` orchestrators |
| `src/lib.rs` | Crate root; re-exports for integration tests |

### Configs (P0)
| Path | Role |
|---|---|
| `Cargo.toml` | Crate metadata, dependencies, profiles |
| `deny.toml` | cargo-deny license + advisory rules |
| `.github/workflows/ci.yml` | CI gate definition (5 jobs: fmt, clippy, test×2, msrv, deny) |
| `.github/workflows/release.yml` | Release artifact build |

### Core — observation + detection (P0)
| Path | Role |
|---|---|
| `src/observe.rs` | Single-pass observer; accumulates `Observations` |
| `src/findings/mod.rs` | `Finding`, `RuleMetadata`, `run_all` |
| `src/findings/{8 files}` | 7 detectors implementing 12 fired finding IDs |
| `src/inventory.rs` | `Asset` derivation, role inference |
| `src/scrub.rs` | Pseudonym minting, scrub/unscrub |
| `src/ai/leak_detector.rs` | Fail-closed privacy invariant |
| `src/audit.rs` | Per-run chain-of-custody log |
| `src/capture_source.rs` | SPAN/host-side/TAP heuristic + DeclaredSource |

### Core — protocol parsers (P1)
| Path | Role |
|---|---|
| `src/parse/modbus.rs` | Modbus/TCP MBAP-framed parser |
| `src/parse/enip.rs` | EtherNet/IP encapsulation + CIP services |
| `src/parse/s7comm.rs` | S7Comm (Siemens TCP/102) |
| `src/parse/dhcp.rs` | DHCPv4 option 12 (hostnames) |
| `src/pcap.rs` | PCAP/PCAPNG packet iterator |
| `src/oui.rs` | Embedded OT-vendor OUI lookup |

### Render (P1)
| Path | Role |
|---|---|
| `src/report.rs` | HTML rendering via askama |
| `src/report_md.rs` | Markdown rendering (string formatting, no template engine) |
| `src/rule_catalog.rs` | `docs/RULES.md` generator |
| `src/ai/html_render.rs` | Safe-HTML rendering of Claude markdown via pulldown-cmark |
| `templates/report.html` | Sole askama template |

### AI layer (P1)
| Path | Role |
|---|---|
| `src/ai/mod.rs` | `AiProvider` trait |
| `src/ai/claude_cli.rs` | `ClaudeCliProvider` — shells out to `claude -p` |
| `src/ai/prompts.rs` | Committed system prompt + default task |

### Tests (P1)
| Path | Role |
|---|---|
| `tests/cli_smoke.rs` | 11 end-to-end binary tests via `assert_cmd` |
| `tests/snapshot.rs` | 20 insta snapshot tests + sentinel tests |
| `tests/snapshots/` | Committed reference outputs |
| `tests/fixtures/` (gitignored) | Real PCAPs for local testing |

### Utils (P2)
| Path | Role |
|---|---|
| `src/error.rs` | `OtError` enum + exit-code mapping |

## Tech stack

### Language + toolchain
- **Rust** edition 2021, MSRV 1.85 (pinned in `Cargo.toml::rust-version`)
- Toolchain pinned in CI via `dtolnay/rust-toolchain@stable` + an explicit `1.85.0` MSRV job

### Direct dependencies (11)
| Crate | Version | Purpose |
|---|---|---|
| clap | 4.5 (derive) | CLI argument parsing |
| pcap-parser | 0.16 (data feature) | PCAP/PCAPNG file format |
| etherparse | 0.15 | Ethernet/IP/TCP/UDP header parsing |
| askama | 0.12 | Compile-time HTML templating (ADR-0003) |
| serde + serde_json | 1.x | Serialization |
| thiserror | 2 | Error enum derivation |
| ipnet | 2.10 (serde feature) | CIDR matching for `--ot-subnet` |
| chrono | 0.4 (serde feature) | Timestamps |
| regex | 1.11 | Pseudonym tokenization, leak detector |
| sha2 | 0.10 | Audit log hashing |
| pulldown-cmark | 0.10 (no default, `html` only) | AI markdown → HTML |

### Dev-dependencies (5)
| Crate | Version | Purpose |
|---|---|---|
| pretty_assertions | 1.4 | Better diff output in tests |
| assert_cmd | 2 | CLI smoke testing |
| predicates | 3 | Predicate matchers for assert_cmd |
| insta | 1 (json feature) | Snapshot testing |
| tempfile | 3 | Temp dirs for tests |

### What's NOT in the stack (deliberately)
- **No async runtime.** No tokio, no async-std. Single-threaded, synchronous processing throughout. (Single-pass observer → batch findings → render.)
- **No HTTP/SDK to AI vendor.** All AI invocation goes through the shell to `claude -p` (ADR-0007).
- **No unsafe code.** Per CLAUDE.md convention.
- **No Zeek dependency** (ADR-0001).
- **No Node/npm in the toolchain** (per saved project posture).
- **No C linkage.** All deps are pure Rust.

## Release profile (`[profile.release]`)
```
lto = "thin"
codegen-units = 1
strip = true
```

Binary is single-file static (with the macOS dynamic system libs that
can't be statically linked) and optimized for size + cold-start time.

## Dependency graph (transitive, from Cargo.lock count)

Total transitive crates: 87 unique packages. No `tokio`, no `reqwest`,
no `openssl-sys` (since no HTTP client is needed). The `sha2` →
`block-buffer` + `digest` cluster is the only crypto-adjacent
dependency.

## Conventions visible at the inventory level

- **One module per detector.** `src/findings/*.rs` — 7 files, 12
  fired finding IDs (plaintext_creds.rs emits 4; engineering_commands.rs emits 3).
- **One module per protocol parser.** `src/parse/*.rs` — 4 files.
- **Templates live in `templates/`**, not inline.
- **No subdirectories for tests.** Flat `tests/*.rs` per Rust idiom.

## State of releases

| Tag | Date | Substance |
|---|---|---|
| v0.1.0 | 2026-05-07 | Initial; pure-Rust PCAP triage, Modbus + EtherNet/IP, 4 findings |
| v0.2.0 | 2026-05-08 | Scrub/unscrub, `analyze`, capture-source detector, flow grouping, S7Comm |
| v0.2.1 | 2026-05-08 | curl-pipe-sh installer + repo URL fix |
| v0.3.0 | 2026-05-11 | CLI consolidation (`analyze` primary), new findings, hostname extraction, rule catalog, audit log, source-type flag, playbooks |
| v0.3.1 | 2026-05-11 | Cargo.toml `repository` URL + AI-flow `.gitignore` |

## Notable absences (worth flagging for downstream)

- **No formal benchmark suite.** Only acceptance is `cargo test`. No `criterion` or `hyperfine` runs committed.
- **No Kani proofs yet.** P0-8 / Phase 6 would add formal verification of the privacy invariant.
- **No mutation testing.** `cargo-mutants` is on the deferred-install list.
- **No fuzz harness.** `cargo-fuzz` deferred.
- **No CHANGELOG.md file.** Release notes are on GitHub releases only.
- **No CODEOWNERS.** Solo maintainer.

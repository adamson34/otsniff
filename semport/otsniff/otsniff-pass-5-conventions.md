---
pass: 5
name: conventions
project: otsniff
generated: 2026-05-11T18:55:00Z
---

# Pass 5 — Convention Catalog

## Naming

### Crates / external types
- Standard Rust ecosystem names: `clap`, `serde`, `chrono`, `pcap_parser`, etc.
- No re-exporting of dep types under our own names (preserves source provenance).

### Modules
- `src/findings/<rule_family>.rs` — one module per detector family (`plaintext_creds.rs`, `engineering_commands.rs`, etc.). Even when one module emits multiple Finding IDs, the file name is the family name, not any one ID.
- `src/parse/<protocol>.rs` — one module per protocol (`modbus.rs`, `enip.rs`, `s7comm.rs`, `dhcp.rs`).
- `src/ai/<component>.rs` — `claude_cli.rs` (provider), `leak_detector.rs`, `html_render.rs`, `prompts.rs`.
- Cross-cutting infrastructure at the top level: `src/scrub.rs`, `src/audit.rs`, `src/observe.rs`, `src/inventory.rs`, etc.

### Types
- **Snake-case nouns** for value types: `HostObs`, `FlowObs`, `ModbusEvent`, `CredEvent`, `AuditLog`, `Classification`, `ScrubMap`, `RuleMetadata`.
- **PascalCase enum variants** that are conceptually values: `Severity::Critical`, `Role::Plc`, `Transport::Tcp`, `CredKind::FtpAuth`, `CaptureSource::Span { … }`.
- **`*Args`** for clap struct-of-options (one per subcommand: `ReportArgs` (removed in v0.3), `AnalyzeArgs`, `ScrubArgs`, `UnscrubArgs`, `RulesArgs`).
- **`*View`** for askama template-fed pre-formatted view structs: `AssetView`, `FindingView`, `TopFlow`.

### Finding IDs
- Period-separated lowercase: `creds.ftp`, `creds.telnet`, `ics.modbus_writes`, `compat.smbv1`, `boundary.dns_resolver`, `ot.unexpected_protocols`, `egress.ot_to_internet`.
- Format: `<family>.<rule_name>`. Family is a stable short word; rule_name describes the firing condition.
- IDs are `&'static str` literals — used in match arms, finding catalog lookup, and snapshot output.

### Pseudonym classes (public contract)
- `host_NNN` — IPv4 or IPv6 address
- `mac_NNN` — MAC address
- `name_NNN` — hostname (DHCP)
- Format: `<class>_<3-digit-decimal>` for indices ≤ 999; the index is monotonic across the run, sorted by real value at map-build time.
- Regex: `\b(?:host|mac|name)_[0-9a-f]+\b` (the `0-9a-f` is forward-compatible for future hex IDs, not used today).

### Test names
- `<what_under_test>_<expected_behavior>` (snake_case). Examples:
  - `every_finding_has_a_non_empty_playbook`
  - `invariant_no_real_values_reach_ai_provider`
  - `declared_source_disagreeing_with_heuristic_produces_warning`
  - `scrub_replaces_observed_values`
  - `cred_event_note_must_not_reach_any_rendered_output`
- Sentinel tests use `must_not`, `always`, or `invariant` prefixes to signal load-bearing role.

## Module organization

### Standard module layout
- Public types and functions at the top.
- Implementation blocks (`impl`) follow declarations.
- Helper functions at the bottom (small, file-local).
- `#[cfg(test)] mod tests { … }` at the file end.
- Module-level docstring at line 1 (per Rust idiom).

### Re-exports
- `src/lib.rs` re-exports `OtError` and `Result` for integration tests.
- `src/findings/mod.rs` re-exports `Finding`, `Severity`, `RuleMetadata`, `Reference`, `ReferenceKind` for renderer use.
- No deep re-exports — consumers go through the canonical path.

### Test placement
- **Unit tests:** inline `#[cfg(test)] mod tests` in the same file as the unit under test. Tests have visibility to private items.
- **Integration tests:** `tests/*.rs`. Only public API. Run as separate binaries.
- **Snapshot fixtures:** `tests/snapshots/*.snap`, committed. Reviewed via `cargo insta review`.

## Error handling

### Error enum pattern
- `OtError` is a `thiserror`-derived enum.
- Each variant maps to a specific `exit_code()` value (sysexits-style).
- `main.rs` catches the error, prints a chain of `source()` references, and exits with the mapped code.
- Variants:
  - `InputOpen { path, source }` — file open failure → 2
  - `BadInput { path, reason }` — file is invalid (e.g. not a PCAP) → 2
  - `WriteOutput { path, source }` — output write failure → 1
  - `Parse(String)` — general parse / validation / leak-detector failure → 1
  - `Json(serde_json::Error)` — auto-from JSON errors → 1
  - `Template(askama::Error)` — auto-from template errors → 1
  - `AiProvider(String)` — AI subprocess failure → 1

### Propagation idiom
- `Result<T> = std::result::Result<T, OtError>` — the only result alias.
- All fallible operations propagate via `?`.
- `unwrap()` and `expect("…")` only on literals validated at compile time (e.g. hardcoded CIDR parsing).

### Error messages
- Errors suggest what to do next: `"not a valid pcap/pcapng"`, `"could not open input"`, `"could not write output"`.
- Leak detector errors specifically mention the offending pattern + byte offset so a user can file a precise bug report.

## Test patterns

### Test pyramid
- **Unit tests** (69 today) — small, fast, internal.
- **Integration tests** (11 + 20 = 31 today) — through the public API.
  - `cli_smoke.rs` (11) — end-to-end CLI tests via `assert_cmd` + `predicates`.
  - `snapshot.rs` (20) — render outputs via `insta`, plus sentinel tests guarding invariants.
- **No e2e network tests, no flake-prone tests.**

### Snapshot test discipline
- `tests/snapshots/*.snap` files are committed.
- Workflow: change output → `cargo test` fails → `cargo insta review` to accept/reject → commit the updated snapshot together with the code change.
- Never `INSTA_UPDATE=always` in commit history (per CLAUDE.md).

### Sentinel test pattern
- Each sentinel guards a single invariant that wouldn't be caught by output snapshots alone.
- Example: `cred_event_note_must_not_reach_any_rendered_output` injects a canary username into `cred_events[].note` and asserts the canary string doesn't appear in HTML, markdown, scrubbed-markdown, or per-event JSON.
- Failure messages explain the regression class so a future maintainer understands why the test exists.

### Fixture pattern
- `build_fixture()` in `tests/snapshot.rs` constructs an `Observations` struct literal with deterministic values.
- Real PCAPs live in `tests/fixtures/` (gitignored).
- A skip-if-missing pattern: smoke tests check fixture presence and skip silently when absent — keeps CI passing in fresh clones.

## Design patterns

### Pattern: "Owned over borrowed" (ADR-0004)
- `Packet::payload: Vec<u8>` is owned, not `&[u8]`. Simplifies downstream code (no lifetime contagion).

### Pattern: "Two-pass scrub" (ADR-0006)
- Render report with real values; THEN substitute via `scrub_text(rendered, &map)`. Limits substitution to values we actually observed (no accidental rewrite of IP-shaped substrings in unrelated text).

### Pattern: "Pre-formatted view structs" (ADR-0003)
- `report::AssetView`, `FindingView`, `TopFlow` are constructed in Rust with all formatting (severity labels, byte humanization, role labels) already done. The askama template only does plain `{{ field }}` interpolation. Avoids template-engine custom-filter fragility.

### Pattern: "Pure function over Observations" (architecture review)
- Every detector signature: `fn detect(obs: &Observations[, ot_subnets: &[IpNet]]) -> Vec<Finding>`.
- No global state, no side effects, no I/O. Easy to unit-test with synthetic Observations.

### Pattern: "Const metadata block per detector"
- Every `src/findings/*.rs` exposes one or more `pub const _METADATA: RuleMetadata`. Lives next to the detector code so it can't drift. Aggregated in `findings::catalog()`.

### Pattern: "Fail-closed leak detection"
- Two-layer regex + map-value check, both must pass before AI invocation.
- Pre-write check on the audit log itself (belt-and-braces — even though the audit log carries no real values, scan it anyway).

### Pattern: "Subagent for AI, never embedded SDK"
- `ClaudeCliProvider` shells out to `claude -p`. No HTTP client, no SDK linked. ADR-0007.

### Pattern: "BTreeMap over HashMap when iteration order matters"
- `Observations::hostnames` is `BTreeMap` (deterministic for scrub map building).
- `Observations::mac_frame_counts` is `BTreeMap` (deterministic for capture-source classifier).
- `ScrubMap::ips/macs/names` are `BTreeMap` (deterministic pseudonym assignment).
- General `HashMap` everywhere else (e.g. `Observations::hosts`) — keys are written but final order doesn't matter for output (re-sorted at render time).

### Pattern: "Auto-derived path from `-o`"
- Audit log path: `report.html → report.audit.json` via `set_extension("audit.json")`. User can override with `--audit-log <PATH>`.
- Pattern is documented in CLAUDE.md and matches the user's mental model.

### Pattern: "Investigation playbook per finding"
- Every Finding ships a `playbook: Vec<String>` of concrete next-actions tied to actual evidence (specific hosts, vendor-specific commands like `ipconfig /all` and Schannel registry paths).
- Sentinel-tested: every detector must populate a non-empty playbook.

## Anti-patterns observed (and avoided)

| Anti-pattern | How otsniff avoids it |
|---|---|
| Stringly-typed finding IDs in tests | `Finding::id: &'static str` — same literal used in source and tests. |
| Hidden global state | Single `Observations` struct flows explicitly through pipeline. |
| Builder pattern boilerplate | All structs constructed with `StructName { field: value, … }` literals. |
| Re-exports that hide module origin | No deep re-exports. |
| Custom error types per module | One `OtError` enum; modules add variants. |
| `Box<dyn Error>` for "anything goes" errors | `thiserror`-derived enum with explicit variants. |
| `anyhow` everywhere | Not used. |
| Unwrap()/expect() in hot paths | Forbidden by convention (CLAUDE.md). |
| Async-for-no-reason | No async runtime; pipeline is sync. |
| Loose pseudonym format | Format is regex-safe and part of the public contract (ADR-0006). |
| Per-detector custom severity scale | One `Severity` enum with 4 levels (Info, Medium, High, Critical). |
| Custom format strings duplicating Display | Display impls used where useful; otherwise `Debug` for diagnostic prints. |

## Commit conventions

### Format
- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`.
- Breaking change indicator: `feat!:` (e.g. `feat!: unify CLI` for v0.3 CLI consolidation).
- Optional scope: `docs(roadmap):`, `feat(scrub):`, etc.

### Body
- Multi-line. Wraps at ~72 columns.
- Explains *why* the change exists, not just *what* it does.
- Cites file paths + test names for traceability.
- Examples in recent history (`git log --oneline -10`) show the style.

### Trailers
- **No `Co-Authored-By: Claude`** (per user preference, applied to recent history).
- Dependabot bot trailers are acceptable.

## Branch conventions

- **`main`** — released code; what `v*` tags point at; what install.sh fetches by default
- **`develop`** — accumulation branch; what `feat/*` and `chore/*` PRs target
- **`feat/<short-description>`** — feature branches (e.g. `feat/hostnames-in-evidence`, `feat/source-type-flag`)
- **`chore/<short-description>`** — chore branches (e.g. `chore/gitignore-factory`)
- **`docs/<short-description>`** — docs-only branches
- **`ci/<short-description>`** — CI workflow changes
- **`release/v<X.Y.Z>`** — temporary, for the develop → main release PR
- **`factory-artifacts`** — orphan branch carrying `.factory/` worktree (vsdd-factory plugin)

## CI conventions

- **5 status checks** required on `main` and `develop`:
  - `Format` (rustfmt --check)
  - `Clippy` (`-D warnings`)
  - `Test (ubuntu-latest)`
  - `MSRV (1.85.0)` (cargo check on the pinned toolchain)
  - `cargo-deny (licenses + advisories)`
- **macOS test** runs on PRs (post-public-flip restoration).
- **`Test (macos-latest)` skips** on private-fork PRs to avoid runner-minute waste; for adamson34/otsniff it always runs.

## Release conventions

- Two flows per `.claude/commands/release.md`:
  - **Dev release** from `develop` (e.g. `v0.4.0-dev.1`) — optimistic next-minor
  - **Stable release** through `release/v<X.Y.Z>` → main → tag
- After every stable release: merge `main` back into `develop` (reconciles the squash) and bump develop's Cargo.toml to next `dev.1`.
- Tag is annotated, signed only if the maintainer has a configured key.
- GitHub Actions builds platform-specific artifacts and a draft release; maintainer publishes manually after release notes are finalized.

## Documentation conventions

- **ADRs** in `docs/adr/NNNN-short-name.md`, numbered sequentially, Markdown with Status / Context / Decision / Consequences sections (loose ADR format — not strict Michael Nygard).
- **Per-feature specs** in `docs/specs/<feature-name>.md`. Each contains: Problem, Decision, Algorithm/Shape, Test Plan, Out of Scope, and (since P0-4) a Scrub Stance section.
- **Audit documents** in `docs/audits/<framework-name>.md` (one today: `scrub-audit-cip011.md`).
- **`CLAUDE.md`** — top-level conventions and architecture overview. Kept under 200 lines; refreshed when a structural decision lands.
- **`docs/RULES.md`** — auto-generated from `findings::catalog()`. Never edit by hand.
- **`docs/ROADMAP.md`** — opinionated priority list. `# Released` section at top; P0/P1/P2 buckets below.

## Consistency assessment

| Convention | Adherence | Notes |
|---|---|---|
| Conventional Commits | 100% (recent history) | Older commits in v0.1/v0.2 era predate the convention enforcement; not a regression. |
| Module-per-detector | 100% | Every fired finding has a known parent module. |
| Snake_case test names | 100% | Verified by grep. |
| `OtError` for all errors | 100% | No `anyhow`, no module-specific error types. |
| `BTreeMap` where iteration order matters | 100% | All scrub map / catalog / capture-source paths are stable. |
| Pseudonym format compliance | 100% | Regex-tested in unit + sentinel. |
| Const metadata for every detector | 100% | Sentinel-tested. |
| `// SAFETY:` on every `unsafe` | N/A | No unsafe blocks exist. |
| Snapshot test review before commit | 100% | `*.snap.new` files gitignored; only reviewed `.snap` files committed. |
| ADR-0006 scrub stance per new feature spec | 100% (P0-4+) | `docs/specs/scrub-stance-template.md` is the required section. Older specs predate this. |
| `feat!` for breaking changes | 100% | v0.3 CLI unification commit uses it correctly. |
| Per-feature spec for non-trivial features | ~80% | Some early features (v0.1 era) lack specs because docs/specs/ didn't exist yet. Newer features (v0.3 era) all have specs. |

Overall: highly consistent. The codebase reads as if one author held the
whole picture in mind throughout — which is accurate.

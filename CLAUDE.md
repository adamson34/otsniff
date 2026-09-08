# otsniff

One-shot OT-aware PCAP triage. A single Rust binary that ingests a PCAP/PCAPNG
and emits a self-contained HTML report with asset inventory + ranked security
findings. Binary name: `otsniff`.

## Scope

**Currently shipped:**

- Modbus/TCP, EtherNet/IP, S7Comm, and DNP3 protocol decoding
  (function-code level), plus DHCP / LDAP / RDP recognizers for inventory
  and credential findings
- **23 rule-based findings** (full catalog in `docs/RULES.md`): plaintext
  credentials (rolled up by kind), LDAP simple-bind, RDP-without-NLA,
  internet egress from OT subnets, ICS engineering commands
  (Modbus / EtherNet-IP CIP / S7Comm / DNP3), SMBv1, stale TLS, weak TLS
  ciphers, NTLMv1, DNS/NTP to non-OT destinations, port-scan + Modbus
  unit-ID-sweep recon, unexpected protocols on OT VLANs, and three
  policy-gated `zonewarden.*` segmentation verdicts
- **Zonewarden segmentation conformance** (ADR-0013) — declarative
  IEC 62443 zone/conduit policy checking with the Purdue-3.5 IDMZ
  no-bypass control. Pure, Kani-verified engine in `crates/zonewarden`;
  surfaced via `analyze --policy`, `zonewarden suggest` (policy drafting),
  and `diff --policy` (segmentation drift, P1-13)
- **AI-augmented findings** — a second LLM pass over the rules + inventory
  surfaces patterns the deterministic rules miss, with per-item confidence
  + reasoning, in a separate report section
- **Cross-capture diff** (`diff` subcommand) — host / finding / role /
  comms-matrix deltas between two captures via merged scrub maps
- Asset inventory with role inference, DHCP hostname extraction, and
  OUI vendor lookup
- Capture-source heuristic (SPAN / host-side / TAP / ambiguous) +
  explicit `--source-type`
- Logical flow grouping (drops ephemeral src_port; tracks unique
  connections per logical flow)
- Investigation playbooks + a rule catalog (`rules` subcommand)
- Scrub/unscrub for AI-assisted triage (ADR-0006) — every IP, MAC, and
  DHCP hostname replaced with stable pseudonyms before any AI sees the
  report
- `analyze --ai` (ADR-0007) — closes the scrub → AI → unscrub loop via
  the user's local `claude` CLI. A fail-closed leak detector enforces the
  privacy invariant even if the scrub layer has a bug; a per-run privacy
  audit log writes alongside the report

See `docs/ROADMAP.md` for the prioritized backlog of what's next.

**Out of scope:** live capture, agent / sensor mode, vendor cloud
integration, audit-grade certification, general-purpose IT triage,
SIEM/IDS event-stream integration. See `docs/ROADMAP.md` for the full
list with rationale per item.

## Architecture

otsniff is a three-member Cargo workspace: the `otsniff` binary crate at the
root, the pure, Kani-verified `zonewarden` engine under `crates/`
(ADR-0013 keeps it a crate boundary so its no-I/O guarantee and proofs stay
isolated), and the pure, Kani-verified `otsniff-privacy` crate (ADR-0016,
same rationale — a formally-verified pure core that a second, not-yet-started
consumer needs).

```
src/
├── main.rs            # Entry, maps OtError → exit code via ExitCode
├── lib.rs             # Crate root (re-exports for integration tests)
├── cli.rs             # clap subcommands: analyze / scrub / unscrub / rules / diff / zonewarden
├── error.rs           # OtError enum + sysexits-style exit codes
├── pcap.rs            # PCAP/PCAPNG iterator (pcap-parser + etherparse)
├── parse/             # Minimal protocol recognizers (function-code level):
│                      #   modbus, enip, s7comm, dnp3, dhcp, ldap, rdp
├── observe.rs         # Single-pass observer — accumulates hosts, flows, events
├── inventory.rs       # Derives Asset records with role inference
├── capture_source.rs  # SPAN / host-side / TAP / ambiguous heuristic + guard
├── findings/          # One free fn per detector → Vec<Finding>. mod.rs wires
│                      #   run_all() + run_with_conformance(). Includes the
│                      #   ICS/creds/compat/boundary/recon rules, zonewarden.rs
│                      #   (policy verdicts), and augmented.rs (second AI pass)
├── segmentation/      # Bridge to crates/zonewarden: policy loader, Observation→
│                      #   Flow bridge, engine runner, `suggest` policy drafter
├── diff.rs            # Cross-capture delta (P1-3) + segmentation drift (P1-13)
├── rule_catalog.rs    # Backing data for `otsniff rules` / docs/RULES.md
├── oui.rs             # Embedded OT-vendor OUI lookup
├── report.rs          # askama HTML rendering (templates/report.html, diff.html)
├── report_md.rs       # Markdown rendering (LLM-friendly text)
├── scrub.rs           # Population only: build_map/build_map_at/merge_map walk
│                      #   otsniff's Observations to discover identifiers; the
│                      #   pseudonym mechanics live in crates/otsniff-privacy
│                      #   (ADR-0016)
├── audit.rs           # Privacy chain-of-custody audit log (ADR-0012)
├── progress.rs        # Verbose-mode progress reporting
├── kani_proofs.rs     # Composed privacy-invariant proof harnesses (CBMC-friendly
│                      #   models; the component proofs moved to
│                      #   crates/otsniff-privacy per ADR-0016)
└── ai/
    ├── mod.rs              # AiProvider trait
    ├── claude_cli.rs       # Provider that shells out to `claude -p ...` (tool-sandboxed)
    ├── html_render.rs      # render_safe — strips raw HTML from the AI response
    └── prompts.rs          # Committed system prompt + default task

crates/
├── zonewarden/         # Pure segmentation engine (resolver, classifier, idmz,
│                       #   multicast, aggregator, digest, validator) + 7 Kani proofs
└── otsniff-privacy/    # Pure privacy/scrub core (ScrubMap, scrub_text/
                        #   unscrub_text, leak_detector) + Kani proofs (ADR-0016).
                        #   otsniff-specific population (build_map/merge_map)
                        #   stays in src/scrub.rs; this crate has zero
                        #   otsniff-specific types so a second consumer
                        #   ("otsniff-hunt") can depend on it directly.

tests/
├── cli_smoke.rs       # End-to-end binary tests (assert_cmd + predicates)
├── snapshot.rs        # insta snapshots of HTML + JSON output + privacy invariants
├── s_*.rs             # Per-story tests (diff, fuzz, mutation, composed Kani proof)
├── prompt_evals.rs    # Structural rubrics for the AI flow
└── fixtures/          # Real PCAPs (gitignored — see fixtures/README.md)

docs/adr/              # Architecture Decision Records, numbered (0001–0016)
```

The data flow is: PCAP → `Packet` stream → `Observer` accumulator →
`Observations` → (`inventory::build` + `findings::run_all`, or
`run_with_conformance` when a `--policy` is supplied) → `render_html`.
With `--policy`, observed flows are bridged into the `zonewarden` engine
(`segmentation::run_conformance_path`) and its verdicts join the findings
and the report's conformance section.

## Build & Test

```bash
cargo build                        # debug build
cargo build --release              # optimized (LTO, strip, single codegen unit)
cargo test --workspace             # all tests (both crates)
cargo test --lib                   # unit tests only
cargo test --test '*'              # integration tests only
cargo clippy --all-targets --workspace -- -D warnings
cargo fmt --all -- --check
cargo deny check                   # license + advisory audit (CI-only by default)

# Snapshot review after intentional output changes:
cargo insta review                 # requires `cargo install cargo-insta`
INSTA_UPDATE=always cargo test     # accept all on first creation
```

Formal verification + fuzzing run in CI (`kani.yml`, `fuzz.yml`,
`mutants.yml`): 7 Zonewarden segmentation proofs + the privacy-invariant
proofs (Kani), parser fuzz harnesses under `fuzz/`, and an 80%-kill
`cargo-mutants` gate.

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`).
- **Branches:** `type/short-description` (e.g., `feat/dnp3-parser`, `fix/oui-table`). Default branch is `develop`. Feature branches → PR to `develop` → release PR to `main`.
- **Errors:** Add a variant to `OtError` with a sensible exit code mapping; don't reach for `anyhow`. Errors should suggest what to do next ("not a valid pcap/pcapng", "could not write output").
- **Output stability:** Any change to HTML or JSON output must be accepted via `cargo insta review`. Don't blindly `INSTA_UPDATE=always` in commits.
- **Findings layer:** Each detector is a free function in `src/findings/`. New detectors should: read `Observations`, return `Vec<Finding>`, use `BTreeMap` for grouping (deterministic iteration), cap evidence samples (~5 per finding) to keep reports readable.
- **Tests:** Unit tests inline (`#[cfg(test)] mod tests`), integration tests in `tests/`. New parsers must include round-trip unit tests with raw byte fixtures.
- **MSRV is 1.85** — bumped from 1.75 because transitive deps (clap_lex via clap 4.5) started requiring `edition = "2024"`, which needs cargo 1.85+. If a future dep pushes us higher, bump again rather than pinning workarounds.
- **No unsafe code** without a `// SAFETY:` justification.
- **No lint suppression without refactoring.** If clippy warns, fix the root cause.

## Subcommands

```
otsniff analyze <PCAP> -o report.html [--ai] [--policy zones.yaml] [--audit-log X] [--md X] [--json X] [--map X] [--ot-subnet ...] [--source-type ...] [--model M]
otsniff diff <BASELINE> <CURRENT> --baseline-map A.json --current-map B.json -o diff.html [--policy zones.yaml] [--flow-shift-multiplier N] [--ot-subnet ...]
otsniff zonewarden suggest <PCAP> [--ot-subnet ...]      # draft a policy from the inventory
otsniff scrub   <PCAP> -o report.md --map map.json [--ot-subnet ...] [--source-type ...]
otsniff unscrub --map map.json [INPUT_FILE] [-o OUTPUT] [--strict]
otsniff rules   [--format md|json]
```

`analyze` is the primary subcommand. Without flags it produces an HTML
report (rules-based findings + inventory + comms-matrix). With `--ai`
it additionally runs scrub → leak-check → invoke local `claude` CLI →
unscrub → embed Claude's response as an "AI analysis" section in the
rendered HTML. When `--ai` is set, the privacy audit log is written
automatically alongside the report (default path: `report.audit.json`).
With `--policy` it runs Zonewarden conformance and adds a segmentation
section + `zonewarden.*` findings (and deduplicates `egress.ot_to_internet`
against the policy).

`diff` compares two captures by pseudonym (via merged scrub maps). With
`--policy` it adds a "Segmentation drift" section — conformance-tally
deltas + per-violation new/resolved/persisting (P1-13).

`zonewarden suggest` drafts a starter `zones.yaml` from the asset
inventory (the only `zonewarden` subcommand; the conformance run itself
is `analyze --policy`).

`scrub` / `unscrub` are advanced subcommands for users who want to
drive their own AI (Claude.ai web UI, ChatGPT, local Ollama, etc.) —
manual two-step counterpart to `analyze --ai`.

`rules` prints the detection catalog (same content as `docs/RULES.md`).

**The privacy invariant is enforced by code, not convention.** See ADR-0007.
`crates/otsniff-privacy/src/leak_detector.rs` (moved from `src/ai/leak_detector.rs`
by ADR-0016) sits between scrub and any AI provider call and fails closed via
two checks: a regex scan for IPv4/IPv6/MAC patterns and a map-value check
that catches anything in the scrub map (notably hostnames, which have no
clean regex shape). The AI's markdown response
is rendered through `src/ai/html_render.rs::render_safe`, which strips
raw HTML events so a Claude response containing `<script>` can't XSS
the rendered report. Any change that adds a code path bypassing scrub
must also pass the leak detector or the invariant test
(`tests/snapshot.rs::invariant_no_real_values_reach_ai_provider`) will
block the commit.

## Key Decisions

See `docs/adr/` for rationale:

- **ADR-0001** — Pure Rust, no Zeek dependency (single-binary UX over richer parsers)
- **ADR-0002** — Hand-rolled minimal protocol parsers (only function-code fidelity needed for the findings layer)
- **ADR-0003** — askama compile-time templating with pre-formatted view structs (avoids custom-filter fragility)
- **ADR-0004** — Owned packet payloads in `Packet` struct (simplicity > per-packet alloc savings)
- **ADR-0005** — Embedded OT-vendor OUI table (full IEEE registry is overkill for the current scope)
- **ADR-0006** — Scrub/unscrub for AI-assisted triage (no embedded AI client; pseudonym round-trip via local map file)
- **ADR-0007** — AI via the Claude Code CLI (shell-out, no HTTP/SDK, fail-closed leak detector enforces privacy)
- **ADR-0008** — Sync throughout, no async runtime (single-shot CLI doesn't need one)
- **ADR-0009** — Drop ephemeral src_port from the flow key (logical-flow grouping)
- **ADR-0010** — Roll up plaintext-cred findings by kind
- **ADR-0011** — pulldown-cmark with a raw-HTML event filter for the AI markdown
- **ADR-0012** — Audit log auto-derives its path from `-o`
- **ADR-0013** — Fold Zonewarden in as a segmentation module (pure engine as a workspace sub-crate)
- **ADR-0014** — MITRE ATT&CK for ICS mapping lives in the rule catalog
- **ADR-0016** — Extract the privacy/scrub layer into `crates/otsniff-privacy`

(ADR-0015 — operator-declared trusted writers — is spec-written but not yet
implemented; see `docs/adr/0015-operator-declared-trusted-writers.md`.)

When adding a non-trivial feature or making an architectural decision, add a new ADR.

## Releases

Use the `/release` slash command (defined in `.claude/commands/release.md`).
Two flows: **dev release** from `develop` (pre-release, optimistic next minor)
and **stable release** through a `release/vX.Y.Z` branch into `main`. A stable
release **must** finish with the back-merge of `main` → `develop` (Stage 4 in
the playbook); skipping it diverges the branches and makes the next release PR
conflict.

## Testing against real captures

Real PCAPs live in `tests/fixtures/` (gitignored). Public sources:

- [4SICS ICS Lab](https://www.netresec.com/?page=PCAP4SICS)
- [ICS-pcap](https://github.com/automayt/ICS-pcap)
- [ICSNPP test traces](https://github.com/cisagov/icsnpp)

When adding a finding, also add a snapshot test in `tests/snapshot.rs` that
exercises it with a deterministic `Observations` fixture — don't rely solely
on real PCAPs, which may not be reproducible across machines.

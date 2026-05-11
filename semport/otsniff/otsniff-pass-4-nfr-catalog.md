---
pass: 4
name: nfr-catalog
project: otsniff
generated: 2026-05-11T18:55:00Z
---

# Pass 4 — Non-Functional Requirements

## Performance

### NFR-PERF.001 — Single-pass observer
- **Property:** Each packet is touched exactly once. `Observer::observe` runs O(1) per packet (amortized), with bounded work in protocol parsers and per-host/flow accumulator updates.
- **Source:** `src/observe.rs::Observer::observe`.
- **Target:** Implied — keep linear in packet count, not super-linear.
- **Empirical:** 4SICS-22 capture (2.3M packets, ~209 MB) processes in <30s on Apple Silicon according to verbose-mode parsing line.
- **Status:** No formal benchmark; behavior verified anecdotally during release validation.

### NFR-PERF.002 — Bounded memory
- **Property:** Memory grows with **unique** hosts, flows, MAC pairs, and protocol events — not with raw packet count.
- **Source:** `src/observe.rs::Observations` uses `HashMap`/`BTreeMap` keyed by aggregation tuples; events are appended to `Vec`s with no per-packet duplication.
- **Bounded by:** number of distinct (src, dst, dst_port, proto) tuples + distinct cred lines + distinct SMB/TLS pairs.
- **Caveat:** `cred_events: Vec<CredEvent>` is NOT bounded — accumulates one entry per matching packet. For a long-running capture with continuous Telnet, this Vec can grow large. Acceptable for the v0.3 PCAP scope (capped file sizes).

### NFR-PERF.003 — Build profile optimizes for size + cold start
- **Property:** Release builds use `lto = "thin"`, `codegen-units = 1`, `strip = true`.
- **Source:** `Cargo.toml::[profile.release]`.
- **Effect:** Binary size ~2.5 MB stripped, single-file static, fast cold-start (no symbol resolution against runtime libs beyond libc).

### NFR-PERF.004 — Stream-hashed input
- **Property:** When computing the audit log's input PCAP SHA-256, the file is streamed in 64KB chunks rather than loaded into memory.
- **Source:** `src/audit.rs::sha256_file_hex` (64KB buffer in `read` loop).
- **Effect:** Hashing a 209MB PCAP doesn't allocate 209MB.

### NFR-PERF.005 — Linear-time pseudonym substitution
- **Property:** `scrub::scrub_text` does N passes through the input, one per pseudonym, with `String::replace`. Substitutions are sorted by descending length to avoid pseudonym overlap.
- **Source:** `src/scrub.rs::scrub_text`.
- **Caveat:** Quadratic in worst case if the map has many entries and the text is large. For v0.3 sizes (reports of a few KB to MB) it's fine. A future trie-based replacer would be needed for streaming AI responses.

## Security

### NFR-SEC.001 — Privacy invariant is the project's load-bearing security claim
- **Property:** No real value (IP, MAC, hostname) reaches the AI provider. Enforced by code, not convention.
- **Source:** `src/ai/leak_detector.rs` + `src/scrub.rs`, gated by `tests/snapshot.rs::invariant_no_real_values_reach_ai_provider`.
- **Failure mode:** A failed check returns `Err(OtError::Parse)` which exits 1 BEFORE the AI subprocess is invoked. Fail-closed.

### NFR-SEC.002 — Two-layer leak detection
- **Property:** Both regex check (IPv4 / IPv6 / MAC patterns) AND map-value check (exact match against every real value in the scrub map) must pass. The map-value check is primary for hostnames (no clean regex shape).
- **Source:** `src/ai/leak_detector.rs::ensure_clean` + `ensure_no_map_values`.

### NFR-SEC.003 — No unsafe code
- **Property:** Zero `unsafe` blocks in `src/`. CLAUDE.md convention requires a `// SAFETY:` justification for any introduction.
- **Source:** CLAUDE.md, verified by grep.

### NFR-SEC.004 — AI markdown XSS defense
- **Property:** Claude's markdown response is rendered to HTML with raw HTML events stripped (`Event::Html`, `Event::InlineHtml` filtered out of pulldown-cmark event stream). A response containing `<script>alert(1)</script>` cannot XSS whoever opens the resulting HTML report.
- **Source:** `src/ai/html_render.rs::render_safe`, gated by `tests/snapshot.rs::ai_section_in_html_strips_script_tags_from_claude_response`.

### NFR-SEC.005 — CIP-011 BCSI handling
- **Property:** Hostnames are classified as High-BCSI and scrubbed with `name_NNN` pseudonyms. The audit document `docs/audits/scrub-audit-cip011.md` walks every field on `Observations` and every rendered surface, classifying each.
- **Source:** ADR-0006 + `docs/audits/scrub-audit-cip011.md`.

### NFR-SEC.006 — Map file is the deanonymization key
- **Property:** The scrub map JSON contains every pseudonym → real value pair. Treated as a secret with the same threat model as the original PCAP.
- **Source:** `src/scrub.rs::ScrubMap`, documented in README + ADR-0006.
- **Operational:** `*.map.json` is gitignored.

### NFR-SEC.007 — CredEvent.note containment
- **Property:** `CredEvent.note` may contain literal credential bytes (FTP `USER` lines, b64'd HTTP Basic). Marked `#[serde(skip)]` so it cannot reach any JSON output. Sentinel test ensures it doesn't reach HTML, markdown, scrubbed, or per-event JSON either.
- **Source:** `src/observe.rs::CredEvent::note`, `tests/snapshot.rs::cred_event_note_must_not_reach_any_rendered_output`.

### NFR-SEC.008 — No HTTP or SDK
- **Property:** AI provider integration is exclusively via subprocess shell-out to the user's local `claude` CLI. No HTTP client, no Anthropic SDK linked. Removes a class of network-side attack surfaces.
- **Source:** ADR-0007.

### NFR-SEC.009 — Branch protection on long-lived branches
- **Property:** `main` and `develop` require PR + 5 status checks (Format, Clippy, Test ubuntu, MSRV, cargo-deny). No force push, no deletion.
- **Source:** GitHub branch protection (set via `gh api`).
- **Operational signal:** Direct push to main/develop is denied.

### NFR-SEC.010 — Vulnerability disclosure via private channel
- **Property:** `SECURITY.md` directs reporters to GitHub Security Advisories (private), not public issues.
- **Source:** `SECURITY.md`.

### NFR-SEC.011 — Sanitized input PCAP path in audit log
- **Property:** Audit log records the input PCAP path verbatim. A user running otsniff from a directory containing operator-identifying paths could leak metadata via the audit log.
- **Status:** Documented in `docs/audits/scrub-audit-cip011.md` as an acceptable trade-off (audit log is the user's own artifact, not shared externally).

## Observability

### NFR-OBS.001 — `--verbose` mode emits a privacy ledger
- **Property:** With `analyze --ai --verbose`, stderr prints the scrub counts, leak-check results, AI invocation timing, and unscrub stats as the run progresses. Allows operator to see the privacy contract holding in real time.
- **Source:** `src/cli.rs::run_analyze` verbose-print blocks.

### NFR-OBS.002 — Audit log is the post-run privacy receipt
- **Property:** Persistent JSON log with cryptographic chain-of-custody. Useful for compliance review.
- **Source:** `src/audit.rs::AuditLog`, populated in `run_analyze`.

### NFR-OBS.003 — Structured `--json` findings sidecar
- **Property:** `--json findings.json` emits a serializable representation of inventory + findings for downstream tooling (SIEM ingest, BI dashboards, etc.).
- **Source:** `src/cli.rs::write_optional_sidecars`.

### NFR-OBS.004 — Detection criteria inline in every fired finding
- **Property:** Each Finding's report rendering carries the plain-English `trigger` description from `RuleMetadata`, sourced via `metadata_for(finding.id)`. Lets operators read what fired the rule without leaving the report.
- **Source:** `src/report.rs::FindingView::trigger` (HTML), `src/report_md.rs` (markdown).

### NFR-OBS.005 — `otsniff rules` for catalog inspection
- **Property:** The catalog can be inspected without a PCAP. Useful for documentation, code review, and external reference.
- **Source:** `src/rule_catalog.rs`, `src/cli.rs::run_rules`.

## Reliability

### NFR-REL.001 — Deterministic output for identical input
- **Property:** Same PCAP + same flags → byte-identical HTML, markdown, JSON, scrub map (modulo timestamp metadata which is parameterized in tests).
- **Source:** `BTreeMap` over `HashMap` where iteration order matters; explicit `sort_by` in detector aggregation; pseudonym minting sorted by real value at map-build time.
- **Gated by:** every snapshot test.

### NFR-REL.002 — Fail-closed on privacy violation
- **Property:** Any leak detected → run aborts BEFORE AI invocation with a descriptive error. The wrong way to fail is silent.
- **Source:** `src/ai/leak_detector.rs::ensure_clean` returns `Err`, propagated through `?` in `run_analyze`.

### NFR-REL.003 — Sysexits-style exit codes
- **Property:** CLI exit codes are stable per error class. Documented in `src/error.rs::OtError::exit_code`.
- **Tests:** `tests/cli_smoke.rs` asserts exit code `2` for bad/missing input, `1` for other failures, `0` for success.

### NFR-REL.004 — Snapshot tests guard against output drift
- **Property:** 20 insta snapshot tests cover HTML, markdown, scrub map, JSON, scrubbed markdown, prompts. Any change to output format requires explicit `cargo insta review`.
- **Source:** `tests/snapshot.rs`.

### NFR-REL.005 — Sentinel tests guard cross-cutting invariants
- **Examples:**
  - `every_finding_has_a_non_empty_playbook`
  - `every_finding_id_appears_in_the_rule_catalog`
  - `every_rule_has_non_empty_metadata`
  - `rule_catalog_matches_committed_rules_md`
  - `invariant_no_real_values_reach_ai_provider`
  - `audit_log_rendered_for_an_analyze_run_carries_no_real_identifiers`
  - `ai_section_in_html_strips_script_tags_from_claude_response`
  - `cred_event_note_must_not_reach_any_rendered_output`
  - `finding_evidence_surfaces_hostnames_when_we_know_them`
- **Pattern:** Each sentinel guards an invariant that wouldn't be caught by snapshot tests alone.

### NFR-REL.006 — No `expect("…")` in production paths without comment
- **Property:** Code uses `expect("hardcoded CIDR is valid")` only on literals whose validity is checked at compile time. No runtime `unwrap()` on data-dependent values without a propagating `?`.
- **Source:** CLAUDE.md convention, verified by reading `src/`.

## Scalability

### NFR-SCALE.001 — Tested on 2.3M-packet capture
- **Property:** The 4SICS-22 capture (~209 MB, 2.3M packets) is the largest fixture in regular use. Produces 10 findings; runs in ~30s.
- **Source:** Local testing during release validation.

### NFR-SCALE.002 — Linear scaling target
- **Property:** Resource use should scale linearly with packet count. No quadratic-shaped algorithm in the parse loop.
- **Source:** Implicit from the single-pass observer design.

### NFR-SCALE.003 — Single-binary deployment
- **Property:** No agents, no daemon, no horizontal scaling. The unit of deployment is "drop the binary on a laptop, run once per PCAP."
- **Source:** Project scope per README + ADR-0001.

## Configuration values that encode NFR decisions

| Constant | Where | NFR encoded |
|---|---|---|
| `HOST_SIDE_DOMINANCE_THRESHOLD = 0.95` | `src/capture_source.rs:95` | Classifier accuracy (Sec) |
| `HOST_SIDE_SECOND_MAC_MAX = 0.30` | `src/capture_source.rs:102` | False-positive rate vs. SPAN traffic |
| `TAP_COVERAGE_THRESHOLD = 0.95` | `src/capture_source.rs:103` | Classifier accuracy |
| `SPAN_MIN_DISTINCT_MACS = 10` | `src/capture_source.rs:104` | Floor before declaring SPAN |
| `HIGH_CONFIDENCE_MIN_FRAMES = 1_000` | `src/capture_source.rs:106` | Confidence calibration |
| Evidence cap `take(15)` | every detector | Report readability (Obs) |
| Pseudonym format `name_NNN` with 3-digit padding | `src/scrub.rs::build_map_at` | Determinism (Rel) |
| PCAP reader buffer `1 << 20` (1 MiB) | `src/pcap.rs::iter_packets` | Memory budget (Perf) |
| File-hash buffer `64 * 1024` | `src/audit.rs::sha256_file_hex` | Memory budget (Perf) |
| OUI table entries (~50) | `src/oui.rs` | Vendor coverage (Obs); P0-6 to expand |
| `Severity::Critical..Info` (4 levels) | `src/findings/mod.rs::Severity` | Triage taxonomy (Obs) |

## Privacy / compliance posture (NFR cluster)

### NFR-PRIV.001 — Designed-to-align-with, not certified
- **Statement:** otsniff is designed to align with NERC CIP-011 BCSI handling principles and analogous frameworks (IEC 62443-3-3, TSA, NIS2). It is explicitly NOT a regulatory certification.
- **Source:** ADR-0006, README "Privacy contract" section.

### NFR-PRIV.002 — Audit document specifies the alignment claims
- **Source:** `docs/audits/scrub-audit-cip011.md`.

### NFR-PRIV.003 — Scrub-stance template gates new feature specs
- **Property:** Every new feature spec must answer four questions about its scrub stance (`docs/specs/scrub-stance-template.md`). The template is part of the process, not just documentation.

## What's NOT an NFR (deliberately)

- **No SLA.** otsniff doesn't have uptime/availability targets — it's not a service.
- **No telemetry.** No phone-home, no usage analytics. Pure local tool.
- **No internationalization.** English-only output.
- **No accessibility (a11y) requirements.** HTML reports use standard semantic HTML but no formal a11y target.
- **No backwards compatibility for the pseudonym scheme.** Adding a new pseudonym class (e.g. `user_NNN`) is an ADR-grade decision per ADR-0006 amendment.
- **No support contract or response SLA.** Solo-maintainer OSS.

These absences are intentional and consistent with the "small tool, not a platform" identity.

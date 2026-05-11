---
artifact_type: architecture-shard
shard: verification-architecture
project: otsniff
traces_to: ARCH-INDEX.md
---

# Verification Architecture

What's verified by which mechanism. This is the architecture shard
that Phase 0 surfaced as genuinely new — Pass 4 cataloged invariants
but didn't draw the verification-by-mechanism map.

## Verification mechanisms today

### Unit tests (`#[cfg(test)] mod tests` inline per file)

69 tests across the codebase. Cover:

- Pure-function behavior (parsers, scrub, leak detector regex, role inference)
- Edge cases per parser (malformed input rejection)
- Type-level invariants (CredKind enum totality, FlowKey hash equality)

### Integration tests (`tests/*.rs`)

| Test file | Count | Coverage |
|---|---:|---|
| `tests/cli_smoke.rs` | 11 | End-to-end binary tests via `assert_cmd` + `predicates`. Asserts: exit codes per OtError variant, help output content, scrub/unscrub round-trip, analyze succeeds on Modbus.pcap |
| `tests/snapshot.rs` | 20 | Insta snapshot tests + sentinel tests |

### Snapshot tests (subset of integration)

Output stability for: HTML report, markdown report, scrubbed
markdown, scrub map JSON, findings JSON, system prompt, default task,
per-source-tag prompt variants. Workflow: change output → fail →
`cargo insta review` → commit accepted snapshot with code change.

### Sentinel tests (cross-cutting invariants)

9 sentinels guard the load-bearing claims:

| Sentinel | Invariant guarded | BC |
|---|---|---|
| `invariant_no_real_values_reach_ai_provider` | Privacy invariant on the assembled AI-bound user_message + system_prompt | BC-5.02.003 |
| `audit_log_rendered_for_an_analyze_run_carries_no_real_identifiers` | Audit log contains no real identifiers | BC-7.01.003 |
| `ai_section_in_html_strips_script_tags_from_claude_response` | AI HTML rendering strips `<script>` and similar | BC-6.01.001 |
| `cred_event_note_must_not_reach_any_rendered_output` | `CredEvent.note` never reaches HTML / md / JSON | BC-7.02.001 |
| `every_finding_has_a_non_empty_playbook` | All detectors emit playbook content | BC-3.06.003 |
| `every_finding_id_appears_in_the_rule_catalog` | Catalog completeness | BC-3.06.002 |
| `every_rule_has_non_empty_metadata` | RuleMetadata fields populated | BC-3.06.002 |
| `rule_catalog_matches_committed_rules_md` | `docs/RULES.md` matches `findings::catalog()` | BC-8.02.001 |
| `finding_evidence_surfaces_hostnames_when_we_know_them` | host_label helper applied across detectors | BC-3.06.004 |

### CI quality gates

5 status checks required for merge to `main` / `develop`:

| Check | What it verifies |
|---|---|
| Format (rustfmt --check) | Stylistic consistency |
| Clippy (`-D warnings`) | Lint cleanliness |
| Test (ubuntu-latest) | All unit + integration tests pass |
| Test (macos-latest) | macOS-specific tests pass (post-public-flip restoration) |
| MSRV (1.85.0) | `cargo check` on the pinned toolchain |
| cargo-deny (licenses + advisories) | License compatibility + no known vulnerabilities |

### Branch protection

- `main` + `develop`: no force push, no deletion, PR required, 5 status checks must pass
- `factory-artifacts` orphan branch: relaxed (commits happen often without PR)

## Verification gaps (deferred or planned)

### Formal verification — Kani proofs (P1, L-P1-004)

Cargo-kani is on the deferred-install list. The five provable BCs
(from BC-INDEX § Provable Properties Catalog) are the highest-
leverage targets:

| BC | Property | Effort |
|---|---|---|
| BC-5.01.003 | Scrub round-trip exact | First proof; ~3 days (Kani learning + harness) |
| BC-5.02.001 | Leak regex saturation | ~1 day after BC-5.01.003 |
| BC-5.02.002 | Map-value substring search | ~1 day |
| BC-5.02.003 | Composed privacy invariant | Builds on the above; ~1 day |
| BC-6.01.001 | render_safe never emits raw HTML | Different shape; ~2 days |

Recommendation: ship BC-5.02.003 first (compositional proof of the
privacy invariant is the marketing-grade claim). The others can
follow as time permits.

### Mutation testing (P2)

`cargo-mutants`. Catches dead tests. Trade-off: noisy on a 6K-LoC
project; requires triage rules.

### Fuzz testing (P2)

`cargo-fuzz` for the 4 protocol parsers. Real value if otsniff ever
ingests untrusted PCAPs (external SOC submissions). Less valuable
for trusted plant captures.

### Performance benchmarks (P1, L-P1-003)

`criterion` + `hyperfine`. Today the NFR-PERF claims (single-pass,
linear memory, <60s on 209MB) are unmeasured. Regression signal
absent.

### Security scanning

`cargo-deny` runs in CI (licenses + advisories). `cargo audit` is
implicit in `cargo-deny` advisories check. `semgrep` is on the
deferred list.

## Verification coverage matrix

See `SS-verification-coverage-matrix.md` for the per-BC test mapping.

## Trade-offs in the verification posture

| Trade-off | Choice |
|---|---|
| Snapshot tests vs property tests | Snapshot — easier to read, easier to review changes via insta, easier to update intentionally |
| Per-function unit tests vs end-to-end snapshot | Both — unit tests for parser edge cases, snapshot for output stability |
| Kani proofs vs sentinel tests | Sentinel tests first (cheaper, exist today); Kani proofs as compliance posture upgrade (L-P1-004) |
| Mutation testing vs trust-the-tests | Trust the tests today; revisit after Phase 6 lands |
| Fuzz testing parsers vs trust-the-tests | Trust-the-tests at v0.3 scope (trusted captures); fuzz when adversarial input becomes a use case |
| Performance benchmarks vs anecdotal | Anecdotal today; L-P1-003 promotes to formal benchmarks |

## What this architecture does NOT verify

- **End-to-end Claude CLI integration.** No test invokes a real `claude` subprocess. The privacy invariant test exercises the leak detector with synthetic inputs but never reaches the AI provider. Integration test would require Claude credentials in CI — punted.
- **Cross-platform output identity.** Snapshot tests run on Linux + macOS but Windows path determinism is untested. The release workflow builds for Windows but doesn't run tests there.
- **Memory ceiling under adversarial input.** No bounded-memory benchmark on a capture with millions of unique IPs.
- **Per-platform install.sh behavior.** Shell script not exercised in CI.

These are knowable gaps; documented here rather than implied.

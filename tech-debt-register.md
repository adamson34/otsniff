# otsniff — Technical Debt Register

All entries are sourced from adversarial reviews, wave-gate findings, or
deliberate deferrals during story delivery. Each entry includes a suggested
fix location so implementers can act without re-reading review artifacts.

Priority: HIGH / MEDIUM / LOW
Status: OPEN / IN-PROGRESS / CLOSED

---

## OPEN entries

Sourced from ADV-P1 (2026-05-23, develop tip `7c98a3a`) and ADV-P2 (2026-05-24, develop tip `f8e34d7`). See `.factory/cycles/v0.4.0-feature/adversarial-reviews/pass-{1,2}.md` for full evidence + remediation per finding.

### ADV-P2 escalations + new findings (priority order)

| ID | Priority | Source | Status | Description | Suggested fix |
|---|---|---|---|---|---|
| F-ADV-P2-014 | HIGH | ADV-P2 | OPEN | **`perf.yml` uses `actions/upload-artifact@v7` — version does NOT exist; CI step fails silently if `if: always()`** | Pin to `@v4` (or current major). Add CI lint for action versions. |
| F-ADV-P2-001 | **CRITICAL** | ADV-P2 (escalation of F-ADV-P1-014) | OPEN | `javascript:`/`data:` URLs in AI-rendered markdown link → live href in shipped HTML report → data-exfil on user click | Post-process pulldown-cmark HTML to strip unsafe URL schemes from href attributes. Flip the test to assert stripping. |
| F-ADV-P2-002 | **CRITICAL** | ADV-P2 (escalation of F-ADV-P1-007) | OPEN | `run_diff` has no `ensure_clean` post-render; `ip_to_pseudo` falls back to raw IP string on map miss; mismatched/stale maps emit raw IPs into Diff output | Add `ensure_clean(&content)` + map-value sweep before `std::fs::write` in `run_diff`. Change fallback to hash-based opaque label and stderr-warn (or fail-closed in strict mode). |
| F-ADV-P2-003 | HIGH | ADV-P2 (partial F-ADV-P1-005) | OPEN | Composed Kani proof rewrite added vacuous-case + structural-soundness but the non-vacuous branch (where scrub actually replaced bytes) is still unasserted — the load-bearing case | Rewrite to assert: "for any input with at most one occurrence of real, after one replace_first_model pass, byte_contains_model(out, real) == false" |
| F-ADV-P2-004 | HIGH | ADV-P2 | OPEN | `OtError::Parse` used for leak/parse/CLI-arg/user-abort — exit code 70 indistinguishable; CI scripts can't branch on "leak vs render failure"; subsumes F-ADV-P2-021 (display says "pcap parse error:" for non-parse) | Add `OtError::PrivacyLeak { kind, pattern, byte_offset }` with distinct exit code (e.g. 75). Migrate leak_detector callsites. |
| F-ADV-P2-005 | HIGH | ADV-P2 (partial F-ADV-P1-004) | OPEN | `scrub_text` fuzz rewrite added non-empty map but discards output — `let _ = otsniff::scrub::scrub_text(&text, &map)` — no oracle | Run `ensure_no_map_values(&scrubbed, &map)` after `scrub_text`; panic on Err so libfuzzer records it |
| F-ADV-P2-007 | HIGH | ADV-P2 | OPEN | Leak-detector error message format echoes the leaked value into stderr → CI logs → world-readable for public repos. Different egress path than the AI provider but still a leak | Replace `'{}'` with `'<redacted len={}>'`; optional debug-gated diagnostic |
| F-ADV-P2-008 | HIGH | ADV-P2 | OPEN | Capture-source report_line() MAC can be unscrubbed when dominant MAC isn't in any host's `host.macs` list (passive observer, SVI/VRRP virtual). Defense-in-depth catches it but layered assertion fails on realistic input | When building scrub map, include every MAC in `obs.mac_frame_counts`, not just `host.macs` |
| F-ADV-P2-009 | HIGH | ADV-P2 | OPEN | PCAP path passed by user is fed verbatim into AI markdown header (`_Source: \`{path}\`_`) — leaks username + plant name + embedded IPs to AI | Use `args.input.file_name()` only OR drop path from AI-bound markdown (audit log already has SHA-256) |
| F-ADV-P2-015 | HIGH | ADV-P2 | OPEN | Tests gated on `tests/fixtures/*.pcap` existence silently no-op in CI (fixtures gitignored). "Passing" without doing anything | Commit synthetic PCAP fixture, OR fail when `pcap.exists() == false && env::var("CI").is_ok()` |
| F-ADV-P2-010 | MEDIUM | ADV-P2 | OPEN | DHCP hostname filter drops non-ASCII bytes silently — `LINE-3-Ümlaut` → `LINE-3-mlaut`; breaks merge-map identity; 1-letter survivors become regex-friendly scrub targets | Decode via `String::from_utf8_lossy`; reject if any control character or shorter than 2 graphemes |
| F-ADV-P2-012 | MEDIUM | ADV-P2 | OPEN | `ipv6_regex` blind to `::1`, `fe80::1`, `2001:db8::`, `::ffff:192.0.2.1`, zoned `fe80::1%eth0` — leak detector blind spot | Use `Ipv6Addr::from_str` on colon-containing tokens; add tests for the missed forms |
| F-ADV-P2-013 | MEDIUM | ADV-P2 | OPEN | `ensure_no_map_values` blocks on first hit; multi-leak inputs under-reported; substring matching false-positives on short (< 4 char) real values | Collect all leaks into Vec; iterate reverse-length order; skip real values < 4 chars |
| F-ADV-P2-016 | LOW | ADV-P2 | OPEN | `unscrub_text` regex unbounded digit suffix; `unmapped` uses O(n²) Vec::contains | Limit suffix to `[0-9]{1,9}`; use `HashSet<String>` for unmapped |
| F-ADV-P2-017 | LOW | ADV-P2 | OPEN | cargo-deny CI step has no positive-coverage assertion (extension of POL-11 theme) | Configure with explicit command + arguments; grep advisory-count line |
| F-ADV-P2-018 | LOW | ADV-P2 | OPEN | `--review-scrub` prints full scrubbed payload to stderr → terminal history / session logs (tmux/screen) capture it | Write payload to temp file; print path + first/last 20 lines |
| F-ADV-P2-019 | LOW | ADV-P2 | OPEN | `which_claude` skips Windows `.exe`/`.cmd`/`.bat` — false-negative pre-flight on shipped Windows target | Use `which` crate or expand candidate names on Windows |
| F-ADV-P2-020 | LOW | ADV-P2 | OPEN | ENIP `engineering_class_cip` heuristic sweeps fixed offset range; can flag benign CPF item bytes (0x05, 0x06, 0x07) as engineering services | Decode CPF item structure properly; restrict scan window |

### ADV-P1 still-OPEN (from 2026-05-23 pass)

| ID | Priority | Source | Status | Description | Suggested fix |
|---|---|---|---|---|---|
| F-ADV-P1-006 | MEDIUM | ADV-P1 | OPEN | `unscrub` writes the AI's response with no leak check — asymmetric to `analyze --ai` flow that guards going TO the AI | Run `leak_detector::ensure_clean(&output)` after `unscrub_text`; refuse to write or at minimum warn |
| F-ADV-P1-007 | MEDIUM | ADV-P1 | OPEN | Diff output is never `ensure_clean`-checked after rendering — relies entirely on `scrub_finding` being comprehensive (F-ADV-P1-003 shows it's not) | After rendering `content` in `run_diff`, run `ensure_clean` + `ensure_no_map_values` against both maps; fail closed |
| F-ADV-P1-008 | MEDIUM | ADV-P1 | OPEN | `diff::compute` disjoint-maps WARNING fires on legitimate first-runs and pollutes CI logs | Add `--disjoint-ok` opt-in OR tag the warning with a noise-suppression key |
| F-ADV-P1-009 | MEDIUM | ADV-P1 | OPEN | `scrub_text` longest-first sort handles containment for IPs but not pseudonyms-containing-pseudonyms; no post-sub assertion of leak-free output | Run `ensure_no_map_values(&out, map)` inside `scrub_text` and panic / return Err if a real value survives |
| F-ADV-P1-010 | MEDIUM | ADV-P1 | OPEN | `kani.yml` has no positive-coverage assertion — `continue-on-error: true` per harness means a silently-dropped harness can still report green (POL-11) | Compute harness count at runtime via `tojson`/`fromJSON`; emit `Check passed: N of M harnesses succeeded` |
| F-ADV-P1-011 | MEDIUM | ADV-P1 | OPEN | `fuzz.yml` has no positive-coverage assertion — `cargo fuzz run` success is exit-0 only (POL-11) | Grep stdout for `#NNN INITED` lines; assert at least one is present; emit `Check passed: harness $h ran $count executions` |
| F-ADV-P1-012 | LOW | ADV-P1 | OPEN | `recon.port_scan`'s `is_broadcast_or_multicast` only catches `255.255.255.255` — subnet-directed broadcast (`.255` on /24) is not excluded → false positives on NetBIOS browse traffic | Either skip last-octet `.255` heuristic, or reword rule trigger to clarify only limited-broadcast/multicast are excluded |
| F-ADV-P1-013 | MEDIUM | ADV-P1 | OPEN | `dnp3::parse` ignores frame `length` field and reads `payload[12]` as function code unconditionally — random bytes can mis-classify as engineering ops on short frames | Read length at offset 2, verify ≥5, compute application offset more carefully, reject if FIR bit not set on first segment |
| F-ADV-P1-014 | MEDIUM | ADV-P1 | OPEN | `render_safe` does NOT strip `javascript:` / `data:` URLs from markdown links — test asserts the opposite of its name | Add post-pass that walks generated HTML and replaces `href` values starting with `javascript:`/`data:`/`vbscript:` with `#`; flip the test |
| F-ADV-P1-015 | LOW | ADV-P1 | OPEN | `audit.path` JSON field contains the input PCAP's full path including user-home directory — chain-of-custody artifact leaks operator identity (POL-12 runtime variant) | Normalise to basename + SHA-256 (already present) OR add `--audit-anonymise-path` flag |
| F-ADV-P1-016 | LOW | ADV-P1 | OPEN | `pcap::iter_packets` silently drops non-Ethernet2 link types (VLAN-tagged trunks, 802.11) after first packet — incomplete inventory without warning | Either handle `LinkSlice::EthernetWithVlan`, or stderr-warn on first dropped frame |
| F-ADV-P1-017 | MEDIUM | ADV-P1 | OPEN | `scrub::merge_map` can `panic!` on a corrupted on-disk baseline map (EC-002 path) — should be `Err(OtError::Parse(...))` per existing error-handling convention | Replace `panic!` with `Err(OtError::Parse(...))`; treat scrub-map corruption as bad input (exit code 2) not a crash |
| F-ADV-P1-018 | LOW | ADV-P1 | OPEN | `scrub_finding` doesn't scrub `Finding.id` or `Finding.recommendation` — safe today (`&'static str`) but fragile to future field changes | Pair with F-ADV-P1-007 (post-render `ensure_clean`) for defense in depth, or add static_assertion on the field type |

---

## CLOSED entries

| ID | Priority | Source | Closed | Resolution |
|---|---|---|---|---|
| F-W1-001 | HIGH | Wave-1 adversarial review | 2026-05-21 (PR #86, 7d8413e) | Added `map.validate()?` after `serde_json::from_slice` in `run_unscrub`. CLI smoke test `test_f_w1_001_unscrub_rejects_corrupted_map` exercises the rejection path. |
| F-W1-002 | HIGH | Wave-1 adversarial review | 2026-05-22 (PR #87, 80a2e91) | Tightened `pseudonym_regex()` from `[0-9a-f]+` to `[0-9]+` to match `build_map`'s `{:03}` decimal output. New tests `test_f_w1_002_pseudonym_regex_rejects_hex_only_suffix` and `test_f_w1_002_decimal_pseudonym_not_in_map_is_still_unknown` cover the correctness gap and the strict-mode regression guard. |
| F-W1-003 | MEDIUM | Wave-1 adversarial review | 2026-05-22 (bundled PR fix/F-W1-003-004-scrub-cleanup) | Extended `ScrubMap::validate()` with a second pass that detects duplicate real-value entries across `ips`/`macs`/`names`. Three new tests cover same-family duplicates, cross-family duplicates, and the regression guard for unique-value maps. |
| F-W1-004 | MEDIUM | Wave-1 adversarial review | 2026-05-22 (bundled PR fix/F-W1-003-004-scrub-cleanup) | Wrapped `IPV4_RE`/`IPV6_RE`/`MAC_RE` in `std::sync::LazyLock` (stable since 1.80; MSRV 1.85). Regexes now compile exactly once per process instead of on every `scan()` call. Public regex-helper signatures changed to return `&'static Regex`. |
| F-W1-005 | MEDIUM | Wave-1 Kani stories (S-4.01..03) | 2026-05-20 (PR #84, f068948) | Kani CI workflow_dispatch executed; first run surfaced all 5 harnesses failed/timed out. Proof-model rewrite landed; all 6 harnesses now report `VERIFICATION:- SUCCESSFUL` on develop CI. |
| F-ADV-P1-001 | HIGH | ADV-P1 | 2026-05-23 (PR #99, f8e34d7) | Added `--ot-subnet` (repeatable) to the `Diff` clap variant; threaded into `run_diff`; calls `ot_or_default(&user_supplied)` instead of hardcoded RFC1918. Test `test_f_adv_p1_001_diff_documents_ot_subnet_flag` verifies the flag appears in `--help`. |
| F-ADV-P1-002 | HIGH | ADV-P1 | 2026-05-23 (PR #99, f8e34d7) | Added `compute_with_multiplier(input, input, multiplier)` as new public function; `compute()` is now a thin wrapper using `DEFAULT_FLOW_SHIFT_MULTIPLIER`. CLI passes user-supplied value directly to compute, removing the broken post-filter. Parse-time validation rejects multiplier < 1.0 or non-finite. Test `test_f_adv_p1_002_flow_shift_multiplier_below_default_retains_flows` verifies a 1.7× flow appears in `flow_shifts` when user passes 1.5. |
| F-ADV-P1-003 | HIGH | ADV-P1 | 2026-05-23 (PR #99, f8e34d7) | Changed `src/findings/ldap_creds.rs:93` evidence format from Unicode `→` to ASCII `->` for diff-extractor compatibility (matches the convention used by every other detector). Test `test_f_adv_p1_003_ldap_creds_evidence_uses_ascii_arrow` builds an LDAP bind fixture and asserts `->` present + `→` absent. |
| F-ADV-P1-004 | HIGH | ADV-P1 | 2026-05-23 (PR #99, f8e34d7) | Rewrote `fuzz/fuzz_targets/scrub_text.rs` to derive a small ScrubMap from fuzzer bytes (one fixed `host_000` entry guaranteeing substitution always runs + two carved-from-data entries). `validate()` map before scrubbing. Test `test_f_adv_p1_004_scrub_fuzz_harness_uses_non_empty_map` does structural check. |
| F-ADV-P1-005 | HIGH | ADV-P1 | 2026-05-23 (PR #99, f8e34d7) | Rewrote composed Kani harness to assert two non-trivial properties: (1) vacuous-case idempotence (scrub-then-scrub on clean input is identity) and (2) leak-detector structural soundness via slice-equality-based independent check (structurally different from `byte_contains_model`'s manual loop). Added preconditions matching production `build_map` invariants (real ⊄ pseudo, pseudo ⊄ real). Updated `docs/proofs/privacy-invariant.md` with "Honest scope" section acknowledging the rewrite and the deferred model-to-production gap (now covered by F-ADV-P1-004's working fuzz harness). |

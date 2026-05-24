# otsniff — Technical Debt Register

All entries are sourced from adversarial reviews, wave-gate findings, or
deliberate deferrals during story delivery. Each entry includes a suggested
fix location so implementers can act without re-reading review artifacts.

Priority: HIGH / MEDIUM / LOW
Status: OPEN / IN-PROGRESS / CLOSED

---

## OPEN entries

Sourced from ADV-P1 (2026-05-23, develop tip `7c98a3a`, full implementation review against 12-policy rubric). See `.factory/cycles/v0.4.0-feature/adversarial-reviews/pass-1.md` for full evidence + remediation per finding.

| ID | Priority | Source | Status | Description | Suggested fix |
|---|---|---|---|---|---|
| F-ADV-P1-001 | HIGH | ADV-P1 | OPEN | `otsniff diff` has no `--ot-subnet` flag → findings layer always uses RFC1918 defaults, mis-classifies severities in non-RFC1918 plants | Add `--ot-subnet` (repeatable) to Diff variant; thread into `run_diff`; call `ot_or_default(&user_supplied)` |
| F-ADV-P1-002 | HIGH | ADV-P1 | OPEN | `--flow-shift-multiplier <1.5` is silently no-op — `compute()` always uses 2.0 internally, post-filter can only raise threshold | Thread multiplier into `DiffInput`/`compute()` and apply user value inside the loop |
| F-ADV-P1-003 | HIGH | ADV-P1 | OPEN | LDAP creds finding uses Unicode `→` arrow but diff key extractors only match ASCII `->`; F-W2-004 fix is incomplete for this detector | Change `src/findings/ldap_creds.rs:93` to use `->` in evidence (keep `→` for display elsewhere if needed) |
| F-ADV-P1-004 | HIGH | ADV-P1 | OPEN | `scrub_text` fuzz harness uses empty `ScrubMap` — the actual substitution branch is never fuzzed | Construct symbolic map (e.g. one ASCII IP + one pseudonym derived from `data[0..n]`) so replacement path runs every input |
| F-ADV-P1-005 | HIGH | ADV-P1 | OPEN | Composed Kani proof asserts `byte_contains_model` against an identical hand-written brute-force — tautology; proves nothing about production `scrub_text`/`ensure_clean` | Either rewrite harness to scrub symbolic input through `replace_first_model` and assert leak-detector returns false, or reduce the documented claim to "self-consistency of leak-detector substring model" |
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

# Build / Test / Lint / Format Runs (AC-004, AC-005)

## `cargo build --workspace`

```
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
```

Clean build across all three workspace members (`otsniff`, `otsniff-privacy`,
`zonewarden`) — zero errors, zero warnings.

## `cargo test --workspace`

Full output tail (per-crate/per-test-binary results). Every `test result:`
line reports `0 failed`:

```
     Running tests/resolver_tests.rs (target/debug/deps/resolver_tests-...)

running 9 tests
test test_BC_1_03_001_network_address_resolves_normally ... ok
test test_BC_1_03_001_host_32_wins_over_net_24 ... ok
test test_BC_1_03_001_slash8_matches ... ok
test test_BC_1_03_002_ipv6_endpoint_ipv4_policy_is_external ... ok
test test_BC_1_03_005_one_external_is_cross_zone ... ok
test test_BC_1_03_005_both_external_yields_intra_zone ... ok
test test_BC_1_03_002_unmatched_resolves_to_external ... ok
test test_BC_1_03_001_longest_prefix_wins ... ok
test test_BC_1_03_001_resolution_deterministic_and_total ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/severity_tests.rs (target/debug/deps/severity_tests-...)

running 5 tests
test test_BC_1_04_009_attempted_states_map_to_attempted ... ok
test test_BC_1_04_009_established_states_map_to_established ... ok
test test_BC_1_04_009_full_13_state_table_correct ... ok
test test_BC_1_04_009_none_conn_state_defaults_to_established ... ok
test test_BC_1_04_009_unknown_state_is_other_and_grades_established ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/types_tests.rs (target/debug/deps/types_tests-...)

running 1 test
test test_BC_1_04_006_is_portless_by_proto ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/validator_tests.rs (target/debug/deps/validator_tests-...)

running 20 tests
test test_BC_1_01_004_external_reserved_id_rejected ... ok
test test_BC_1_01_004_duplicate_zone_id_rejected ... ok
test test_BC_1_01_004_conduit_unknown_zone_rejected ... ok
test test_BC_1_01_004_external_conduit_endpoint_ok ... ok
test test_BC_1_01_004_prefix_eight_emits_no_short_warning ... ok
test test_BC_1_01_004_short_prefix_warning_emitted ... ok
test test_BC_1_01_004_valid_policy_passes_no_warnings ... ok
test test_BC_1_01_004_validated_policy_contains_sorted_index ... ok
test test_BC_1_01_005_different_prefix_length_ok ... ok
test test_BC_1_01_005_disjoint_same_length_ok ... ok
test test_BC_1_01_005_host_tie_rejected ... ok
test test_BC_1_01_005_equal_prefix_tie_rejected ... ok
test test_BC_1_01_005_ipv4_mapped_member_ties_with_ipv4 ... ok
test test_BC_1_01_005_same_zone_duplicate_member_is_not_a_tie ... ok
test test_BC_1_01_006_catch_all_cidr_rejected ... ok
test test_BC_1_01_006_ipv4_mapped_96_catch_all_rejected ... ok
test test_BC_1_01_006_ipv6_catch_all_rejected ... ok
test test_BC_1_01_006_prefix_one_through_seven_not_error ... ok
test test_BC_1_01_008_zero_members_warn_not_error ... ok
test test_empty_policy_is_vacuously_valid ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests otsniff

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests otsniff_privacy

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests zonewarden

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Aggregated pass/fail count

Summing every `test result:` line across all 33 test binaries in the
workspace (`otsniff` lib + bin, `cli_smoke`, `fuzz_regressions`,
`ldap_creds`, `memory_bound`, `modbus_recon`, `ntlmv1`, `prompt_evals`,
`rdp_legacy`, `s_3_03_mutation_testing_infrastructure`,
`s_3_04_fuzz_infrastructure`, `s_4_04_composed_kani_proof`,
`s_6_02_diff_subcommand`, `s_8_01`, `snapshot`, `weak_tls_cipher`,
`zonewarden_cli`, `otsniff-privacy` lib, `zonewarden` lib +
`aggregator_tests`/`classifier_tests`/`digest_tests`/`errors_tests`/
`idmz_tests`/`multicast_tests`/`resolver_tests`/`severity_tests`/
`types_tests`/`validator_tests`, plus 3 doc-test targets):

```
total passed: 678
total failed: 0
```

The story's AC-005 requirement is: "full existing test suite (currently
669 tests per the last wave gate note) passes with the same count (modulo
any tests that move files but not content — count of test functions is
unchanged)." That requirement is about the *move itself*: the 17 tests
that relocated from `src/scrub.rs`/`src/ai/leak_detector.rs` into
`otsniff-privacy`'s own lib target are the same 17 test functions counted
in the 669 baseline — moving a test's file doesn't change the count, so
the move contributes zero to the delta.

The 669→678 delta (9 tests) is separate from the move, and is fully
accounted for by regression tests added during this story's adversarial
review cycles, on top of the unchanged 669 baseline:

- 4 `test_f_002_*` tests in `crates/otsniff-privacy/src/scrub.rs`
  (MapCorrupt-cause discrimination and the `u32`-overflow-guard regression).
- 5 error-boundary tests in `src/error.rs` (`privacy_wrapper_*` and
  `map_corrupt_*_is_routed_to_parse_not_privacy`) pinning the hand-written
  `From<otsniff_privacy::PrivacyError>` impl's routing and message shape.

Zero test functions were dropped anywhere in the move. In short: 678 = 669
(unchanged baseline, move-neutral) + 9 (net-new hardening tests from
review).

### AC-004/AC-005 note

No absolute filesystem paths appear anywhere in the `cargo build` or
`cargo test` output above — every path reported by cargo is relative
(`target/debug/deps/...`).

## `cargo clippy --workspace --all-targets --all-features -- -D warnings`

```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.16s
```

Zero warnings, zero errors — clean across all three workspace crates,
all targets (lib, bins, tests), all features.

## `cargo fmt --all -- --check`

```
(no output)
```

Exit code 0 — the entire workspace (including the new
`crates/otsniff-privacy`) is already formatted to the project's `rustfmt`
config; no diff produced.

# Red-Gate Log — S-9.01 (Multi-PCAP / rotated-capture analyze)

Branch: `feature/S-9.01-multi-pcap-analyze`
TDD mode: strict. Tests were written and observed FAILING (on assertions /
expected behavior) before the implementation that makes them pass.

Commit ordering (verified `git log develop..HEAD`):

| Order | Commit | Kind |
|---|---|---|
| 1 | `af5bbc6` | **test**(pcap): failing multi-iter + peek_link_type + mixed-type guard |
| 2 | `bff9367` | feat(pcap): iter_packets_multi + peek_link_type + link homogeneity guard |
| 3 | `d5d9126` | **test**(cli): failing multi-PCAP analyze smoke tests |
| 4 | `b0608ff` | feat(cli,audit): multi-PCAP analyze inputs + per-file audit attribution |
| 5 | `d8cc9d6` | style(pcap,cli): cargo fmt + clippy |

## Red gate 1 — `src/pcap.rs` (at commit `af5bbc6`, against stubs)

4 tests failed on assertions (not compile errors — stubs compiled):

```
peek_link_type_reads_legacy_network_field: assertion `left == right` failed
  left: None / right: Some(Linktype(1))
multi_iter_yields_packets_in_file_order: assertion `left == right` failed: expected 2 packets across the two files
  left: 0 / right: 2
multi_iter_mixed_link_types_are_rejected: panicked "expected MixedLinkTypes, got Ok"
missing_second_file_surfaces_error_after_first: panicked "expected first file's packet"
test result: FAILED. 4 passed; 4 failed
```

## Red gate 2 — `tests/cli_smoke.rs` (at commit `d5d9126`)

Multi-file analyze test failed against the still-single-file binary:

```
s_9_01_analyze_two_inputs_succeeds: code=2
error: unexpected argument '.../capture-02.pcap' found
Usage: otsniff analyze [OPTIONS] <INPUT>
test result: FAILED. 2 passed; 1 failed
```

(The zero-input and one-input tests passed pre-change, as EC-001/EC-002 require.)

## Red gate 3 — `src/audit.rs` schema bump

Serialization test failed with `SCHEMA_VERSION` temporarily held at 1:

```
input_pcaps_serializes_as_array_with_schema_v2: assertion `left == right` failed: schema_version must bump to 2
  left: 1 / right: 2
test result: FAILED. 3 passed; 1 failed
```

## Green (post-implementation, independently re-verified by orchestrator)

- `cargo fmt --all -- --check` → clean
- `cargo clippy --all-targets --workspace -- -D warnings` → clean (0 warnings)
- `cargo test --workspace` → all pass, 0 failed (301 lib + 24 cli_smoke + 86 snapshot + all integration/zonewarden suites)
- No `.snap.new` files; no `Cargo.toml` change; no `.factory/` change from the code branch.

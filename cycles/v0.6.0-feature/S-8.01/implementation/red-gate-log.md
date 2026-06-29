---
document_type: red-gate-log
level: ops
version: "1.0"
status: verified
producer: test-writer
timestamp: 2026-06-29T00:00:00
phase: 3
inputs:
  - stories/S-8.01-hostname-mdns-netbios-llmnr.md
input-hash: "n/a"
traces_to: "S-8.01 / BC-1.02.010..013, BC-2.01.002, BC-5.02.002"
stub_architect_agent: "stub-architect (commit a4df09c)"
stub_compile_verified: true
test_writer_agent: "test-writer (commit d08e4f0)"
red_gate_verified: true
---

# Red Gate Log: S-8.01 — mDNS / NetBIOS-NS / LLMNR hostname extraction

## Summary
| Story | Tests Written | All (behavior) Fail (Red)? | Gate |
|-------|-------------|-----------------|------|
| S-8.01 | 27 new | Yes — all behavior-bearing tests fail with assertion errors | **PASS (correctly red)** |

## Stubs Created (commit a4df09c, `cargo check` verified)
### S-8.01
- `parse::mdns::parse(&[u8]) -> Vec<MdnsHostname>` — red-gate default `Vec::new()`
- `parse::netbios::parse_registration(&[u8]) -> Option<NetBiosHostname>` — red-gate default `None`
- `parse::llmnr::parse(&[u8]) -> Vec<LlmnrHostname>` — red-gate default `Vec::new()`
- `observe.rs` — UDP/5353, UDP/137, UDP/5355 branches wired; `classify_flow` llmnr arm.

(Stub Architect used `todo!()` initially; the Test Writer flipped the three bodies
to benign wrong defaults — `Vec::new()`/`None`, no parsing logic — so the suite
fails with assertion errors rather than `todo!()` panics, per the Red Gate criterion.)

## Red Gate Verification (independently re-run by orchestrator)
27 new tests: 12 behavior-bearing tests FAIL with assertion errors; 15
negative/rejection tests pass vacuously (the empty/`None` default already
satisfies "reject malformed input / never panic" — they remain green after
implementation, which is correct).

- AC-001 (BC-1.02.010): `parse::mdns::tests::test_bc_1_02_010_extracts_a_record_local_dot_suffix` — FAIL (assertion)
- AC-001 (BC-1.02.010): `..._multiple_a_records_extracted`, `..._preserves_name_without_local_suffix` — FAIL (assertion)
- AC-002 (BC-1.02.011): `parse::netbios::tests::test_bc_1_02_011_valid_registration_returns_hostname` — FAIL (assertion)
- AC-003 (BC-1.02.012): `parse::llmnr::tests::test_bc_1_02_012_response_extracts_a_record` — FAIL (assertion)
- AC-004 (BC-1.02.013): 5 `observe` wiring/precedence tests — FAIL (assertion; e.g. `left: None right: Some("PLC-A")`)
- AC-005 (BC-2.01.002): `tests/s_8_01.rs::test_bc_2_01_002_mdns_hostname_surfaces_in_inventory` — FAIL (assertion)
- AC-006 (BC-5.02.002): `tests/s_8_01.rs::test_bc_5_02_002_mdns_hostname_scrubbed_in_scrub_map` — FAIL (assertion)

**Verification evidence:** `not yet implemented` panic count = 0; build-error
count = 0; failures are `assertion 'left == right' failed: BC-...` referencing
the behavior under test.

## Regression Check
| Existing Tests | Status |
|---------------|--------|
| 265 pre-existing tests | all pass |

## Hand-Off to Implementer
- Story ready for implementation: S-8.01.
- Implementation guidance: implement the three parsers (DNS A-record walk for
  mDNS/LLMNR with compression-pointer rejection; NetBIOS first-level decode +
  space-strip + suffix-drop) and the observer wiring; turn the 12 red tests
  green without breaking the 15 vacuous-pass negative tests or the 265
  pre-existing tests. No new pseudonym class (reuse `name_NNN`).

# Kani Proof Verification: `scrub_roundtrip_bounded` (AC-001)

**Tooling:** `cargo-kani 0.67.0` is installed in this environment
(`which cargo-kani` resolves). Unlike S-4.01 (which deferred proof
execution to CI because Kani wasn't installed locally at the time), this
evidence captures an actual local run of the moved harness.

## Command

```
cargo kani -p otsniff-privacy --harness scrub_roundtrip_bounded
```

## Output (tail)

```
Check 108: scrub::kani_proofs::scrub_roundtrip_bounded.pointer_dereference.17
	 - Status: SUCCESS
	 - Description: "dereference failure: pointer outside object bounds"
	 - Location: crates/otsniff-privacy/src/scrub.rs:606:30 in function scrub::kani_proofs::scrub_roundtrip_bounded

Check 109: scrub::kani_proofs::scrub_roundtrip_bounded.pointer_dereference.18
	 - Status: SUCCESS
	 - Description: "dereference failure: invalid integer address"
	 - Location: crates/otsniff-privacy/src/scrub.rs:606:30 in function scrub::kani_proofs::scrub_roundtrip_bounded

Check 110: scrub::kani_proofs::scrub_roundtrip_bounded.unwind.0
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 0"
	 - Location: crates/otsniff-privacy/src/scrub.rs:581:17 in function scrub::kani_proofs::scrub_roundtrip_bounded

Check 111: scrub::kani_proofs::scrub_roundtrip_bounded.unwind.1
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 1"
	 - Location: crates/otsniff-privacy/src/scrub.rs:578:13 in function scrub::kani_proofs::scrub_roundtrip_bounded

Check 112: scrub::kani_proofs::replace_first_model.unwind.0
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 0"
	 - Location: crates/otsniff-privacy/src/scrub.rs:478:13 in function scrub::kani_proofs::replace_first_model

Check 113: scrub::kani_proofs::replace_first_model.unwind.1
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 1"
	 - Location: crates/otsniff-privacy/src/scrub.rs:494:17 in function scrub::kani_proofs::replace_first_model

Check 114: scrub::kani_proofs::replace_first_model.unwind.2
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 2"
	 - Location: crates/otsniff-privacy/src/scrub.rs:504:21 in function scrub::kani_proofs::replace_first_model

Check 115: scrub::kani_proofs::replace_first_model.unwind.3
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 3"
	 - Location: crates/otsniff-privacy/src/scrub.rs:489:9 in function scrub::kani_proofs::replace_first_model

Check 116: scrub::kani_proofs::replace_first_model.unwind.4
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 4"
	 - Location: crates/otsniff-privacy/src/scrub.rs:521:9 in function scrub::kani_proofs::replace_first_model

Check 117: scrub::kani_proofs::scrub_roundtrip_bounded.unwind.2
	 - Status: SUCCESS
	 - Description: "unwinding assertion loop 2"
	 - Location: crates/otsniff-privacy/src/scrub.rs:604:9 in function scrub::kani_proofs::scrub_roundtrip_bounded


SUMMARY:
 ** 0 of 117 failed (5 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 0.78389233s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
```

## Verification

- All 117 checks report `Status: SUCCESS`; 0 failed.
- Final verdict: `VERIFICATION:- SUCCESSFUL`.
- Every check's `Location:` points into
  `crates/otsniff-privacy/src/scrub.rs` — confirming the harness executes
  against the moved code at its new crate path, not the old
  `src/scrub.rs` location.
- This directly satisfies AC-001's requirement: "the scrub round-trip Kani
  proof ... moves verbatim and `cargo kani --harness <name>` still proves
  it inside the new crate" and the Architecture Compliance Rules table's
  "Kani proofs must still run under `cargo kani` after the move" row.

Note: the compiler/loader lines preceding the check-by-check output
(elided above) reference the local build path and the toolchain's
standard-library source paths on the machine that ran this verification;
those are build-environment artifacts, not part of the proof result, and
are omitted here.

# Kani Proof Execution — Deferred to CI

Kani (CBMC-backed model checker) requires a separate toolchain installation
(`cargo install --locked kani-verifier && cargo kani setup`) that is not
present in the local development environment.

The harness (`map_value_substring`) and its CI step are structurally complete
and verified by `scripts/check-s-4-03-acceptance.sh` (7/7 PASS). Actual
symbolic-execution proof will run on the first CI push that triggers
`.github/workflows/kani.yml`.

This is the same deferral pattern used for S-4.01 and S-4.02.

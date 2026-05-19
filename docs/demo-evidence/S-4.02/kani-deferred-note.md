# Kani Execution — Deferred to CI

`cargo-kani` is not installed in the local recording environment. The proof harnesses (`leak_regex_ipv4`, `leak_regex_ipv6`, `leak_regex_mac`) are structurally verified by the acceptance script (12/12 PASS) and will be machine-checked on first CI run via `.github/workflows/kani.yml`.

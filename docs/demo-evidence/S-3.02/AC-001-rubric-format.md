# AC-001 Rubric Format — Evidence

## cargo test --test prompt_evals (last 15 lines)

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.13s
     Running tests/prompt_evals.rs (target/debug/deps/prompt_evals-473c49dee24f3e6f)

running 7 tests
test test_BC_6_02_001_multiple_assertions ... ok
test test_BC_6_02_001_must_assertion ... ok
test test_BC_6_02_001_must_not_assertion ... ok
test test_BC_6_02_001_rejects_malformed_input ... ok
test test_BC_6_02_001_should_assertion ... ok
test test_BC_6_02_001_skips_blank_lines_and_comments ... ok
test test_BC_AUDIT_013_parse_existing_rubric_files ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Eval directories and contents

```
tests/prompt-evals/ambiguous/
  observations.json
  rubric.md
  run.sh

tests/prompt-evals/host-side/
  observations.json
  rubric.md
  run.sh

tests/prompt-evals/span/
  observations.json
  rubric.md
  run.sh

tests/prompt-evals/tap/
  observations.json
  rubric.md
  run.sh
```

//! Smoke test for the prompt-eval rubric parser.
//! AC-002: invokes the parser in --dry-run mode, asserts rubric files parse without error.

#[derive(Debug)]
struct RubricAssertion {
    severity: AssertionSeverity,
    pattern: String,
}

#[derive(Debug, PartialEq)]
enum AssertionSeverity {
    Must,
    Should,
    MustNot,
}

fn parse_rubric(_text: &str) -> Result<Vec<RubricAssertion>, String> {
    todo!("S-3.02: rubric parser lands in step 4")
}

#[test]
fn placeholder_to_keep_test_file_alive() {
    // Will be replaced with real tests in Step 3
}

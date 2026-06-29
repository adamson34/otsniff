# AC-002 (BC-6.05.002) + AC-003 (BC-6.05.003): Augmented finding shape and dedup
#
# Demonstrates:
#   - AugmentedFinding {id, severity, title, evidence, confidence, reasoning}
#     with ai.* namespaced IDs (AC-002)
#   - JSON parser tolerates prose preamble/postamble (AC-002)
#   - Overlapping rule findings are dropped; disjoint ones survive (AC-003)
#
# Uses the mock-provider integration tests in tests/snapshot.rs, which drive
# augment_findings with deterministic canned responses. No live Claude CLI needed.

Output docs/demo-evidence/S-5.03/ac-002-003-shape-and-dedup.gif
Output docs/demo-evidence/S-5.03/ac-002-003-shape-and-dedup.webm

Set FontFamily "Andale Mono"
Set FontSize 14
Set Width 1280
Set Height 720
Set Framerate 30
Set PlaybackSpeed 1.0

Hide
Type "export CARGO_TERM_COLOR=always"
Enter
Sleep 0.3
Show

# AC-002: parser returns correct id/severity/confidence from well-formed JSON array
Type "cargo test --lib augment_parses_well_formed_json_array augment_id_namespace 2>&1 | tail -6"
Enter
Sleep 4

Type "clear"
Enter
Sleep 0.3

# AC-002: parser tolerates prose preamble/postamble around the JSON array
Type "cargo test --lib augment_tolerates_preamble_and_postamble 2>&1 | tail -6"
Enter
Sleep 4

Type "clear"
Enter
Sleep 0.3

# AC-003: rule finding takes precedence — overlapping augmented finding is dropped
Type "cargo test --test snapshot augment_dedup_rule_finding_takes_precedence 2>&1 | tail -6"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# AC-003: disjoint augmented finding survives dedup
Type "cargo test --test snapshot augment_dedup_disjoint_finding_survives 2>&1 | tail -6"
Enter
Sleep 6

Sleep 2

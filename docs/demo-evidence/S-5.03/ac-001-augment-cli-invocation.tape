# AC-001 (BC-6.05.001): AI-augmented findings — CLI surface
#
# Demonstrates that `otsniff analyze` documents the `--ai` flag and the
# augment pass as part of its help output. The --ai flag is the entry point
# that triggers the augment_findings call after run_all_findings + build_inventory.
#
# Substitution note: the `--ai` flag requires the real `claude` CLI and a live
# LLM. This demo records the documented interface surface only. The augment
# pipeline itself is exercised by the mock-provider integration tests shown in
# ac-002-003-shape-and-dedup.tape and ac-005-privacy-invariant.tape.

Output docs/demo-evidence/S-5.03/ac-001-augment-cli-invocation.gif
Output docs/demo-evidence/S-5.03/ac-001-augment-cli-invocation.webm

Set FontFamily "Andale Mono"
Set FontSize 14
Set Width 1280
Set Height 720
Set Framerate 30
Set PlaybackSpeed 1.0

Hide
Require ./target/release/otsniff
Type "export PATH=$PWD/target/release:$PATH"
Enter
Sleep 0.3
Show

# Highlight the augment-specific flags from analyze --help
Type "otsniff analyze --help 2>&1 | grep -A2 'Also run the AI'"
Enter
Sleep 2

Type "clear"
Enter
Sleep 0.3

# Show --ai flag and audit-log flag side by side
Type "otsniff analyze --help 2>&1 | grep -E '^\s+--ai|^\s+--audit-log' | head -4"
Enter
Sleep 2

Type "clear"
Enter
Sleep 0.3

# Confirm augment flag is in main help
Type "otsniff --help 2>&1 | grep -i analyze"
Enter
Sleep 2

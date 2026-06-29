# AC-005 (privacy invariant extends to augment path)
#
# Demonstrates that real IPs, MACs, and hostnames never reach the AI provider
# on the augment code path. The test injects canary identifiers into fixture
# observations, runs augment_findings with a mock provider that records its
# input, and asserts the canaries are absent — scrubbed to pseudonyms.
#
# Test: invariant_no_real_values_reach_ai_provider_augment (tests/snapshot.rs)

Output docs/demo-evidence/S-5.03/ac-005-privacy-invariant.gif
Output docs/demo-evidence/S-5.03/ac-005-privacy-invariant.webm

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

# Privacy invariant: canary IP/MAC/hostname must not reach AI provider (augment path)
Type "cargo test --test snapshot invariant_no_real_values_reach_ai_provider_augment 2>&1 | tail -4"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# Also show the analyze-path invariant (both paths enforced)
Type "cargo test --test snapshot invariant_no_real_values_reach_ai_provider 2>&1 | tail -4"
Enter
Sleep 6

Sleep 2

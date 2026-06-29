# AC-006: Audit log records augment-pass SHA-256 hashes separately
#
# Demonstrates that the AuditLog.augment_pass field is populated after an
# augment run, holding its own SHA-256 hashes (system_prompt, user_message,
# response) that are distinct from the analyze-pass hashes when the
# content differs (AUGMENT_PROMPT vs SYSTEM_PROMPT).
#
# Test: audit_log_records_augment_pass_hashes_separately (tests/snapshot.rs)

Output docs/demo-evidence/S-5.03/ac-006-audit-log.gif
Output docs/demo-evidence/S-5.03/ac-006-audit-log.webm

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

# Audit log: augment_pass field holds 64-char SHA-256 hashes distinct from analyze-pass
Type "cargo test --test snapshot audit_log_records_augment_pass_hashes_separately 2>&1 | tail -4"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# Error path (EC-004): augment failure after analyze success renders without augment section
Type "cargo test --test snapshot augment_failure_after_analyze_success_renders_without_augment 2>&1 | tail -4"
Enter
Sleep 6

Sleep 2

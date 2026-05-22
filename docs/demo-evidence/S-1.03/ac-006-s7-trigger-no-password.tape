Output docs/demo-evidence/S-1.03/ac-006-s7-trigger-no-password.gif
Output docs/demo-evidence/S-1.03/ac-006-s7-trigger-no-password.webm
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 420
Set Theme "Dracula"
Env PS1 "$ "
Require cargo

Hide
Type "clear"
Enter
Sleep 500ms
Show

Type "cargo test --lib findings::engineering_commands::tests::s7_metadata_trigger_does_not_mention_password -- --nocapture"
Sleep 500ms
Enter
Sleep 15s

Type "cargo run --release --quiet -- rules --format md 2>/dev/null | grep -A10 '^## .ics.s7_engineering' | head -10"
Sleep 500ms
Enter
Sleep 10s

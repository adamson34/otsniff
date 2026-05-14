Output docs/demo-evidence/S-1.03/ac-005-ot-default-ipv4-only.gif
Output docs/demo-evidence/S-1.03/ac-005-ot-default-ipv4-only.webm
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

Type "cargo test --lib cli::tests::ot_or_default_empty_input_returns_only_ipv4_rfc1918 -- --nocapture"
Sleep 500ms
Enter
Sleep 15s

Type "cargo run --release --quiet -- analyze --help 2>/dev/null | grep -A1 'ot-subnet'"
Sleep 500ms
Enter
Sleep 10s

Output docs/demo-evidence/S-2.09/ac-001-ntp-detection.gif
Output docs/demo-evidence/S-2.09/ac-001-ntp-detection.webm
Set FontSize 14
Set Width 1200
Set Height 480
Set Theme "Dracula"
Env PS1 "$ "
Require cargo

Hide
Type "clear"
Enter
Sleep 500ms
Show

Type "cargo test --test snapshot ntp_external -- --nocapture"
Sleep 500ms
Enter
Sleep 10s

Type "cargo run --release --quiet -- rules --format md 2>/dev/null | grep -A4 'boundary.ntp_external' | head -20"
Sleep 500ms
Enter
Sleep 5s

Output docs/demo-evidence/S-2.09/ec-003-multicast.gif
Output docs/demo-evidence/S-2.09/ec-003-multicast.webm
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

Type "cargo test --test snapshot ntp_external_flags_multicast_destination -- --nocapture"
Sleep 500ms
Enter
Sleep 10s

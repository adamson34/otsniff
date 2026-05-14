Output AC-001-002-lockdown-tests.gif
Output AC-001-002-lockdown-tests.webm
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 420
Set Theme "Dracula"
Env PS1 "$ "
Require cargo

Hide
Type "cd ../../../../"
Enter
Sleep 500ms
Show

Type "cargo test --lib unexpected_label"
Sleep 600ms
Enter
Sleep 10s

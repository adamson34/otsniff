Output docs/demo-evidence/S-9.01/EC-003-link-type-guard.gif
Output docs/demo-evidence/S-9.01/EC-003-link-type-guard.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 440
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0
Set WaitTimeout 30s

Require ./target/release/otsniff

Hide
Type "alias otsniff=./target/release/otsniff"
Enter
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Show

# EC-003 (BC-1.01.004): the link-layer homogeneity guard refuses to merge an
# Ethernet capture with a LINUX_SLL one — naming both files and types — rather
# than silently misparsing. Exit code 65 (EX_DATAERR).
Type "otsniff analyze docs/demo-evidence/S-9.01/fixtures/capture-part1.pcap docs/demo-evidence/S-9.01/fixtures/sll.pcap -o /tmp/x.html"
Sleep 300ms
Enter
Wait+Screen /differing link-layer types/
Sleep 800ms

Type "echo exit-code=$?"
Sleep 300ms
Enter
Wait+Screen /exit-code=65/
Sleep 2s

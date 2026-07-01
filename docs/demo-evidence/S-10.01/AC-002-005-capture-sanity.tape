Output docs/demo-evidence/S-10.01/AC-002-005-capture-sanity.gif
Output docs/demo-evidence/S-10.01/AC-002-005-capture-sanity.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 620
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

# AC-002/003/004 (BC-4.01.004/005): a degenerate capture (all-epoch timestamps)
# triggers a stderr WARNING and a report banner.
Type "otsniff analyze docs/demo-evidence/S-10.01/fixtures/epoch.pcap -o /tmp/epoch.html --md /tmp/epoch.md"
Sleep 300ms
Enter
Wait+Screen /WARNING/
Sleep 600ms

Type "grep -i 'timestamp warning' /tmp/epoch.md"
Sleep 300ms
Enter
Wait+Screen /timestamp warning/
Sleep 800ms

# AC-005: a sane capture (timestamps seconds apart, ascending) is silent — no
# WARNING, no banner — and the report is byte-identical to pre-S-10.01.
Type "otsniff analyze docs/demo-evidence/S-10.01/fixtures/sane.pcap -o /tmp/sane.html --md /tmp/sane.md"
Sleep 300ms
Enter
Wait+Screen /wrote/
Sleep 400ms

Type "grep -c 'timestamp warning' /tmp/sane.md"
Sleep 300ms
Enter
Wait+Screen /0/
Sleep 2s

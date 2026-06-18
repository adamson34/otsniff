Output docs/demo-evidence/S-6.03/EC-001-empty-diff.gif
Output docs/demo-evidence/S-6.03/EC-001-empty-diff.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 480
Set Padding 20
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0

Require ./target/release/otsniff

Hide
Type "export PS1='$ '"
Enter
Type "clear"
Enter
Show

# Diff a capture against itself — CLI summary shows 0 new hosts, 0 gone, 0 new findings, 0 resolved
Type "# Self-diff: same PCAP as both baseline and current"
Sleep 300ms
Enter

Type "otsniff diff \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/baseline.pcap \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/baseline.pcap \\"
Sleep 300ms
Enter
Type "  --baseline-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json \\"
Sleep 300ms
Enter
Type "  --current-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json \\"
Sleep 300ms
Enter
Type "  -o /tmp/ec001-self.html"
Sleep 300ms
Enter
Sleep 4s

# Confirm JSON also shows zero deltas
Type "otsniff diff \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/baseline.pcap \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/baseline.pcap \\"
Sleep 300ms
Enter
Type "  --baseline-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json \\"
Sleep 300ms
Enter
Type "  --current-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json \\"
Sleep 300ms
Enter
Type "  -o /tmp/ec001.json && jq '{hosts_new,hosts_gone,findings_new,findings_resolved}' /tmp/ec001.json"
Sleep 300ms
Enter
Sleep 5s

Sleep 2s

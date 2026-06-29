Output docs/demo-evidence/S-6.03/AC-002-markdown-renderer.gif
Output docs/demo-evidence/S-6.03/AC-002-markdown-renderer.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 600
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

# Produce the markdown diff report
Type "otsniff diff \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/baseline.pcap \\"
Sleep 300ms
Enter
Type "  docs/demo-evidence/S-6.03/fixtures/current.pcap \\"
Sleep 300ms
Enter
Type "  --baseline-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json \\"
Sleep 300ms
Enter
Type "  --current-map docs/demo-evidence/S-6.03/fixtures/current-map.json \\"
Sleep 300ms
Enter
Type "  -o /tmp/ac002-diff.md"
Sleep 300ms
Enter
Sleep 4s

# Show the rendered markdown content
Type "cat /tmp/ac002-diff.md"
Sleep 300ms
Enter
Sleep 3s

Sleep 2s

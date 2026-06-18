Output docs/demo-evidence/S-6.03/AC-003-determinism.gif
Output docs/demo-evidence/S-6.03/AC-003-determinism.webm

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

# Run the renderer twice on identical inputs
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
Type "  -o /tmp/run1.html 2>/dev/null"
Sleep 300ms
Enter
Sleep 3s

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
Type "  -o /tmp/run2.html 2>/dev/null"
Sleep 300ms
Enter
Sleep 3s

# Compare: no output = byte-identical
Type "cmp /tmp/run1.html /tmp/run2.html && echo 'IDENTICAL: byte-for-byte match confirmed'"
Sleep 300ms
Enter
Sleep 2s

Sleep 2s

Output docs/demo-evidence/S-6.03/AC-001-html-renderer.gif
Output docs/demo-evidence/S-6.03/AC-001-html-renderer.webm

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

# Produce the HTML diff report
Type "otsniff diff docs/demo-evidence/S-6.03/fixtures/baseline.pcap docs/demo-evidence/S-6.03/fixtures/current.pcap --baseline-map docs/demo-evidence/S-6.03/fixtures/baseline-map.json --current-map docs/demo-evidence/S-6.03/fixtures/current-map.json --flow-shift-multiplier 1.1 -o /tmp/ac001.html"
Sleep 300ms
Enter
Sleep 5s

# Show the section headings present in the rendered HTML
Type "grep -o 'class..stat[a-z -]*' /tmp/ac001.html | sort -u"
Sleep 300ms
Enter
Sleep 2s

Type "grep -n 'h2' /tmp/ac001.html"
Sleep 300ms
Enter
Sleep 2s

Sleep 2s

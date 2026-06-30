Output docs/demo-evidence/S-12.01/AC-001-004-mitre-mapping.gif
Output docs/demo-evidence/S-12.01/AC-001-004-mitre-mapping.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 13
Set Width 1280
Set Height 720
Set Padding 20
Set TypingSpeed 38ms
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

# AC-002/003/004 (BC-8.05.001): each finding surfaces its MITRE ATT&CK for ICS
# techniques as links, in HTML, markdown, and JSON.
Type "otsniff analyze tests/fixtures/synthetic-1mb.pcap -o /tmp/r.html --md /tmp/r.md --json /tmp/r.json"
Sleep 300ms
Enter
Wait+Screen /findings/
Sleep 500ms

Type "grep -A1 'MITRE ATT' /tmp/r.md"
Sleep 300ms
Enter
Wait+Screen /attack.mitre.org/
Sleep 1s

Type "jq -c '.findings[].mitre_techniques' /tmp/r.json"
Sleep 300ms
Enter
Wait+Screen /T0836/
Sleep 1s

# AC-001 (BC-3.06.006): the rule catalog now maps every detection rule —
# including the 7 newly-mapped ones (credentials, SMBv1, TLS, DNS, NTP).
Type "otsniff rules | grep 'MITRE' | sort -u"
Sleep 300ms
Enter
Wait+Screen /Connection Proxy/
Sleep 2s

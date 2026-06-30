Output docs/demo-evidence/S-9.01/AC-001-002-multi-pcap-union.gif
Output docs/demo-evidence/S-9.01/AC-001-002-multi-pcap-union.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 600
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

# AC-001/002/005 (BC-1.01.003): two rotated captures analyzed as one logical
# capture. part1 = hosts .10/.20, part2 = hosts .30/.40 — the union is 4 hosts.
Type "otsniff analyze docs/demo-evidence/S-9.01/fixtures/capture-part1.pcap docs/demo-evidence/S-9.01/fixtures/capture-part2.pcap -o /tmp/s901-report.html --json /tmp/s901-findings.json"
Sleep 300ms
Enter
Wait+Screen /4 hosts/
Sleep 800ms

# The union inventory carries hosts from BOTH captures — no mergecap needed.
Type "jq -r '.inventory[].ip' /tmp/s901-findings.json | sort"
Sleep 300ms
Enter
Wait+Screen /192.168.10.40/
Sleep 2s

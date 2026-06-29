Output docs/demo-evidence/S-8.01/AC-001-005-hostname-extraction.gif
Output docs/demo-evidence/S-8.01/AC-001-005-hostname-extraction.webm

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

# AC-001/002/003/004/005: mDNS + NetBIOS-NS + LLMNR hostname extraction
# Synthetic PCAP: mDNS A-record (HMI-LINE-3.local.), NBNS Registration
# (PLC-LINE3), LLMNR A-record response (ENG-WS-01).
Type "otsniff analyze docs/demo-evidence/S-8.01/fixtures/hostname-extraction.pcap -o /tmp/s801-report.html --json /tmp/s801-findings.json"
Sleep 300ms
Enter
Wait+Screen /wrote/
Sleep 500ms

# Show all extracted hostnames from the JSON inventory
Type "jq '.inventory[] | select(.hostname) | {ip,hostname}' /tmp/s801-findings.json"
Sleep 300ms
Enter
Wait+Screen /ENG-WS-01/
Sleep 2s

Output docs/demo-evidence/S-8.01/EC-001-malformed-graceful.gif
Output docs/demo-evidence/S-8.01/EC-001-malformed-graceful.webm

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

# EC-001 / edge path: truncated mDNS header + LLMNR compression pointer +
# NBNS wrong OPCODE -- all silently discarded; analyze exits 0.
Type "otsniff analyze docs/demo-evidence/S-8.01/fixtures/malformed-hostname.pcap -o /tmp/s801-malformed.html --json /tmp/s801-malformed.json && echo 'exit: 0'"
Sleep 300ms
Enter
Wait+Screen /exit: 0/
Sleep 500ms

# Confirm no hostnames were extracted from the malformed packets
Type "jq '[.inventory[].hostname] | map(select(. != null)) | length' /tmp/s801-malformed.json"
Sleep 300ms
Enter
Wait+Screen /[0-9]/
Sleep 2s

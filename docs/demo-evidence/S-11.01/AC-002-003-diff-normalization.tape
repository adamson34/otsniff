Output docs/demo-evidence/S-11.01/AC-002-003-diff-normalization.gif
Output docs/demo-evidence/S-11.01/AC-002-003-diff-normalization.webm

Set Theme "Dracula"
Set FontFamily "Menlo"
Set FontSize 13
Set Width 1280
Set Height 700
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
Type "F=docs/demo-evidence/S-11.01/fixtures"
Enter
# Mint a scrub map per capture (pseudonyms line up — same IPs, deterministic minting).
Type "otsniff scrub $F/base.pcap -o /tmp/b.md --map /tmp/b.map.json >/dev/null 2>&1"
Enter
Type "otsniff scrub $F/curr_steady.pcap -o /tmp/cs.md --map /tmp/cs.map.json >/dev/null 2>&1"
Enter
Type "otsniff scrub $F/curr_realshift.pcap -o /tmp/cr.md --map /tmp/cr.map.json >/dev/null 2>&1"
Enter
Type "clear"
Enter
Show

# AC-002/003: a STEADY flow over unequal capture windows (base 3900s vs current
# 1800s) — raw bytes differ ~2×, but the per-second RATE is unchanged. It must
# NOT be reported as a shift, and the window mismatch is flagged.
Type "otsniff diff $F/base.pcap $F/curr_steady.pcap --baseline-map /tmp/b.map.json --current-map /tmp/cs.map.json -o /tmp/A.json"
Sleep 300ms
Enter
Wait+Screen /windows differ/
Sleep 700ms

Type "jq '.flow_shifts | length' /tmp/A.json"
Sleep 300ms
Enter
Wait+Screen /0/
Sleep 1s

# AC-002 (EC-005): the SAME flow with a genuine rate doubling (4 packets over
# 1800s instead of 3900s) — identical raw bytes (48 → 48) yet correctly flagged
# at ~2.17× because the per-second rate doubled.
Type "otsniff diff $F/base.pcap $F/curr_realshift.pcap --baseline-map /tmp/b.map.json --current-map /tmp/cr.map.json -o /tmp/B.json"
Sleep 300ms
Enter
Wait+Screen /windows differ/
Sleep 700ms

Type "jq -c '.flow_shifts[0] | {baseline_bytes, current_bytes, ratio}' /tmp/B.json"
Sleep 300ms
Enter
Wait+Screen /2.16/
Sleep 2s

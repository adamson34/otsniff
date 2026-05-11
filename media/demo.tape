## otsniff demo tape — regenerate the README GIF with:
##
##     brew install vhs
##     cargo install --path . --force    # ensure fresh dev binary on PATH
##     # Drop the public 4SICS day-1 capture at media/demo.pcap:
##     curl -L -o media/demo.pcap \
##       https://www.netresec.com/pcap/4SICS-GeekLounge-151020.pcap
##     vhs media/demo.tape
##
## `media/demo.pcap` is gitignored — the tape ships in-repo, the
## rendered GIF ships in-repo, the input PCAP does not.
##
## Privacy notes for the recording:
##   - PS1 is forced to `$ ` so the captured frames never show
##     hostname / username.
##   - All commands run from `media/` so the visible cwd is short
##     and contains no $HOME.
##   - `analyze` is intentionally NOT in this demo — it would shell
##     out to `claude` and surface the operator's auth + response.

Output media/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Width 1200
Set Height 720
Set Padding 20
Set TypingSpeed 30ms
Set PlaybackSpeed 1.0

## Hide everything before the first visible command: set a minimal
## prompt, cd into the media/ folder, clear the screen. vhs >=0.7
## supports Hide/Show; commands between them run in the shell but
## are not drawn to the canvas.
Hide
Type "export PS1='$ '"
Enter
Type "export PATH=$HOME/.cargo/bin:$PATH"
Enter
Type "cd media"
Enter
Type "clear"
Enter
Show

## --- 1. Version sanity check -----------------------------------------
Type "otsniff --version"
Sleep 400ms
Enter
Sleep 1.5s

## --- 2. Show the rule catalog (truncated for the GIF) ----------------
Type "otsniff rules --format md | head -22"
Sleep 400ms
Enter
Sleep 3.5s

Hide
Type "clear"
Enter
Show

## --- 3. Run the rules-based report on a public capture ---------------
##     Default OT zone is RFC1918 (10/8, 172.16/12, 192.168/16), which
##     matches the 4SICS demo network and exercises every cross-zone
##     finding. Use `--ot-subnet <CIDR>` repeatedly on real captures to
##     pin OT to specific PLC ranges.
Type "otsniff report demo.pcap -o demo.report.html --json demo.json --verbose"
Sleep 400ms
Enter
Sleep 4s

Hide
Type "clear"
Enter
Show

## --- 4. Peek at the findings via the JSON sidecar --------------------
Type "jq '.findings[] | {id, severity, title}' demo.json"
Sleep 400ms
Enter
Sleep 5s

## --- 5. Hold the final frame so the loop pause is readable ----------
Sleep 2s

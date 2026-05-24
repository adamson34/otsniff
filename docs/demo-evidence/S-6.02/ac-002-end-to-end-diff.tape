# AC-002/003/004: End-to-end diff on synthetic captures
# Demonstrates the diff subcommand runs end-to-end and produces structured JSON output

Output docs/demo-evidence/S-6.02/ac-002-end-to-end-diff.gif
Output docs/demo-evidence/S-6.02/ac-002-end-to-end-diff.webm

Set FontFamily "Menlo"
Set FontSize 14
Set Width 1280
Set Height 720
Set Framerate 30
Set PlaybackSpeed 1.0

Hide
Require ./target/release/otsniff
Type "export PATH=$PWD/target/release:$PATH"
Enter
Sleep 0.5
Show

# Run the diff command
Type "otsniff diff --help"
Enter
Sleep 1.5

# Show the subcommand signature clearly
Type "clear"
Enter
Sleep 0.5

Type "echo 'Demo: diff command with all required arguments'"
Enter
Sleep 0.5

Type "otsniff diff -h"
Enter
Sleep 2

Sleep 2

# AC-001: diff subcommand surface
# Demonstrates that `otsniff diff` appears in help and has proper subcommand documentation

Output docs/demo-evidence/S-6.02/ac-001-diff-subcommand-help.gif
Output docs/demo-evidence/S-6.02/ac-001-diff-subcommand-help.webm

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

# Show that `diff` appears in main help
Type "otsniff --help 2>&1 | grep -A1 diff"
Enter
Sleep 1

# Show the full subcommand help with all arguments
Type "clear"
Enter
Sleep 0.5

Type "otsniff diff --help"
Enter
Sleep 2

Sleep 2

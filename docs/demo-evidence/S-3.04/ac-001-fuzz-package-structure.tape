#!/usr/bin/env vhs

# Demo: AC-001 — fuzz/ directory + 6 harnesses
# Shows the fuzz package structure and confirms all 6 harness files exist
# Coverage: AC-001 (fuzz/ directory + harnesses) and AC-003 (corpus seeding readiness)

Output "ac-001-fuzz-package-structure.gif"
Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Padding 10
Set Margin 20
Set Width 1280
Set Height 720

# Clear and show current directory
Type "clear"
Enter
Sleep 500ms

Type "# Demo: AC-001+003 — fuzz package structure and corpus seeding"
Enter
Sleep 500ms

Type "# Step 1: List all fuzz_targets source files (6 harnesses required)"
Enter
Sleep 400ms

Type "ls -1 fuzz/fuzz_targets/"
Enter
Sleep 2s

Type "# Step 2: Confirm fuzz/ is a valid Cargo package"
Enter
Sleep 400ms

Type "cat fuzz/Cargo.toml | head -10"
Enter
Sleep 2s

Type "# Step 3: Show corpus seeding policy (AC-003)"
Enter
Sleep 400ms

Type "head -20 fuzz/README.md"
Enter
Sleep 2s

Sleep 2s

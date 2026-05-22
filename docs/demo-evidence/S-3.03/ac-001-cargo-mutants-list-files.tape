#!/usr/bin/env vhs

# Demo: AC-001 — cargo-mutants config scope verification
# Shows that .cargo-mutants.toml restricts mutations to high-value modules
# Expected output: only src/findings/, src/parse/, src/scrub.rs, src/ai/leak_detector.rs

Output "ac-001-cargo-mutants-list-files.gif"
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

Type "# Demo: AC-001 — cargo-mutants file scope"
Enter
Sleep 500ms

Type "# The .cargo-mutants.toml restricts mutations to 4 high-value modules:"
Enter
Type "# src/findings/, src/parse/, src/scrub.rs, src/ai/leak_detector.rs"
Enter
Sleep 500ms

Type "cargo mutants --list-files 2>&1 | head -30"
Enter
Sleep 3s

Sleep 2s

# AC-004 (BC-3.07.001): AI-augmented findings HTML + Markdown render section
#
# Demonstrates:
#   - HTML report has a dedicated "AI-augmented findings" section (render_augmented_section)
#   - Markdown report has equivalent section (render_augmented_section_md)
#   - Empty findings produce no heading (omit-when-empty behavior)
#
# Uses snapshot tests that call render_augmented_section / render_augmented_section_md
# directly with fixture data. The insta snapshot files pin the rendered shape.

Output docs/demo-evidence/S-5.03/ac-004-render-section.gif
Output docs/demo-evidence/S-5.03/ac-004-render-section.webm

Set FontFamily "Andale Mono"
Set FontSize 14
Set Width 1280
Set Height 720
Set Framerate 30
Set PlaybackSpeed 1.0

Hide
Type "export CARGO_TERM_COLOR=always"
Enter
Sleep 0.3
Show

# HTML section present when findings exist
Type "cargo test --test snapshot html_report_contains_augmented_section_when_present 2>&1 | tail -4"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# HTML section omitted when findings are empty
Type "cargo test --test snapshot html_report_omits_augmented_section_when_empty 2>&1 | tail -4"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# Markdown section present
Type "cargo test --test snapshot markdown_report_contains_augmented_section_when_present 2>&1 | tail -4"
Enter
Sleep 6

Type "clear"
Enter
Sleep 0.3

# Snapshot tests pin the exact rendered shape (HTML + markdown)
Type "cargo test --test snapshot augmented_findings_html_section_snapshot augmented_findings_markdown 2>&1 | tail -5"
Enter
Sleep 6

Sleep 2

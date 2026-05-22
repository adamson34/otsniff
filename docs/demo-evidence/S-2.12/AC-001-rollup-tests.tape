Output AC-001-rollup-tests.gif
Set FontFamily "Menlo"
Set FontSize 14
Set Width 1200
Set Height 420
Set Theme "Dracula"

Hide
Type "export PS1='$ '"
Enter
Type "export PATH=$HOME/.cargo/bin:$PATH"
Enter
Type "cd ../../.."
Enter
Type "clear"
Enter
Show

Type "cargo test --test snapshot recon_port_scan 2>&1 | grep -E 'recon_port_scan|test result'"
Sleep 600ms
Enter
Sleep 10s

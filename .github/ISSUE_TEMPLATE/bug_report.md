---
name: Bug report
about: Something doesn't work as documented
labels: bug
---

## What happened

<!-- One-paragraph description. Include the exact command if relevant. -->

## What you expected

<!-- What the README, ROADMAP, or ADR led you to expect. -->

## Reproduce

```sh
# Exact command(s)
otsniff ...
```

## Environment

- otsniff version: <!-- output of `otsniff --version` -->
- OS / arch: <!-- e.g., macOS 15 arm64 / Ubuntu 24.04 x86_64 -->
- Rust version (if built from source): <!-- output of `rustc --version` -->
- Claude Code version (if `analyze` is involved): <!-- output of `claude --version` -->

## Capture

<!-- If this is a parser / finding / classification issue, please attach
     a small PCAP that reproduces it. Public 4SICS captures are ideal.
     Do NOT attach captures from real plant networks. If you only have
     a private capture, run `otsniff scrub` first and attach the
     scrubbed.md output instead. -->

## Additional context

<!-- Logs, screenshots, etc. -->

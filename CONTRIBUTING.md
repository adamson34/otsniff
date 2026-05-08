# Contributing to otsniff

Thanks for considering it. This project is small and opinionated; the
guardrails below exist to keep it that way.

## Before you start

Read these in order:

1. [README.md](README.md) — what the tool is and what it isn't.
2. [docs/ROADMAP.md](docs/ROADMAP.md) — what's planned, what's
   explicitly *not* in scope, and the honest gaps.
3. [CLAUDE.md](CLAUDE.md) — architecture, conventions, and the
   project's design contract.
4. [docs/adr/](docs/adr/) — the load-bearing decisions.

If your idea is in "Explicitly not in scope" in the roadmap, please
don't open a PR for it. Open an issue first to discuss whether the
non-goal should change (it can — but it's an ADR-grade conversation).

## Workflow

- **Default branch is `develop`.** `main` is releases.
- **Feature branches:** `type/short-description` (e.g.,
  `feat/dnp3-parser`, `fix/oui-coverage`, `docs/contributing-update`).
- **Conventional Commits** for messages: `feat:`, `fix:`, `docs:`,
  `chore:`, `ci:`, `test:`, `refactor:`. Subject + optional body. No
  trailers required.
- **Spec before implementation.** For non-trivial features, write
  `docs/specs/<your-feature>.md` first describing scope, design, and
  what's NOT in scope. PR the spec early if you want feedback before
  coding.
- **One PR per logical change.** Squash-merge into `develop`.
- **Releases** go through `develop → main` via the `/release`
  slash-command flow (see `.claude/commands/release.md`).

## Quality gates

PRs must pass:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
```

Plus the MSRV check on Rust 1.85.0. CI runs all of these on every PR.

## Tests

- **Unit tests** inline (`#[cfg(test)] mod tests`) close to the code
  they cover.
- **Integration tests** in `tests/` using `assert_cmd` for CLI smoke
  and `insta` for snapshots.
- **The privacy invariant test** (`invariant_no_real_values_reach_ai_provider`)
  is non-negotiable. If your change touches the AI / scrub / leak-detector
  path and breaks that test, fix the implementation, not the test.
- New parsers must include unit tests with raw byte fixtures, plus at
  least one negative-case test (rejects malformed input).
- New detectors must include a snapshot test that exercises the
  detector on the deterministic fixture in `tests/snapshot.rs`.

## What's intentionally NOT in scope

Repeated for emphasis (see roadmap for full list):

- Live capture / sniffing / agent mode
- Vendor cloud integration
- Audit-grade compliance certification
- General-purpose IT triage
- SIEM / IDS event-stream integration

PRs targeting these will be closed.

## Privacy / NERC CIP discipline

If your change touches anything in the AI / scrub / leak-detector path,
your spec must declare its scrub stance — what new identifier types
your code extracts or renders, and how each is scrubbed before reaching
an AI provider. The leak detector exists to catch bugs in scrubbing;
it's a safety net, not a substitute for getting scrubbing right at
extraction time.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Don't file public issues for security bugs.

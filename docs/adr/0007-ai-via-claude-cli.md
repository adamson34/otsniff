# ADR-0007: AI integration via the Claude Code CLI

## Status
Accepted (v0.3)

## Context
v0.2 shipped the scrub/unscrub layer that makes AI-assisted OT triage
*safe*. v0.3 closes the loop: actually invoke an AI from inside otsniff,
so the user runs one command instead of three.

How to talk to the AI was the design question. Three viable shapes:

1. **Embed an HTTP client + Anthropic API** — `reqwest` / `ureq`,
   `ANTHROPIC_API_KEY` env var, hand-rolled JSON request bodies.
2. **Embed a vendor SDK** — pull in `anthropic-sdk` or similar.
3. **Shell out to the user's existing CLI** — `claude` (or later
   `ollama`), inheriting whatever auth and billing the user already has.

## Decision
Shell out to the Claude Code CLI (`claude -p ...`) via
`std::process::Command`. No HTTP client, no SDK, no API key in otsniff's
environment.

## Rationale

- **No new auth surface.** The user has already authenticated `claude`;
  they shouldn't have to manage a second secret in a different env var.
- **Billing follows the user.** If they're on Claude Pro/Max, `analyze`
  "costs nothing extra." With an HTTP integration, we'd be inventing a
  separate billing relationship.
- **Supply-chain story.** ADR-0001 already commits us to a single
  static binary with a small dep tree. Adding `reqwest` pulls in tokio,
  hyper, rustls/openssl, et al. Adding `ureq` is lighter but still a
  dep that has to be audited. Shelling out adds zero crates.
- **Forward-compatible.** `ollama` (v0.4) and `claude-code` use the
  same shell-out pattern. The `AiProvider` trait shape locks in across
  providers without churn.
- **Updates ride along.** When Claude Code adds new models, new
  features, or fixes bugs, otsniff inherits them without a release.

## Critical safety property: the leak detector

The privacy contract — Claude must never see real IPs/MACs — is enforced
by `src/ai/leak_detector.rs` sitting between scrub and the provider call.
It scans the about-to-be-sent text for IPv4, IPv6, and MAC-shaped
patterns. If any are found, the run aborts with a descriptive error;
the AI is never invoked.

This is intentionally redundant with the scrub layer. The reasoning:

- **Scrub** is the common-case correctness mechanism — it replaces
  every value present in the map.
- **Leak detector** is the bug-case safety net — even if scrub has a
  bug (missed observation, future code path that builds the AI input
  by an alternate route, accidentally interpolated unscrubbed
  observation in a future feature), the detector still fails closed.

The detector is treated as more important than the scrubber. The scrubber
prevents the common case; the detector prevents the bug case. Tests
assert both: the round-trip property of the scrubber, and the
"detector finds a leak when given un-scrubbed input" property.

## What's intentionally not supported in v0.3

- **User-supplied free-text task / context.** A `--task "investigate
  X at the Acme refinery"` flag would route user-supplied strings
  unscrubbed to the AI. We'd need to either scrub those strings (no
  context to mint pseudonyms from, since we haven't observed the
  user's input), or document loudly that they're not scrubbed (sets a
  trap for users). v0.3 ships only with the committed default task.
  Revisit in v0.4 if there's demand and we have a sound design.
- **Embedded API client / SDK.** See above.
- **Streaming output.** Buffered stdout from `claude` is fine for v0.3.

## What's deferred to v0.4

- **Ollama provider.** Same shell-out pattern, different binary
  (`ollama run ...`). Drop in alongside `claude_cli.rs`. The scrub +
  leak-detector boundary is identical because it's between us and the
  provider, not between us and a network.
- **HTTP fallback.** If a user wants `--provider anthropic-http`, that
  becomes one more `AiProvider` impl. The trait shape doesn't change.

## Consequences

- Runtime dependency: `claude` must be on PATH. Detected at
  `analyze` invocation with a clear error pointing to
  https://claude.com/code if missing.
- We don't control the model selection from inside otsniff (it's
  Claude Code's domain). We expose `--model` as a passthrough.
- Provider trait abstraction means swapping providers later is
  additive, not a refactor.
- The leak detector becomes a load-bearing test. If it ever needs to
  be relaxed (e.g., a real PCAP produces a false-positive IP-shaped
  string in a payload), that's an ADR-grade change, not a quick fix.

## Amendment — 2026-05-12 (S-5.04)

Original ADR covered the shell-out architecture and the privacy contract
on prompt bytes. It did not address what tools the spawned `claude -p`
instance can use at runtime. By default, Claude Code has Bash, Read,
Write, WebFetch, etc. — which means the LLM could read the source PCAP
or the scrub map file itself, bypassing the leak detector.

**Decision (amendment):**

1. `ClaudeCliProvider::analyze` always passes
   `--disallowed-tools "Bash,Read,Write,Edit,WebFetch,WebSearch,Glob,Grep,Task,NotebookEdit"`.
   Not user-configurable. The leak detector enforces *prompt bytes*;
   the tool disable enforces *runtime access*. Two airlocks, one
   contract.

2. New opt-in flag `analyze --review-scrub` prints the scrubbed bytes
   to stderr and pauses for a `y/N` confirmation before invoking
   claude. Default off so the fast path is unchanged. Defense for
   the paranoid operator who doesn't trust the automated leak
   detector's coverage.

**Status:** Accepted (this amendment is additive to the original ADR;
nothing in the prior decision is superseded).

**Behavioral contracts introduced:** BC-6.03.002, BC-9.06.001.

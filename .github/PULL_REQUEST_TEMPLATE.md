<!-- Thanks for the PR. Please fill in the sections below. -->

## Summary

<!-- One-paragraph description of what this PR does and why. -->

## Spec

<!-- Link to docs/specs/<your-feature>.md if this is non-trivial. If it's
     a trivial fix or a one-line config tweak, say so and skip. -->

## What this is NOT

<!-- Naming the related thing this PR specifically doesn't do helps
     scope the review. Optional but encouraged. -->

## Privacy / scrub stance (delete if not applicable)

<!-- If this PR touches anything in the AI / scrub / leak-detector path:
       - What new identifier types does it extract or render?
       - How is each scrubbed before reaching an AI provider?
       - Did you extend the leak detector regex / invariant test?
     If those questions don't apply, delete this section. -->

## Test plan

<!-- Checklist of how the PR was tested. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] New unit tests added if a new parser / detector / module landed
- [ ] Snapshot tests regenerated and reviewed (if output format changed)
- [ ] Verified end-to-end on a real PCAP fixture (if user-facing)

## Roadmap

<!-- If this implements a roadmap item, link to it. If it changes
     priority, say so explicitly. -->

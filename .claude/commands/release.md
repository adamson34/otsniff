# Release Workflow

Multi-stage release workflow for otsniff. Two release types:

- **Dev release** — pre-release from `develop`, optimistic next minor (e.g., `v0.2.0-dev.1`)
- **Stable release** — full release from `main` (e.g., `v0.2.0` or `v0.1.1`)

## Entry Point

Ask the user: "What type of release? (A) Dev release from develop, (B) Stable release to main"

- If **Dev release**: go to Dev Release Flow
- If **Stable release**: go to Stage 1

---

## Dev Release Flow

Dev versions use an optimistic minor bump from the last stable release.
For example, if the last stable is `0.1.0`, the first dev is `0.2.0-dev.1`.
If the eventual stable turns out to be a patch (`0.1.1`), that's fine —
dev tags are ephemeral and the stable version is chosen at release time.

1. Checkout `develop`, pull latest
2. Determine next dev version:
   - Last stable: `git tag -l "v*" --sort=-v:refname | grep -v -- '-' | head -1`
   - Optimistic next minor (`v0.1.0` → `0.2.0`)
   - Latest dev for that base: `git tag -l "v0.2.0-dev.*" --sort=-v:refname | head -1`
   - First dev = `dev.1`; otherwise increment
   - Confirm with user: "Next dev version: vX.Y.Z-dev.N — proceed?"
3. Bump `Cargo.toml` version to the dev version
4. `cargo check` to update `Cargo.lock`
5. `cargo fmt --all`
6. `cargo clippy --all-targets -- -D warnings`
7. `cargo test`
8. Commit: `chore: bump version to X.Y.Z-dev.N`
9. Annotated tag: `git tag -a vX.Y.Z-dev.N -m "chore: release vX.Y.Z-dev.N"`
10. Push: `git push origin develop && git push origin vX.Y.Z-dev.N`
11. Print: "Dev release vX.Y.Z-dev.N tagged and pushed. GitHub Actions will build and publish pre-release binaries."
12. Provide the releases URL

---

## Stage 1: Feature → develop

If on a feature branch (not `develop` or `main`):

1. Ensure all changes are committed
2. Push the branch
3. Create PR targeting `develop`
4. Show PR URL
5. Ask: "PR created. Proceed to develop → main release, or stop here?"
   - Stop: done
   - Proceed: wait for merge confirmation, continue

If already on `develop` or `main`, skip to Stage 2.

## Stage 2: develop → main

1. Checkout `develop`, pull latest
2. Generate changelog summary from conventional commits since last stable:
   ```
   LAST_TAG=$(git tag -l "v*" --sort=-v:refname | grep -v -- '-' | head -1)
   git log $LAST_TAG..HEAD --oneline --pretty=format:"- %s"
   ```
3. Group commits by type (feat, fix, docs, chore, etc.)
4. Determine stable version:
   - Show the changelog and ask: "Release as (A) minor vX.Y+1.0, (B) patch vX.Y.Z+1, or (C) custom?"
5. Set `Cargo.toml` version to the chosen stable version (strip any `-dev.N`)
6. Create branch `release/vX.Y.Z` from develop
7. Open PR `release/vX.Y.Z` → `main` with the changelog as the body
8. Show PR URL
9. Ask: "Release PR created. Proceed to tag after merge, or stop here?"
   - Stop: done
   - Proceed: wait for merge confirmation, continue

## Stage 3: Tag & Release

1. Checkout `main`, pull latest
2. Verify `Cargo.toml` version (no pre-release suffix):
   ```
   grep '^version' Cargo.toml
   ```
3. `cargo check` → updates `Cargo.lock`
4. `cargo fmt --all`
5. `cargo clippy --all-targets -- -D warnings`
6. `cargo test`
7. If anything changed in 3-6, commit on a branch and PR into `main`
8. After merge confirmation, annotated tag on `main`:
   ```
   git tag -a vX.Y.Z -m "chore: release vX.Y.Z"
   ```
9. Verify tag and Cargo.toml agree:
   ```
   TAG_VERSION=$(git describe --tags --exact-match | sed 's/^v//')
   CARGO_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
   ```
   Stop if they differ.
10. Push the tag to trigger the release workflow
11. Print: "Release vX.Y.Z tagged and pushed. GitHub Actions will build and publish binaries."
12. Provide the releases URL
13. Clean up dev tags for this cycle:
    ```
    git tag -l "vX.Y.Z-dev.*" | xargs -I {} git push origin :refs/tags/{}
    ```

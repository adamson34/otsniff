//! Pack system (ADR-0019).
//!
//! A pack is an optional component distributed as its own binary,
//! `otsniff-<name>`, installed next to the core binary. `otsniff <name>
//! …` dispatches to it the way `git foo` finds `git-foo`, so an installed
//! pack behaves like a built-in subcommand.
//!
//! Transport shells out to tools the operator already has (`curl`, `tar`)
//! rather than embedding an HTTP client — same stance ADR-0007 took for
//! the AI providers. `pack add` constructs the release URL itself and
//! verifies the checksum before placing anything; it never executes
//! downloaded shell code.
//!
//! Checksum verification is done **in-process** via `sha2` (already a
//! dependency), not by shelling out to `sha256sum -c`. See
//! [`verify_checksum`] — delegating that decision was fail-open on macOS.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{OtError, Result};

/// One optional component. The catalog is static (ADR-0019 D4) so
/// `pack list` works with no network: a core release can only advertise
/// packs whose artifacts that same release publishes.
pub struct Pack {
    pub name: &'static str,
    pub summary: &'static str,
}

pub const PACKS: &[Pack] = &[Pack {
    name: "web",
    summary:
        "Local web companion app — upload a PCAP in a browser, view the report, browse past runs.",
}];

pub fn find(name: &str) -> Option<&'static Pack> {
    PACKS.iter().find(|p| p.name == name)
}

/// Binary a pack installs as. Windows keeps the `.exe` suffix so
/// resolution finds what the release tarball actually contains.
pub fn binary_name(name: &str) -> String {
    if cfg!(windows) {
        format!("otsniff-{name}.exe")
    } else {
        format!("otsniff-{name}")
    }
}

/// Directory `pack add` installs into and dispatch looks in first: the
/// directory holding the running `otsniff`, unless `OTSNIFF_INSTALL_DIR`
/// overrides it (same env var `install.sh` honors, for the case where the
/// core binary sits somewhere the operator can't write).
pub fn install_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("OTSNIFF_INSTALL_DIR") {
        let dir = PathBuf::from(dir);
        // ADV-P2 F-P2-005: `search_dirs` drops non-absolute entries (they
        // resolve against the CWD), so a relative value here would make the
        // write path and the search path disagree — `add` would install to
        // ./otsniff-web and report success while `list` said "not
        // installed", and `remove` would delete from whatever directory the
        // operator happened to be in. Reject rather than silently diverge.
        if !dir.is_absolute() {
            return Err(OtError::Pack(format!(
                "OTSNIFF_INSTALL_DIR must be an absolute path (got '{}') — a relative \
                 install directory resolves against the current directory, which is \
                 exactly what pack resolution refuses to search",
                dir.display()
            )));
        }
        return Ok(dir);
    }
    let exe = std::env::current_exe().map_err(|e| {
        OtError::Pack(format!(
            "could not locate the running otsniff binary ({e}); \
             set OTSNIFF_INSTALL_DIR to choose where packs install"
        ))
    })?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| {
        OtError::Pack(
            "the running otsniff binary has no parent directory; \
             set OTSNIFF_INSTALL_DIR to choose where packs install"
                .to_string(),
        )
    })
}

/// True for a name that is safe to interpolate into a binary filename.
///
/// **F-P1-016 (ADV-P1).** Dispatch takes the name straight from argv and
/// `binary_name` interpolates it into a path that is then joined and
/// `exec`d, so `otsniff ../../../bin/sh` would traverse out of every
/// search directory. Pack names are an identifier-shaped namespace; treat
/// anything else as not-a-pack.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Locate an installed pack binary: `OTSNIFF_INSTALL_DIR` (if set), then
/// next to the running `otsniff`, then `PATH` (ADR-0019 D2 — the install
/// location is searched before `PATH`, so an unrelated `PATH` entry can't
/// shadow an installed pack).
pub fn resolve(name: &str) -> Option<PathBuf> {
    if !is_valid_name(name) {
        return None;
    }
    resolve_in(search_dirs(), &binary_name(name))
}

/// Search order, split out so [`resolve_in`] is testable without mutating
/// the process environment.
///
/// **F-P1-002 (ADV-P1).** `OTSNIFF_INSTALL_DIR` must come first: `add`
/// installs there, so if resolution ignored it, `pack add` would report
/// success and `pack list`/dispatch would then report the pack missing —
/// and ADR-0019's "PATH can't shadow an installed pack" property would be
/// silently void, because nothing would be found in the sibling dir at all.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    // Use the *validated* install dir rather than re-reading the env var, so
    // the write path and the search path cannot disagree (ADV-P2 F-P2-005).
    if let Ok(dir) = install_dir() {
        dirs.push(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    // F-P1-004 (ADV-P1): `split_paths` preserves empty components, and an
    // empty or relative entry resolves against the process CWD — so
    // `PATH="/usr/bin:"` would make `otsniff <name>` exec a planted
    // `./otsniff-<name>`. otsniff's usage pattern is "operator cd's into a
    // directory of captures", which is exactly where such a file would be.
    dirs.retain(|dir| dir.is_absolute());
    dirs
}

fn resolve_in(dirs: Vec<PathBuf>, binary: &str) -> Option<PathBuf> {
    dirs.into_iter()
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable_file(candidate))
}

/// F-P1-018 (ADV-P1): resolution requires an *executable* file, not just a
/// present one. Shared with the AI providers via [`crate::which`] — having
/// three private copies of this logic is what let ADV-P2 F-P2-001 survive
/// the ADV-P1 fix.
use crate::which::is_executable_file;

/// Rendered `pack list` output: every known pack with its installed state.
pub fn render_list() -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(
        out,
        "Packs (ADR-0019) — optional components installed alongside otsniff.\n"
    )
    .unwrap();
    for pack in PACKS {
        let state = match resolve(pack.name) {
            Some(path) => format!("installed  ({})", path.display()),
            None => format!("not installed  (otsniff pack add {})", pack.name),
        };
        writeln!(out, "  {:<8} {}", pack.name, state).unwrap();
        writeln!(out, "           {}", pack.summary).unwrap();
        writeln!(out).unwrap();
    }
    writeln!(
        out,
        "An installed pack runs as a subcommand: `otsniff web --help`."
    )
    .unwrap();
    out
}

/// Runs an installed pack, forwarding `args` (which still includes the
/// pack name at index 0 as clap captured it).
pub fn dispatch(args: &[OsString]) -> Result<()> {
    let (name, rest) = args
        .split_first()
        .ok_or_else(|| OtError::Pack("no subcommand given".to_string()))?;
    let name = name.to_string_lossy().into_owned();

    match resolve(&name) {
        Some(bin) => exec_pack(&bin, rest),
        None => Err(unknown_subcommand(&name)),
    }
}

/// Error for a subcommand that is neither built in nor an installed pack.
/// Distinguishes "known pack, not installed" from "no such thing" — clap's
/// external-subcommand handling can't, now that unknown subcommands are a
/// meaningful category.
fn unknown_subcommand(name: &str) -> OtError {
    if find(name).is_some() {
        return OtError::Pack(format!(
            "the '{name}' pack is not installed — run `otsniff pack add {name}`"
        ));
    }
    // F-P1-010 (ADV-P1): `external_subcommand` makes clap's own
    // `tip: a similar subcommand exists` unreachable, so a one-letter typo
    // of a built-in (`analyse` for `analyze`) lost its suggestion. Restore
    // it here rather than sending the operator off to read full --help.
    match nearest_subcommand(name) {
        Some(suggestion) => OtError::Pack(format!(
            "unknown subcommand '{name}' — did you mean '{suggestion}'?"
        )),
        None => OtError::Pack(format!(
            "unknown subcommand '{name}' — run `otsniff --help` for built-in commands \
             or `otsniff pack list` for optional packs"
        )),
    }
}

/// Built-in subcommand names, for typo suggestions. Kept here rather than
/// derived from clap so this module has no dependency on `cli`; the test
/// below asserts it matches what clap actually accepts.
pub const BUILTIN_SUBCOMMANDS: &[&str] = &[
    "analyze",
    "scrub",
    "unscrub",
    "rules",
    "diff",
    "slice",
    "bundle",
    "unbundle",
    "zonewarden",
    "pack",
];

/// Closest built-in subcommand or pack name within a small edit distance.
fn nearest_subcommand(name: &str) -> Option<&'static str> {
    let candidates = BUILTIN_SUBCOMMANDS
        .iter()
        .copied()
        .chain(PACKS.iter().map(|p| p.name));
    // Distance 2 catches single typos and transpositions without matching
    // unrelated words; require the candidate to be at least as long as the
    // distance so short names don't match everything.
    candidates
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, c)| *d <= 2 && c.len() > *d)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Levenshtein distance, iterative two-row form.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Error for an unknown *argument* to `pack add`/`pack remove`.
///
/// **F-P1-011 (ADV-P1).** These used to reuse the dispatch error, so
/// `otsniff pack add nosuchpack` said "unknown subcommand 'nosuchpack' —
/// run `otsniff --help`" — but the operator typed a perfectly valid
/// subcommand with a bad argument, and `--help` will never list packs.
fn unknown_pack(name: &str) -> OtError {
    let known: Vec<&str> = PACKS.iter().map(|p| p.name).collect();
    OtError::Pack(format!(
        "no such pack '{name}' — available: {}. Run `otsniff pack list` for details.",
        known.join(", ")
    ))
}

#[cfg(unix)]
fn exec_pack(bin: &Path, args: &[OsString]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // `exec` replaces this process, so signals and the exit code belong to
    // the pack directly. It only returns if the exec itself failed.
    let err = Command::new(bin).args(args).exec();
    Err(OtError::Pack(format!(
        "could not run {}: {err}",
        bin.display()
    )))
}

#[cfg(not(unix))]
fn exec_pack(bin: &Path, args: &[OsString]) -> Result<()> {
    let status = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| OtError::Pack(format!("could not run {}: {e}", bin.display())))?;
    std::process::exit(status.code().unwrap_or(1));
}

// ---------------------------------------------------------------------------
// pack add / remove
// ---------------------------------------------------------------------------

const REPO: &str = "adamson34/otsniff";

/// Release target triple for this build, matching the names
/// `release.yml` packages artifacts under (and `install.sh` derives from
/// `uname`).
pub fn target_triple() -> Result<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(OtError::Pack(format!(
                "no pack artifacts are published for this architecture ({other}); \
                 build the pack from source instead"
            )))
        }
    };
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        "windows" => "pc-windows-msvc",
        other => {
            return Err(OtError::Pack(format!(
                "no pack artifacts are published for this OS ({other}); \
                 build the pack from source instead"
            )))
        }
    };
    // F-P1-019 (ADV-P1): release.yml does not build aarch64 Linux (the
    // cross-rs glibc issue noted in that workflow), so constructing the URL
    // would 404 with a misleading "release may not exist" message.
    // install.sh has guarded this since v0.2; the Rust copy had not.
    if arch == "aarch64" && os == "unknown-linux-gnu" {
        return Err(OtError::Pack(
            "pack artifacts aren't published for aarch64 Linux yet — build the \
             pack from source (`cargo build --release -p otsniff-web`) and put \
             the binary next to otsniff"
                .to_string(),
        ));
    }

    Ok(format!("{arch}-{os}"))
}

/// Normalizes `--version` into a release tag, rejecting anything that
/// isn't tag-shaped.
///
/// **F-P1-008 (ADV-P1).** The value was concatenated straight into the
/// release URL, so `--version ../../../../some/other/path` could redirect
/// the download within github.com, and a value with a newline or space
/// would produce a confusing failure rather than a clear rejection.
/// Semver tags only need alphanumerics, `.`, `-`, and `+`.
pub fn release_tag(version: Option<&str>) -> Result<String> {
    let raw = match version {
        Some(v) => v,
        None => return Ok(format!("v{}", crate::VERSION)),
    };
    let tag = raw.strip_prefix('v').unwrap_or(raw);
    let shaped = !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    if !shaped {
        return Err(OtError::Pack(format!(
            "'{raw}' is not a valid release tag — expected something like v0.7.0"
        )));
    }
    Ok(format!("v{tag}"))
}

/// Release artifact base name for a pack at a given tag, e.g.
/// `otsniff-web-v0.7.0-aarch64-apple-darwin`. The tarball is this plus
/// `.tar.gz`, and it unpacks to a directory of the same name — mirroring
/// how the core binary is packaged.
pub fn artifact_stem(name: &str, tag: &str, target: &str) -> String {
    format!("otsniff-{name}-{tag}-{target}")
}

/// Downloads, verifies, and installs a pack.
///
/// `version` defaults to the running core's version: packs and core are
/// published from the same tag, so matching them is the correct default.
pub fn add(name: &str, version: Option<&str>) -> Result<()> {
    let pack = find(name).ok_or_else(|| unknown_pack(name))?;

    if cfg!(windows) {
        return Err(OtError::Pack(format!(
            "`pack add` isn't supported on Windows yet — download \
             otsniff-{name} from https://github.com/{REPO}/releases and put it \
             next to otsniff.exe"
        )));
    }

    let target = target_triple()?;
    let tag = release_tag(version)?;
    let stem = artifact_stem(pack.name, &tag, &target);
    let tarball = format!("{stem}.tar.gz");
    let url = format!("https://github.com/{REPO}/releases/download/{tag}/{tarball}");

    let dest_dir = install_dir()?;
    let tmp = TempDir::new()?;

    eprintln!("downloading {tarball}...");
    curl(&url, &tmp.0.join(&tarball))?;
    curl(
        &format!("{url}.sha256"),
        &tmp.0.join(format!("{tarball}.sha256")),
    )?;

    eprintln!("verifying checksum...");
    verify_checksum(&tmp.0, &tarball)?;

    eprintln!("installing...");
    // F-P1-015 (ADV-P1): refuse member modes and ownership from the
    // archive rather than letting a substituted tarball choose them.
    run(
        Command::new("tar")
            .args(["--no-same-owner", "--no-same-permissions", "-xzf"])
            .arg(&tarball)
            .current_dir(&tmp.0),
        "tar",
    )?;

    let binary = binary_name(pack.name);
    let extracted = tmp.0.join(&stem).join(&binary);
    // ADV-P2 F-P2-004: `is_file()` follows symlinks, so a symlink member
    // would pass the check and then be copied/chmod'd through to whatever
    // it points at. Check the link itself.
    if extracted
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(OtError::Pack(format!(
            "{tarball} contains {stem}/{binary} as a symlink — refusing to install.              This is not something a genuine release artifact does."
        )));
    }
    if !extracted.is_file() {
        return Err(OtError::Pack(format!(
            "{tarball} did not contain {stem}/{binary} — the release artifact \
             looks malformed; please file a bug"
        )));
    }

    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| OtError::Pack(format!("could not create {}: {e}", dest_dir.display())))?;
    let dest = dest_dir.join(&binary);

    // F-P1-007 (ADV-P1): stage beside the destination, set the mode, then
    // rename into place. `fs::copy` straight to `dest` truncated the live
    // binary first (a mid-copy failure left a truncated file that
    // `pack list` still reported as installed) and followed a symlink at
    // the destination. `rename` is atomic within a filesystem and replaces
    // a destination symlink rather than writing through it.
    let staged = dest_dir.join(format!(".{binary}.tmp-{:016x}", random_suffix()));
    let staging_failed = |e: std::io::Error| {
        OtError::Pack(format!(
            "could not install to {} ({e}) — re-run with write access to that \
             directory, or set OTSNIFF_INSTALL_DIR to somewhere you can write",
            dest_dir.display()
        ))
    };
    // ADV-P2 F-P2-010: `fs::copy` is O_CREAT|O_TRUNC and follows symlinks,
    // so a pre-planted symlink at `staged` would be written through and then
    // chmod'd. `create_new` fails if the path exists at all — including as a
    // symlink — which is the property that matters here, since the staged
    // name is only unpredictable-ish.
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o700);
        }
        let bytes = std::fs::read(&extracted).map_err(staging_failed)?;
        let mut out = opts.open(&staged).map_err(staging_failed)?;
        out.write_all(&bytes).map_err(staging_failed)?;
    }

    let finish = |staged: &Path| -> Result<()> {
        make_executable(staged)?;
        // The binary isn't notarized; without this macOS Gatekeeper blocks
        // it. Done before the rename so `dest` is never briefly quarantined.
        if std::env::consts::OS == "macos" {
            let _ = Command::new("xattr")
                .args(["-d", "com.apple.quarantine"])
                .arg(staged)
                .status();
        }
        std::fs::rename(staged, &dest).map_err(|e| {
            OtError::Pack(format!(
                "could not move the staged pack into place at {} ({e})",
                dest.display()
            ))
        })
    };
    if let Err(e) = finish(&staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }

    eprintln!("installed {} → {}", pack.name, dest.display());

    // F-P1-002 (ADV-P1): confirm the thing we just installed is actually
    // reachable, rather than reporting success and letting dispatch then
    // claim it isn't installed.
    match resolve(pack.name) {
        Some(found) if found == dest => {
            eprintln!("run it with: otsniff {} --help", pack.name);
        }
        Some(found) => {
            eprintln!(
                "WARNING: `otsniff {}` will run {} instead — it comes earlier in the \
                 search path than what was just installed.",
                pack.name,
                found.display()
            );
        }
        None => {
            eprintln!(
                "WARNING: {} is not on otsniff's search path, so `otsniff {}` won't \
                 find it. Add it to PATH:\n\n    export PATH=\"{}:$PATH\"",
                dest.display(),
                pack.name,
                dest_dir.display()
            );
        }
    }
    Ok(())
}

/// Deletes a pack binary **from the install directory only**. Packs keep
/// no state outside their own data directories, so this never touches user
/// data.
///
/// **F-P1-003 (ADV-P1).** This used to delete whatever `resolve()` found
/// first — which searches all of `PATH` — so it could delete a
/// package-manager-owned `/usr/local/bin/otsniff-web` that otsniff never
/// installed, or a `target/debug` build artifact, and it wasn't idempotent
/// (repeat runs walked `PATH` deleting a different file each time). It now
/// targets exactly the path `add` would have written, and reports rather
/// than deletes anything else.
pub fn remove(name: &str) -> Result<()> {
    find(name).ok_or_else(|| unknown_pack(name))?;
    let dir = install_dir()?;
    let target = dir.join(binary_name(name));

    if !target.is_file() {
        return Err(match resolve(name) {
            Some(elsewhere) => OtError::Pack(format!(
                "the '{name}' pack is not installed in {} — otsniff did not install \
                 the copy at {}, so it will not remove it. Delete it with whatever \
                 installed it (package manager, build, or by hand).",
                dir.display(),
                elsewhere.display()
            )),
            None => OtError::Pack(format!("the '{name}' pack is not installed")),
        });
    }

    std::fs::remove_file(&target)
        .map_err(|e| OtError::Pack(format!("could not remove {}: {e}", target.display())))?;
    eprintln!("removed {} ({})", name, target.display());
    Ok(())
}

fn curl(url: &str, dest: &Path) -> Result<()> {
    // F-P1-009 (ADV-P1): pin the protocol so a redirect can't downgrade to
    // plaintext or hop to file://, and bound the transfer so a hung or
    // endless response can't stall `pack add` indefinitely.
    run(
        Command::new("curl")
            .args([
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--connect-timeout",
                "20",
                "--max-time",
                "300",
                "--retry",
                "2",
                "-fsSL",
                url,
                "-o",
            ])
            .arg(dest),
        "curl",
    )
    .map_err(|_| {
        OtError::Pack(format!(
            "download failed: {url}\n\
             Check that the release exists at https://github.com/{REPO}/releases, \
             or pass --version to pick a different one."
        ))
    })
}

/// Parses the expected digest out of a `sha256sum`-format sidecar
/// (`<64 hex>  <filename>`), rejecting anything that isn't one.
///
/// **F-P1-001 (ADV-P1).** This used to delegate the decision to
/// `sha256sum -c`, which is fail-open on macOS: Darwin's `/sbin/sha256sum`
/// exits 0 for a checklist containing no properly formatted lines, so an
/// empty or HTML sidecar body "verified". The fail-closed `shasum` branch
/// was unreachable, because `which` finds `/sbin/sha256sum` first on a
/// default macOS PATH. Parsing the digest ourselves and comparing it in
/// Rust removes the dependence on any external tool's checklist semantics
/// — and on any external tool at all, since `sha2` is already a
/// dependency of this crate.
fn expected_digest(sidecar: &str, tarball: &str) -> Result<String> {
    let token = sidecar.split_whitespace().next().unwrap_or("");
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OtError::Pack(format!(
            "the checksum sidecar for {tarball} does not contain a SHA-256 digest \
             — refusing to install. The download may have been intercepted or \
             the release may be malformed."
        )));
    }
    Ok(token.to_ascii_lowercase())
}

/// Hashes the downloaded tarball in-process and compares it against the
/// sidecar. Fail-closed by construction: a missing, empty, or non-checksum
/// sidecar cannot produce a passing comparison.
fn verify_checksum(dir: &Path, tarball: &str) -> Result<()> {
    let sidecar_path = dir.join(format!("{tarball}.sha256"));
    let sidecar = std::fs::read_to_string(&sidecar_path).map_err(|e| {
        OtError::Pack(format!(
            "could not read the checksum sidecar for {tarball} ({e}) — refusing to install"
        ))
    })?;
    let expected = expected_digest(&sidecar, tarball)?;

    let (_, actual) = crate::audit::sha256_file_hex(&dir.join(tarball))?;
    if actual != expected {
        return Err(OtError::Pack(format!(
            "checksum verification FAILED for {tarball} \
             (expected {expected}, got {actual}) — refusing to install"
        )));
    }
    Ok(())
}

/// Runs a command, suppressing its output, and maps a non-zero exit to an
/// error. Callers add the context — the raw exit status is never the most
/// useful thing to show an operator.
fn run(cmd: &mut Command, name: &str) -> Result<()> {
    let status = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| OtError::Pack(format!("could not run {name}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(OtError::Pack(format!(
            "{name} exited with {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".to_string())
        )))
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| OtError::Pack(format!("could not stat {}: {e}", path.display())))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .map_err(|e| OtError::Pack(format!("could not chmod {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Unpredictable-enough suffix for scratch paths, without taking a `rand`
/// dependency: `RandomState` is seeded from the OS per process.
fn random_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::process::id() as u64);
    h.finish()
}

/// Scratch directory that cleans itself up, including on the `?` early
/// returns above. `tempfile` is a dev-dependency only — promoting it to a
/// runtime dep for ten lines isn't worth it.
///
/// **F-P1-006 (ADV-P1).** This previously used `create_dir_all` on a
/// wall-clock-nanosecond name, which succeeds if the path already exists
/// — including as a symlink into an attacker-owned directory — and
/// inherited `0777 & ~umask`. A local user could then swap the extracted
/// binary between verification and install. Now: randomized name,
/// exclusive `create` (fails if the path exists at all), and `0700`.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("otsniff-pack-{:016x}", random_suffix()));
        Self::create_exclusive(&dir)
            .map_err(|e| OtError::Pack(format!("could not create {}: {e}", dir.display())))?;
        Ok(TempDir(dir))
    }

    #[cfg(unix)]
    fn create_exclusive(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }

    #[cfg(not(unix))]
    fn create_exclusive(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_lookup() {
        assert_eq!(find("web").map(|p| p.name), Some("web"));
        assert!(find("nope").is_none());
    }

    #[test]
    fn every_pack_has_a_summary() {
        for pack in PACKS {
            assert!(!pack.name.is_empty());
            assert!(
                !pack.summary.is_empty(),
                "pack {} has no summary",
                pack.name
            );
        }
    }

    #[test]
    fn binary_name_is_prefixed() {
        let name = binary_name("web");
        assert!(name.starts_with("otsniff-web"), "got {name}");
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        }
    }

    #[test]
    fn resolve_in_prefers_the_first_directory_that_has_it() {
        let tmp = TempDir::new().unwrap();
        let first = tmp.0.join("first");
        let second = tmp.0.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        // Must be executable to count as a pack binary (F-P1-018).
        write_executable(&second.join("otsniff-web"));

        // Only the second directory has it.
        let found = resolve_in(vec![first.clone(), second.clone()], "otsniff-web");
        assert_eq!(found, Some(second.join("otsniff-web")));

        // Once both do, the earlier directory wins (install-dir before PATH).
        write_executable(&first.join("otsniff-web"));
        let found = resolve_in(vec![first.clone(), second], "otsniff-web");
        assert_eq!(found, Some(first.join("otsniff-web")));
    }

    fn write_executable(path: &Path) {
        std::fs::write(path, b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn resolve_in_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        assert!(resolve_in(vec![tmp.0.clone()], "otsniff-web").is_none());
    }

    #[test]
    fn unknown_subcommand_distinguishes_uninstalled_from_nonexistent() {
        // A real pack that isn't installed points at `pack add`.
        let msg = unknown_subcommand("web").to_string();
        assert!(msg.contains("pack add web"), "got: {msg}");

        // Something that isn't a pack at all points at help/list.
        let msg = unknown_subcommand("frobnicate").to_string();
        assert!(msg.contains("unknown subcommand"), "got: {msg}");
        assert!(msg.contains("pack list"), "got: {msg}");
    }

    /// F-P1-010: `external_subcommand` made clap's own did-you-mean tip
    /// unreachable, so a typo of a built-in lost its suggestion.
    #[test]
    fn typos_of_builtins_get_a_suggestion() {
        for (typo, expected) in [
            ("analyse", "analyze"), // British spelling of the primary command
            ("analyz", "analyze"),  // truncation
            ("anlayze", "analyze"), // transposition
            ("scub", "scrub"),
            ("bundl", "bundle"),
            ("zonewardn", "zonewarden"),
            ("wbe", "web"), // pack names are suggestion candidates too
        ] {
            let msg = unknown_subcommand(typo).to_string();
            assert!(
                msg.contains(&format!("did you mean '{expected}'")),
                "'{typo}' should suggest '{expected}', got: {msg}"
            );
        }

        // An *exact* pack name is not a typo — it gets the more useful
        // "not installed, run pack add" message instead.
        let msg = unknown_subcommand("web").to_string();
        assert!(msg.contains("pack add web"), "got: {msg}");
    }

    #[test]
    fn unrelated_names_get_the_generic_guidance_not_a_bogus_suggestion() {
        let msg = unknown_subcommand("frobnicate").to_string();
        assert!(msg.contains("unknown subcommand"), "got: {msg}");
        assert!(msg.contains("pack list"), "got: {msg}");
        assert!(!msg.contains("did you mean"), "got: {msg}");
    }

    /// The suggestion list is hand-maintained; assert it matches the
    /// subcommands clap actually accepts, so adding one to the CLI without
    /// adding it here is caught.
    #[test]
    fn builtin_subcommand_list_matches_the_cli() {
        use clap::CommandFactory;
        let mut from_clap: Vec<String> = crate::cli::Cli::command()
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        from_clap.sort();
        let mut declared: Vec<String> = BUILTIN_SUBCOMMANDS.iter().map(|s| s.to_string()).collect();
        declared.sort();
        assert_eq!(
            declared, from_clap,
            "packs::BUILTIN_SUBCOMMANDS is out of sync with the clap definition"
        );
    }

    /// F-P1-011: a bad *argument* to `pack add` is not an unknown
    /// subcommand — pointing at `--help` would be useless, since `--help`
    /// never lists packs.
    #[test]
    fn unknown_pack_names_the_alternatives_and_not_help() {
        let msg = unknown_pack("nosuchpack").to_string();
        assert!(msg.contains("no such pack 'nosuchpack'"), "got: {msg}");
        assert!(msg.contains("web"), "must list what is available: {msg}");
        assert!(msg.contains("pack list"), "got: {msg}");
        assert!(
            !msg.contains("unknown subcommand"),
            "must not reuse the dispatch wording: {msg}"
        );
    }

    /// F-P1-001: the regression that matters. Delegating to
    /// `sha256sum -c` passed an empty or HTML sidecar on macOS.
    #[test]
    fn checksum_rejects_sidecars_that_are_not_checksums() {
        for bad in [
            "",
            "\n",
            "   \n",
            "<html><body>404 Not Found</body></html>",
            "not-a-digest  file.tar.gz",
            // 63 hex chars — one short.
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde  f.tar.gz",
            // 64 chars but not all hex.
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeZ  f.tar.gz",
        ] {
            let err = expected_digest(bad, "t.tar.gz")
                .expect_err(&format!("must reject sidecar {bad:?}"));
            assert!(
                err.to_string()
                    .contains("does not contain a SHA-256 digest"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn checksum_accepts_a_well_formed_sidecar_case_insensitively() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            expected_digest(&format!("{hex}  t.tar.gz\n"), "t.tar.gz").unwrap(),
            hex
        );
        assert_eq!(
            expected_digest(&format!("{}  t.tar.gz\n", hex.to_uppercase()), "t.tar.gz").unwrap(),
            hex,
            "digests must compare case-insensitively"
        );
    }

    /// F-P1-001 end-to-end: a tarball whose real hash doesn't match the
    /// sidecar must be refused, and a matching one accepted.
    #[test]
    fn verify_checksum_compares_the_real_file_hash() {
        let tmp = TempDir::new().unwrap();
        let tarball = "t.tar.gz";
        std::fs::write(tmp.0.join(tarball), b"payload").unwrap();

        // Correct digest for b"payload".
        let good = crate::audit::sha256_hex("payload");
        std::fs::write(
            tmp.0.join(format!("{tarball}.sha256")),
            format!("{good}  {tarball}\n"),
        )
        .unwrap();
        verify_checksum(&tmp.0, tarball).expect("matching digest must verify");

        // Wrong digest → refused.
        let bad = crate::audit::sha256_hex("something else entirely");
        std::fs::write(
            tmp.0.join(format!("{tarball}.sha256")),
            format!("{bad}  {tarball}\n"),
        )
        .unwrap();
        let err = verify_checksum(&tmp.0, tarball).expect_err("mismatch must fail");
        assert!(err.to_string().contains("FAILED"), "got: {err}");

        // Empty sidecar → refused (the macOS fail-open case).
        std::fs::write(tmp.0.join(format!("{tarball}.sha256")), b"").unwrap();
        assert!(verify_checksum(&tmp.0, tarball).is_err());
    }

    /// F-P1-004: an empty or relative PATH entry must never be searched,
    /// because it resolves against the CWD.
    #[test]
    fn search_dirs_are_always_absolute() {
        for dir in search_dirs() {
            assert!(
                dir.is_absolute(),
                "relative search dir would resolve against the CWD: {dir:?}"
            );
        }
    }

    /// F-P1-016: names that would traverse out of the search directories
    /// are not packs.
    #[test]
    fn invalid_names_are_rejected_before_any_path_join() {
        for bad in [
            "",
            "../../../bin/sh",
            "a/b",
            "a\\b",
            ".",
            "..",
            "web;rm -rf /",
            "web nam",
        ] {
            assert!(!is_valid_name(bad), "{bad:?} must not be a valid pack name");
            assert!(
                resolve(bad).is_none(),
                "{bad:?} must never resolve to a path"
            );
        }
        for good in ["web", "hunt", "some_pack", "some-pack", "p1"] {
            assert!(is_valid_name(good), "{good:?} should be valid");
        }
    }

    /// F-P1-018: a present-but-not-executable file must not satisfy
    /// resolution — it would only fail confusingly at exec time, and could
    /// mask a real pack later in the search path.
    #[test]
    #[cfg(unix)]
    fn resolve_in_skips_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let first = tmp.0.join("first");
        let second = tmp.0.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        // Non-executable in the earlier dir, executable in the later one.
        let dud = first.join("otsniff-web");
        std::fs::write(&dud, b"").unwrap();
        std::fs::set_permissions(&dud, std::fs::Permissions::from_mode(0o644)).unwrap();
        let real = second.join("otsniff-web");
        std::fs::write(&real, b"").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            resolve_in(vec![first, second], "otsniff-web"),
            Some(real),
            "the non-executable file must be skipped, not returned"
        );
    }

    /// F-P1-008: `--version` reaches a URL, so it must be tag-shaped.
    #[test]
    fn release_tag_normalizes_and_rejects() {
        assert_eq!(release_tag(Some("0.7.0")).unwrap(), "v0.7.0");
        assert_eq!(release_tag(Some("v0.7.0")).unwrap(), "v0.7.0");
        assert_eq!(release_tag(Some("v0.7.0-dev.1")).unwrap(), "v0.7.0-dev.1");
        assert_eq!(release_tag(None).unwrap(), format!("v{}", crate::VERSION));

        for bad in [
            "../../../../etc/passwd",
            "v0.7.0/../../other",
            "v0 7 0",
            "v0.7.0\nX",
            "",
            "v",
        ] {
            assert!(
                release_tag(Some(bad)).is_err(),
                "{bad:?} must be rejected as a release tag"
            );
        }
    }

    /// F-P1-006: the staging directory must be exclusive, so a
    /// pre-created path (or a symlink into an attacker-owned dir) fails
    /// rather than being adopted.
    #[test]
    fn temp_dir_creation_is_exclusive() {
        let tmp = TempDir::new().unwrap();
        let victim = tmp.0.join("already-there");
        std::fs::create_dir(&victim).unwrap();
        assert!(
            TempDir::create_exclusive(&victim).is_err(),
            "creating over an existing directory must fail"
        );
    }

    #[cfg(unix)]
    #[test]
    fn temp_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let mode = std::fs::metadata(&tmp.0).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging dir must not be group/world readable");
    }

    #[test]
    fn artifact_stem_matches_the_release_naming_scheme() {
        assert_eq!(
            artifact_stem("web", "v0.7.0", "aarch64-apple-darwin"),
            "otsniff-web-v0.7.0-aarch64-apple-darwin"
        );
    }

    #[test]
    fn target_triple_is_one_we_publish() {
        // On any platform CI runs, this must resolve rather than error.
        let triple = target_triple().expect("CI platforms are all published targets");
        assert!(
            triple.ends_with("apple-darwin")
                || triple.ends_with("unknown-linux-gnu")
                || triple.ends_with("pc-windows-msvc"),
            "got {triple}"
        );
    }

    #[test]
    fn render_list_mentions_every_pack_and_how_to_install() {
        let out = render_list();
        for pack in PACKS {
            assert!(out.contains(pack.name), "list omits {}", pack.name);
            assert!(
                out.contains(pack.summary),
                "list omits {}'s summary",
                pack.name
            );
        }
    }

    #[test]
    fn temp_dir_cleans_up_on_drop() {
        let path = {
            let tmp = TempDir::new().unwrap();
            assert!(tmp.0.is_dir());
            tmp.0.clone()
        };
        assert!(!path.exists(), "TempDir must remove itself on drop");
    }
}

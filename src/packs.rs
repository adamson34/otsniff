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

/// Every `otsniff-<name>` binary present in the install directory, whether
/// or not it is in the catalog.
///
/// **ADV-P2 F-P2-016.** Dispatch runs any `otsniff-<name>` it resolves —
/// ADR-0019 `:83-85` explicitly invites third-party packs — but `pack list`
/// and `pack remove` only ever consulted the static catalog. A planted
/// `otsniff-acme` therefore ran as `otsniff acme`, was absent from
/// `pack list`, and `pack remove acme` said "no such pack": the execution
/// surface and the management surface disagreed, so a pack an operator
/// could run was one they could neither audit nor remove through the tool.
pub fn installed_in_dir(dir: &Path) -> Vec<(String, PathBuf)> {
    let prefix = "otsniff-";
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        // Windows artifacts keep the .exe suffix; strip it back off so the
        // reported name is the one the operator types.
        let rest = rest.strip_suffix(".exe").unwrap_or(rest);
        if !is_valid_name(rest) {
            continue;
        }
        let path = dir.join(&file_name);
        if is_executable_file(&path) {
            found.push((rest.to_string(), path));
        }
    }
    found.sort();
    found
}

/// Rendered `pack list` output: every known pack with its installed state,
/// followed by anything else installed that otsniff would dispatch to.
pub fn render_list() -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(
        out,
        "Packs (ADR-0019) — optional components installed alongside otsniff.\n"
    )
    .unwrap();
    let dir = install_dir().ok();
    for pack in PACKS {
        let state = match resolve(pack.name) {
            Some(path) => format!("installed  ({})", path.display()),
            None => {
                // ADV-P2 F-P2-021: `resolve` requires the execute bit, so a
                // present-but-not-executable file used to be reported
                // identically to nothing at all — while `pack remove` (which
                // checked only `is_file()`) deleted it. Naming the state is
                // what makes the two commands agree about what exists.
                let inert = dir
                    .as_ref()
                    .map(|d| d.join(binary_name(pack.name)))
                    .filter(|p| p.is_file());
                match inert {
                    Some(path) => format!(
                        "present but not executable  ({}) — `otsniff pack add {}` to reinstall",
                        path.display(),
                        pack.name
                    ),
                    None => format!("not installed  (otsniff pack add {})", pack.name),
                }
            }
        };
        writeln!(out, "  {:<8} {}", pack.name, state).unwrap();
        writeln!(out, "           {}", pack.summary).unwrap();
        writeln!(out).unwrap();
    }

    // F-P2-016: anything dispatchable that the catalog doesn't know about.
    if let Some(dir) = dir.as_ref() {
        let extra: Vec<_> = installed_in_dir(dir)
            .into_iter()
            .filter(|(name, _)| find(name).is_none())
            .collect();
        if !extra.is_empty() {
            writeln!(
                out,
                "Other installed components (not from this otsniff release):\n"
            )
            .unwrap();
            for (name, path) in extra {
                writeln!(out, "  {name:<8} installed  ({})", path.display()).unwrap();
                writeln!(
                    out,
                    "           runs as `otsniff {name}`; remove with `otsniff pack remove {name}`"
                )
                .unwrap();
                writeln!(out).unwrap();
            }
        }
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
    // Everything below echoes the name back to a terminal, so sanitize it
    // first (F-P2-041).
    let name = &display_name(name);
    // F-P1-010 (ADV-P1): `external_subcommand` makes clap's own
    // `tip: a similar subcommand exists` unreachable, so a one-letter typo
    // of a built-in (`analyse` for `analyze`) lost its suggestion. Restore
    // it here rather than sending the operator off to read full --help.
    match nearest_subcommand(name) {
        // ADV-P2 F-P2-029: the suggestion branch used to stop at the guess,
        // so ADR-0019 `:66`'s claim that unknown names point at
        // `otsniff pack list` was true of one branch out of two — and the
        // branch it was false for is the one an operator who mistyped a
        // *pack* name lands in.
        Some(suggestion) => OtError::Pack(format!(
            "unknown subcommand '{name}' — did you mean '{suggestion}'? \
             (`otsniff --help` for built-in commands, `otsniff pack list` for \
             optional packs)"
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

/// Longest input `nearest_subcommand` will even attempt to score.
///
/// **ADV-P2 F-P2-042.** `edit_distance` allocated a `Vec<char>` over raw
/// argv with no cap — an `ARG_MAX`-length subcommand name meant a ~4 MB
/// allocation and ~10^8 cell updates before printing "unknown subcommand".
/// `is_valid_name`'s 64-byte cap exists two functions away but was never
/// applied on this path. Nothing this long is a typo of a ≤10-char word.
const MAX_SUGGESTION_INPUT: usize = 64;

/// Closest built-in subcommand or pack name within a small edit distance.
fn nearest_subcommand(name: &str) -> Option<&'static str> {
    let len = name.chars().count();
    if len == 0 || len > MAX_SUGGESTION_INPUT {
        return None;
    }
    let candidates = BUILTIN_SUBCOMMANDS
        .iter()
        .copied()
        .chain(PACKS.iter().map(|p| p.name));
    // Distance 2 catches single typos and transpositions without matching
    // unrelated words.
    //
    // **ADV-P2 F-P2-019.** The length guard here used to read `c.len() > *d`
    // — the *candidate*'s length. Every candidate is at least 4 characters,
    // so `c.len() > 2` was always true and the guard was dead code.
    // Two-character noise got a confident wrong suggestion instead of the
    // useful generic guidance: `ab`→`web`, `pk`→`pack`, `df`→`diff`. The
    // input is what needs to be long enough to be a typo *of* something, so
    // it is the input's length that must exceed the distance.
    candidates
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, _)| *d <= 2 && len > *d)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Levenshtein distance, iterative two-row form.
///
/// Callers must bound `a` (see [`MAX_SUGGESTION_INPUT`]): this is
/// O(|a|·|b|) in time and O(|a|+|b|) in allocation.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().take(MAX_SUGGESTION_INPUT).collect();
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
        "no such pack '{}' — available: {}. Run `otsniff pack list` for details.",
        display_name(name),
        known.join(", ")
    ))
}

/// Renders an untrusted name for an error message.
///
/// **ADV-P2 F-P2-041.** These messages echo `argv` straight to a terminal.
/// Unbounded and unfiltered, `otsniff $'\e]0;pwned\a'` injected terminal
/// escape sequences into otsniff's own stderr, and an `ARG_MAX`-length name
/// produced a megabytes-long error. Control characters become `\xNN`; the
/// text is capped at the same 64 bytes [`is_valid_name`] allows, since a
/// longer name cannot be a pack anyway.
fn display_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_SUGGESTION_INPUT) + 1);
    let mut truncated = false;
    for ch in name.chars() {
        if out.len() >= MAX_SUGGESTION_INPUT {
            truncated = true;
            break;
        }
        if ch.is_control() {
            out.push_str(&format!("\\x{:02x}", ch as u32 & 0xff));
        } else {
            out.push(ch);
        }
    }
    if truncated {
        out.push('…');
    }
    out
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
    triple_for(std::env::consts::ARCH, std::env::consts::OS)
}

/// The pure mapping behind [`target_triple`].
///
/// **ADV-P2 F-P2-045.** `target_triple` read `std::env::consts` directly, so
/// the aarch64-Linux guard could only be exercised on an aarch64 Linux
/// runner — and CI has none. Deleting the guard left every test green. Taking
/// the two strings as parameters makes the whole table testable anywhere.
fn triple_for(arch: &str, os: &str) -> Result<String> {
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(OtError::Pack(format!(
                "no pack artifacts are published for this architecture ({other}); \
                 build the pack from source instead"
            )))
        }
    };
    let os = match os {
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
    let dest = install_binary(&extracted, &dest_dir, &binary, &tarball, &stem)?;

    eprintln!("installed {} → {}", pack.name, dest.display());

    // ADV-P2 F-P2-015: run-verify, the same standard
    // `docs/specs/install-script.md:52` sets for the core and install.sh
    // applies to packs — `resolve()` only checks the mode bit, so a
    // wrong-arch or glibc-mismatched binary passed every other check here.
    // A pack that cannot execute must not be left in place reporting
    // success (the F-P2-014 shape, in the Rust copy).
    if let Err(e) = run_verify(&dest) {
        let _ = std::fs::remove_file(&dest);
        return Err(e);
    }

    // F-P1-002 (ADV-P1): confirm the thing we just installed is actually
    // reachable, rather than reporting success and letting dispatch then
    // claim it isn't installed.
    match resolve(pack.name) {
        Some(found) if found == dest => {
            eprintln!("run it with: otsniff {} --help", pack.name);
            Ok(())
        }
        // Unreachable in practice now that `search_dirs()` derives its first
        // entry from the same validated `install_dir()` that `dest_dir` came
        // from (F-P2-005, F-P2-049). Kept as a real error rather than
        // deleted: it is the assertion that those two stay in agreement, and
        // it costs nothing until they don't.
        Some(found) => Err(OtError::Pack(format!(
            "installed {}, but `otsniff {}` would run {} instead — it comes earlier \
             in the search path. Remove or rename that copy, or set \
             OTSNIFF_INSTALL_DIR to a directory that is searched first.",
            dest.display(),
            pack.name,
            found.display()
        ))),
        // ADV-P2 F-P2-031: this used to warn and exit **0**, while
        // `install-script.md:51` sets the opposite contract for the same
        // operation — so automation saw success for a pack that cannot run.
        None => Err(OtError::Pack(format!(
            "installed {}, but it is not on otsniff's search path, so `otsniff {}` \
             won't find it. Add the directory to PATH:\n\n    export PATH=\"{}:$PATH\"",
            dest.display(),
            pack.name,
            dest_dir.display()
        ))),
    }
}

/// Confirms a freshly installed binary actually executes.
///
/// `--help` rather than `--version`: every pack has one, and it is the check
/// `install.sh` already performs.
fn run_verify(bin: &Path) -> Result<()> {
    let out = Command::new(bin)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match out {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(OtError::Pack(format!(
            "{} was installed but `--help` exited with {} — the artifact looks \
             broken, so it has been removed rather than left half-installed",
            bin.display(),
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".to_string())
        ))),
        Err(e) => Err(OtError::Pack(format!(
            "{} was installed but could not be executed ({e}) — most likely built \
             for a different architecture or libc. It has been removed rather than \
             left half-installed.",
            bin.display()
        ))),
    }
}

/// Places an extracted release binary at `dest_dir/binary`, atomically and
/// without following symlinks at either end. Returns the installed path.
///
/// Split out of [`add`] so it is reachable from a unit test:
/// **ADV-P2 F-P2-008** found that nothing in the suite reached this code at
/// all, so deleting the staged-rename property, the exact `0o755`, or the
/// symlink-member refusal left the suite green.
fn install_binary(
    extracted: &Path,
    dest_dir: &Path,
    binary: &str,
    tarball: &str,
    stem: &str,
) -> Result<PathBuf> {
    // ADV-P2 F-P2-004/F-P2-024: `is_file()` follows symlinks, so a symlink
    // member would pass the check and then be read through to whatever it
    // points at — installing the *target's* contents as the pack. Check the
    // link itself. A genuine release artifact never contains one.
    if extracted
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(OtError::PackIntegrity(format!(
            "{tarball} contains {stem}/{binary} as a symlink — refusing to install. \
             This is not something a genuine release artifact does."
        )));
    }
    if !extracted.is_file() {
        return Err(OtError::PackIntegrity(format!(
            "{tarball} did not contain {stem}/{binary} — the release artifact \
             looks malformed; please file a bug"
        )));
    }

    std::fs::create_dir_all(dest_dir)
        .map_err(|e| OtError::Pack(format!("could not create {}: {e}", dest_dir.display())))?;
    let dest = dest_dir.join(binary);

    // F-P1-007 (ADV-P1): stage beside the destination, set the mode, then
    // rename into place. `fs::copy` straight to `dest` truncated the live
    // binary first (a mid-copy failure left a truncated file that
    // `pack list` still reported as installed) and followed a symlink at
    // the destination. `rename` is atomic within a filesystem and replaces
    // a destination symlink rather than writing through it.
    //
    // ADV-P2 F-P2-037: the guard owns the staged path from here on, so the
    // file is removed on *every* error return and on unwind — not only
    // inside the one closure that used to clean up. Orphans are dot-
    // prefixed, so neither `pack list` nor `pack remove` would ever surface
    // them.
    let staged = Staged::create(dest_dir.join(format!(".{binary}.tmp-{:016x}", random_suffix())))
        .map_err(|e| staging_failed(dest_dir, e))?;

    {
        use std::io::Write as _;
        let bytes = std::fs::read(extracted).map_err(|e| staging_failed(dest_dir, e))?;
        let mut handle = staged.handle();
        handle
            .write_all(&bytes)
            .map_err(|e| staging_failed(dest_dir, e))?;
        handle.flush().map_err(|e| staging_failed(dest_dir, e))?;
    }

    make_executable(staged.path())?;
    clear_quarantine(staged.path());

    let staged_path = staged.keep();
    std::fs::rename(&staged_path, &dest).map_err(|e| {
        let _ = std::fs::remove_file(&staged_path);
        OtError::Pack(format!(
            "could not move the staged pack into place at {} ({e})",
            dest.display()
        ))
    })?;
    Ok(dest)
}

fn staging_failed(dest_dir: &Path, e: std::io::Error) -> OtError {
    OtError::Pack(format!(
        "could not install to {} ({e}) — re-run with write access to that \
         directory, or set OTSNIFF_INSTALL_DIR to somewhere you can write",
        dest_dir.display()
    ))
}

/// Strips the macOS Gatekeeper quarantine attribute, if it is set.
///
/// **ADV-P2 F-P2-036.** This used to run `xattr -d` unconditionally, outside
/// `run()`, so its stderr reached the terminal — and since `curl` does not
/// set quarantine and the staged file is freshly created, the attribute is
/// normally *absent*, meaning a successful install printed
/// `xattr: ... No such xattr` mid-run. Meanwhile `let _ =` swallowed the
/// genuine failures, so a pack that really was quarantined got blocked by
/// Gatekeeper with no hint why. Both directions were wrong: probe first,
/// then report only a real failure.
fn clear_quarantine(path: &Path) {
    if std::env::consts::OS != "macos" {
        return;
    }
    const ATTR: &str = "com.apple.quarantine";
    let present = Command::new("xattr")
        .args(["-p", ATTR])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !present {
        return;
    }
    if run(Command::new("xattr").args(["-d", ATTR]).arg(path), "xattr").is_err() {
        eprintln!(
            "WARNING: could not clear the macOS quarantine attribute on {}; \
             Gatekeeper may refuse to run it.",
            path.display()
        );
    }
}

/// A file created exclusively at a staging path, removed unless [`keep`]ed.
///
/// [`keep`]: Staged::keep
struct Staged {
    path: PathBuf,
    file: Option<std::fs::File>,
    keep: bool,
}

impl Staged {
    /// ADV-P2 F-P2-010: `fs::copy` is `O_CREAT|O_TRUNC` and follows
    /// symlinks, so a pre-planted symlink at the staging path would be
    /// written through and then chmod'd. `create_new` fails if the path
    /// exists at all — including as a symlink — which is the property that
    /// matters, since `random_suffix()` is only unpredictable-ish
    /// (`RandomState` is documented as HashDoS-resistant, not unpredictable).
    fn create(path: PathBuf) -> std::io::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o700);
        }
        let file = opts.open(&path)?;
        Ok(Staged {
            path,
            file: Some(file),
            keep: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn handle(&self) -> &std::fs::File {
        self.file.as_ref().expect("staged file is open")
    }

    /// Closes the file and hands the path over; the caller owns cleanup
    /// from here (the rename either consumes it or removes it).
    fn keep(mut self) -> PathBuf {
        self.keep = true;
        self.file.take();
        self.path.clone()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        self.file.take();
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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
    // ADV-P2 F-P2-016: accept any dispatchable name, not just catalog
    // entries — `otsniff acme` will run a planted `otsniff-acme`, so
    // `otsniff pack remove acme` has to be able to take it away again.
    // A name that is neither in the catalog nor installed still gets the
    // catalog-listing error, which is the useful answer for a typo.
    if !is_valid_name(name) {
        return Err(unknown_pack(name));
    }
    let dir = install_dir()?;
    let target = dir.join(binary_name(name));
    let known = find(name).is_some();

    // `is_file()` follows symlinks; `symlink_metadata` does not. Removing a
    // symlink is fine (it unlinks the link, not the target) — but reporting
    // it as "the pack" would be wrong, and otsniff never installs one.
    let meta = std::fs::symlink_metadata(&target).ok();
    let present = meta.as_ref().is_some_and(|m| !m.file_type().is_dir());
    if !present {
        if !known && installed_in_dir(&dir).iter().all(|(n, _)| n != name) {
            return Err(unknown_pack(name));
        }
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

/// Largest release artifact `pack add` will accept. The biggest thing
/// `release.yml` publishes is a stripped release binary plus two text files,
/// two orders of magnitude under this; the cap exists so a hostile or broken
/// endpoint cannot stream unbounded data into the operator's temp
/// filesystem (ADV-P2 F-P2-011).
const MAX_ARTIFACT_BYTES: &str = "268435456"; // 256 MiB

fn curl(url: &str, dest: &Path) -> Result<()> {
    // F-P1-009 (ADV-P1): pin the protocol so a redirect can't downgrade to
    // plaintext or hop to file://, and bound the transfer so a hung or
    // endless response can't stall `pack add` indefinitely. ADV-P2 F-P2-011
    // adds the size and redirect-chain bounds, which were absent in both
    // copies; `--` (F-P2-048) terminates option parsing so neither the URL
    // nor the destination can ever be read as a flag.
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
                "--max-redirs",
                "5",
                "--max-filesize",
                MAX_ARTIFACT_BYTES,
                "-fsSL",
                "-o",
            ])
            .arg(dest)
            .arg("--")
            .arg(url),
        "curl",
    )
    .map_err(|e| {
        // ADV-P2 F-P2-012: `map_err(|_| …)` discarded curl's own diagnosis
        // and reported every transport failure — TLS, proxy, timeout,
        // curl-not-installed — as a wrong version. Keep it.
        OtError::Pack(format!(
            "download failed: {url}\n{e}\n\
             If that is a 404, check the release exists at \
             https://github.com/{REPO}/releases or pass --version to pick a \
             different one; otherwise it is a network, proxy, or TLS problem \
             on this machine."
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
    // ADV-P2 F-P2-022: this took the first whitespace token *anywhere in the
    // file* while install.sh took field 1 of line 1 — so a sidecar with a
    // leading blank line was accepted by one copy and rejected by the other,
    // contradicting ADR-0019's claim that both parse it the same way. Line 1
    // is the correct reading of the `sha256sum` format, so both copies now
    // use it.
    let first_line = sidecar.lines().next().unwrap_or("");
    let mut fields = first_line.split_whitespace();
    let token = fields.next().unwrap_or("");
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OtError::PackIntegrity(format!(
            "the checksum sidecar for {tarball} does not contain a SHA-256 digest \
             — refusing to install. The download may have been intercepted or \
             the release may be malformed."
        )));
    }
    // ADV-P2 F-P2-022 (second half): neither copy checked the sidecar's
    // *filename* field, so a sidecar naming a different artifact — the wrong
    // pack, target, or version — verified fine as long as its digest matched
    // the bytes served. `sha256sum` writes a bare basename, optionally
    // `*`-prefixed for binary mode.
    if let Some(named) = fields.next() {
        let named = named.trim_start_matches('*');
        let named = named.rsplit('/').next().unwrap_or(named);
        if named != tarball {
            return Err(OtError::PackIntegrity(format!(
                "the checksum sidecar for {tarball} names a different file \
                 ('{named}') — refusing to install. The release may be malformed, \
                 or the sidecar may have been substituted."
            )));
        }
    }
    Ok(token.to_ascii_lowercase())
}

/// Hashes the downloaded tarball in-process and compares it against the
/// sidecar. Fail-closed by construction: a missing, empty, or non-checksum
/// sidecar cannot produce a passing comparison.
fn verify_checksum(dir: &Path, tarball: &str) -> Result<()> {
    let sidecar_path = dir.join(format!("{tarball}.sha256"));
    let sidecar = std::fs::read_to_string(&sidecar_path).map_err(|e| {
        OtError::PackIntegrity(format!(
            "could not read the checksum sidecar for {tarball} ({e}) — refusing to install"
        ))
    })?;
    let expected = expected_digest(&sidecar, tarball)?;

    let (_, actual) = crate::audit::sha256_file_hex(&dir.join(tarball))?;
    if actual != expected {
        // ADV-P2 F-P2-028: exit 76 (EX_PROTOCOL), not 2 — this is the one
        // pack failure automation must be able to escalate, and it shared an
        // exit code with `pack add nosuchpack`.
        return Err(OtError::PackIntegrity(format!(
            "checksum verification FAILED for {tarball} \
             (expected {expected}, got {actual}) — refusing to install"
        )));
    }
    Ok(())
}

/// Runs a command, suppressing its output, and maps a non-zero exit to an
/// error. Callers add the context — the raw exit status is never the most
/// useful thing to show an operator.
/// **ADV-P2 F-P2-012 / F-P2-024.** This used to send stderr to `/dev/null`,
/// which is the only channel that distinguishes "no such release" from a TLS
/// verification failure, a proxy refusing CONNECT, a timeout, or curl not
/// being installed at all — every one of them surfaced as "check that the
/// release exists". It also hid the sanitization warnings `tar` prints while
/// exiting 0 (e.g. stripping a leading `/` or a `..` component from a member
/// path). Capture stderr and fold it into the error instead: suppressed on
/// success, reported on failure.
fn run(cmd: &mut Command, name: &str) -> Result<()> {
    let out = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            OtError::Pack(format!(
                "could not run {name}: {e} — is {name} installed and on PATH?"
            ))
        })?;
    if out.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&out.stderr);
    let detail = detail.trim();
    let code = out
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "a signal".to_string());
    Err(OtError::Pack(if detail.is_empty() {
        format!("{name} exited with {code}")
    } else {
        format!("{name} exited with {code}: {detail}")
    }))
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

    /// F-P2-029: ADR-0019 `:66` states that *every* unknown name points at
    /// `otsniff pack list`. The suggestion branch did not.
    #[test]
    fn every_unknown_subcommand_error_points_somewhere_useful() {
        for name in ["frobnicate", "analyse", "wbe", "ab", "", "x"] {
            let msg = unknown_subcommand(name).to_string();
            assert!(
                msg.contains("pack list"),
                "{name:?} left the operator with nowhere to go: {msg}"
            );
        }
        // A known-but-uninstalled pack is the one case that points at
        // `pack add` instead, which is strictly more useful.
        let msg = unknown_subcommand("web").to_string();
        assert!(msg.contains("pack add web"), "got: {msg}");
    }

    /// The suggestion list is hand-maintained; assert it matches the
    /// subcommands clap actually accepts, so adding one to the CLI without
    /// adding it here is caught.
    /// **ADV-P2 F-P2-035.** This used to compare against the raw
    /// `get_subcommands()` list, which also yields clap's
    /// `external_subcommand` placeholder and (depending on clap's version
    /// and the command's configuration) a `help` entry — neither of which is
    /// in the constant. So the assertion either passed on a clap
    /// implementation detail that could change under us, or quietly
    /// tolerated an entry it should have caught. Filter both explicitly, and
    /// assert the filtering is real rather than assuming it.
    #[test]
    fn builtin_subcommand_list_matches_the_cli() {
        use clap::CommandFactory;
        let cmd = crate::cli::Cli::command();
        let all: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();

        let mut from_clap: Vec<String> = all
            .iter()
            .filter(|n| n.as_str() != "help")
            .filter(|n| !n.is_empty())
            .cloned()
            .collect();
        from_clap.sort();
        from_clap.dedup();

        let mut declared: Vec<String> = BUILTIN_SUBCOMMANDS.iter().map(|s| s.to_string()).collect();
        declared.sort();
        assert_eq!(
            declared, from_clap,
            "packs::BUILTIN_SUBCOMMANDS is out of sync with the clap definition \
             (clap reported {all:?})"
        );

        // Negative case: the list must be exact, not merely a subset. If
        // this ever passes, the assertion above is comparing sets loosely.
        let mut padded = declared.clone();
        padded.push("definitely-not-a-subcommand".to_string());
        padded.sort();
        assert_ne!(
            padded, from_clap,
            "the comparison is not exact — an extra entry was tolerated"
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

    // -----------------------------------------------------------------
    // ADV-P2 F-P2-008: `add()`'s install path had zero coverage. These
    // exercise the extracted core directly — every deletion the reviewer
    // listed as surviving a green suite now fails one of them.
    // -----------------------------------------------------------------

    /// Sets up an "extracted archive" and a destination directory.
    fn staged_release(tmp: &TempDir, body: &[u8]) -> (PathBuf, PathBuf) {
        let stem = tmp.0.join("otsniff-web-v1.0.0-t");
        std::fs::create_dir_all(&stem).unwrap();
        let extracted = stem.join("otsniff-web");
        std::fs::write(&extracted, body).unwrap();
        let dest_dir = tmp.0.join("bin");
        std::fs::create_dir_all(&dest_dir).unwrap();
        (extracted, dest_dir)
    }

    #[test]
    #[cfg(unix)]
    fn install_binary_places_the_file_executable_and_leaves_no_staging_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let (extracted, dest_dir) = staged_release(&tmp, b"#!/bin/sh\nexit 0\n");

        let dest = install_binary(&extracted, &dest_dir, "otsniff-web", "t.tar.gz", "s").unwrap();
        assert_eq!(dest, dest_dir.join("otsniff-web"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"#!/bin/sh\nexit 0\n");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o755,
            "installed pack must be exactly 0755, got {mode:o}"
        );

        let leftovers: Vec<_> = std::fs::read_dir(&dest_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging file left behind: {leftovers:?}"
        );
    }

    /// F-P1-007: the destination may be a symlink under stow/chezmoi/brew.
    /// It must be *replaced*, not written through.
    #[test]
    #[cfg(unix)]
    fn install_binary_replaces_a_destination_symlink_without_touching_its_target() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let (extracted, dest_dir) = staged_release(&tmp, b"new");

        let victim = tmp.0.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&victim, dest_dir.join("otsniff-web")).unwrap();

        let dest = install_binary(&extracted, &dest_dir, "otsniff-web", "t.tar.gz", "s").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o600,
            "the symlink target's mode was changed"
        );
        assert!(
            !std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the destination is still a symlink"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    /// F-P2-004/F-P2-024: a symlinked archive member installs its *target's*
    /// contents as the pack, because `is_file()` follows symlinks.
    #[test]
    #[cfg(unix)]
    fn install_binary_refuses_a_symlinked_archive_member() {
        let tmp = TempDir::new().unwrap();
        let (extracted, dest_dir) = staged_release(&tmp, b"ignored");
        let secret = tmp.0.join("secret");
        std::fs::write(&secret, b"not yours").unwrap();
        std::fs::remove_file(&extracted).unwrap();
        std::os::unix::fs::symlink(&secret, &extracted).unwrap();

        let err = install_binary(&extracted, &dest_dir, "otsniff-web", "t.tar.gz", "s")
            .expect_err("a symlink member must be refused");
        assert!(err.to_string().contains("symlink"), "got: {err}");
        assert_eq!(err.exit_code(), 76, "integrity failures exit 76 (F-P2-028)");
        assert!(!dest_dir.join("otsniff-web").exists());
    }

    #[test]
    fn install_binary_refuses_an_archive_missing_the_binary() {
        let tmp = TempDir::new().unwrap();
        let (extracted, dest_dir) = staged_release(&tmp, b"x");
        std::fs::remove_file(&extracted).unwrap();
        let err = install_binary(&extracted, &dest_dir, "otsniff-web", "t.tar.gz", "s")
            .expect_err("a missing member must be refused");
        assert!(err.to_string().contains("did not contain"), "got: {err}");
    }

    /// F-P2-010: the staging path must be created exclusively, so a
    /// pre-planted symlink there is not written through.
    #[test]
    #[cfg(unix)]
    fn staged_creation_refuses_a_pre_planted_path() {
        let tmp = TempDir::new().unwrap();
        let victim = tmp.0.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        let planted = tmp.0.join(".planted");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        assert!(
            Staged::create(planted).is_err(),
            "create_new must refuse an existing path, symlink included"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
    }

    /// F-P2-037: the staged file must not survive an error return.
    #[test]
    fn staged_file_is_removed_when_not_kept() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.0.join(".scratch");
        {
            let _staged = Staged::create(path.clone()).unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists(), "staged file leaked on drop");
    }

    // -----------------------------------------------------------------
    // ADV-P2 F-P2-007: `remove()`'s deletion path was entirely untested —
    // only the refusal branch was covered, so turning the whole function
    // into `Ok(())` killed no test.
    // -----------------------------------------------------------------

    /// `remove` targets exactly `install_dir()/otsniff-<name>`, so these
    /// drive it through the env var rather than reimplementing it.
    fn with_install_dir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        // Serialized: the tests in this block all mutate the same env var.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var_os("OTSNIFF_INSTALL_DIR");
        // SAFETY: guarded by LOCK, and every caller restores the previous
        // value before releasing it.
        unsafe { std::env::set_var("OTSNIFF_INSTALL_DIR", dir) };
        let out = f();
        match previous {
            Some(v) => unsafe { std::env::set_var("OTSNIFF_INSTALL_DIR", v) },
            None => unsafe { std::env::remove_var("OTSNIFF_INSTALL_DIR") },
        }
        out
    }

    #[test]
    #[cfg(unix)]
    fn remove_deletes_the_installed_pack_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.0.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        let planted = dir.join(binary_name("web"));
        write_executable(&planted);

        with_install_dir(&dir, || {
            remove("web").expect("removing an installed pack must succeed");
            assert!(!planted.exists(), "remove() did not delete the file");
            // Second call must report "not installed", not succeed again and
            // not walk PATH deleting something else.
            let err = remove("web").expect_err("a second remove must not succeed");
            assert!(err.to_string().contains("not installed"), "got: {err}");
        });
    }

    /// F-P2-021: `remove` used a bare `is_file()` while `resolve`/`list`
    /// require the execute bit — so a 0644 `otsniff-web` was reported *not*
    /// installed by `pack list` and **deleted** by `pack remove`. The two
    /// must agree about what exists; `list` now names the state.
    #[test]
    #[cfg(unix)]
    fn a_non_executable_pack_file_is_reported_by_list_and_removable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.0.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        let planted = dir.join(binary_name("web"));
        std::fs::write(&planted, b"").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o644)).unwrap();

        with_install_dir(&dir, || {
            let listing = render_list();
            assert!(
                listing.contains("present but not executable"),
                "list must not report a present file as absent: {listing}"
            );
            remove("web").expect("a file `list` reports must be removable");
            assert!(!planted.exists());
        });
    }

    /// F-P2-016: third-party packs dispatch but could not be listed or
    /// removed, so a planted `otsniff-acme` was neither auditable nor
    /// removable through the tool that would happily run it.
    #[test]
    #[cfg(unix)]
    fn third_party_packs_are_listed_and_removable() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.0.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        let planted = dir.join("otsniff-acme");
        write_executable(&planted);
        // Not a pack binary at all — must not be reported.
        write_executable(&dir.join("unrelated-tool"));

        with_install_dir(&dir, || {
            let found = installed_in_dir(&dir);
            assert!(
                found.iter().any(|(n, _)| n == "acme"),
                "installed_in_dir missed otsniff-acme: {found:?}"
            );
            assert!(
                !found.iter().any(|(n, _)| n == "unrelated-tool"),
                "installed_in_dir picked up a non-pack: {found:?}"
            );

            let listing = render_list();
            assert!(
                listing.contains("acme"),
                "a dispatchable pack must appear in `pack list`: {listing}"
            );

            remove("acme").expect("a pack otsniff will run must be removable");
            assert!(!planted.exists());
        });
    }

    #[test]
    fn remove_still_rejects_a_name_that_is_neither_a_pack_nor_installed() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.0.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        with_install_dir(&dir, || {
            let err = remove("nosuchpack").expect_err("must reject");
            assert!(err.to_string().contains("no such pack"), "got: {err}");
            let err = remove("../../etc").expect_err("must reject a traversal");
            assert!(err.to_string().contains("no such pack"), "got: {err}");
        });
    }

    // -----------------------------------------------------------------
    // ADV-P2 F-P2-019/020: the did-you-mean length guard was dead code, and
    // the test guarding it was tautological — `"frobnicate"` is filtered by
    // the distance check alone, so deleting the guard left it green.
    // -----------------------------------------------------------------

    #[test]
    fn two_character_noise_gets_generic_guidance_not_a_confident_wrong_guess() {
        // The guard is `input length > edit distance`. What it has to reject
        // is an input *no longer than the distance itself* — at that point
        // more than half the string is being invented, and the "suggestion"
        // is really just the nearest short word. The reviewer reproduced
        // exactly this: ab→web, pk→pack, df→diff, di→diff — each two
        // characters, each at distance 2.
        for noise in ["ab", "pk", "df", "di", "a", "z", ""] {
            assert_eq!(
                nearest_subcommand(noise),
                None,
                "{noise:?} is mostly invented characters; it must not produce a \
                 confident suggestion"
            );
            let msg = unknown_subcommand(noise).to_string();
            assert!(
                !msg.contains("did you mean"),
                "{noise:?} got a bogus suggestion: {msg}"
            );
            assert!(msg.contains("pack list"), "{noise:?}: {msg}");
        }

        // …while a genuine one-character slip still suggests, so the guard
        // is not just "reject everything short". `we`/`wb` are one edit from
        // `web`; that is a dropped keystroke, not noise.
        for (typo, expected) in [
            ("dif", "diff"),
            ("we", "web"),
            ("wb", "web"),
            ("web", "web"),
        ] {
            assert_eq!(
                nearest_subcommand(typo),
                Some(expected),
                "{typo:?} is one edit from {expected:?} and should still suggest it"
            );
        }
    }

    /// F-P2-042: `edit_distance` allocated over raw argv with no cap.
    #[test]
    fn an_enormous_subcommand_name_is_not_scored() {
        let huge = "a".repeat(200_000);
        assert_eq!(nearest_subcommand(&huge), None);
        let msg = unknown_subcommand(&huge).to_string();
        assert!(
            msg.len() < 500,
            "the error echoed the whole argv back ({} bytes)",
            msg.len()
        );
    }

    /// F-P2-041: unbounded, unsanitized argv echoed to a terminal.
    #[test]
    fn control_characters_in_a_subcommand_name_are_escaped() {
        let hostile = "\u{1b}]0;pwned\u{7}";
        let msg = unknown_subcommand(hostile).to_string();
        assert!(
            !msg.contains('\u{1b}'),
            "terminal escape reached stderr verbatim: {msg:?}"
        );
        assert!(msg.contains("\\x1b"), "got: {msg:?}");
        assert!(
            !unknown_pack(hostile).to_string().contains('\u{1b}'),
            "the `pack add` error path is unsanitized too"
        );
    }

    /// F-P2-022: the two sidecar parsers diverged, and neither checked the
    /// filename field.
    #[test]
    fn the_sidecar_filename_field_must_name_the_artifact_being_verified() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // Correct name — accepted, with and without the binary-mode `*`.
        assert!(expected_digest(&format!("{hex}  t.tar.gz\n"), "t.tar.gz").is_ok());
        assert!(expected_digest(&format!("{hex} *t.tar.gz\n"), "t.tar.gz").is_ok());
        // No name at all — accepted; some tools emit digest-only sidecars.
        assert!(expected_digest(&format!("{hex}\n"), "t.tar.gz").is_ok());
        // A different artifact — refused.
        let err = expected_digest(&format!("{hex}  other.tar.gz\n"), "t.tar.gz")
            .expect_err("a sidecar naming another file must be refused");
        assert!(
            err.to_string().contains("names a different file"),
            "got: {err}"
        );
        assert_eq!(err.exit_code(), 76);
    }

    /// F-P2-022: a leading blank line was accepted by the Rust copy and
    /// rejected by the shell copy, while ADR-0019 claimed both parsed it the
    /// same way. Line 1 is the sha256sum format; both refuse it now.
    #[test]
    fn a_sidecar_whose_first_line_is_not_a_digest_is_refused() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = expected_digest(&format!("\n{hex}  t.tar.gz\n"), "t.tar.gz")
            .expect_err("the digest must be on line 1");
        assert!(err.to_string().contains("does not contain"), "got: {err}");
    }

    /// F-P2-045: the aarch64-Linux guard could only run on a runner CI does
    /// not have, so deleting it left the suite green.
    #[test]
    fn triple_mapping_covers_every_published_target_and_refuses_the_rest() {
        assert_eq!(
            triple_for("x86_64", "macos").unwrap(),
            "x86_64-apple-darwin"
        );
        assert_eq!(
            triple_for("aarch64", "macos").unwrap(),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            triple_for("x86_64", "linux").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            triple_for("x86_64", "windows").unwrap(),
            "x86_64-pc-windows-msvc"
        );

        // F-P1-019: release.yml publishes no aarch64-Linux artifact, so the
        // URL would 404 with a misleading "release may not exist".
        let err = triple_for("aarch64", "linux").expect_err("aarch64 Linux is not published");
        assert!(err.to_string().contains("aarch64 Linux"), "got: {err}");

        for (arch, os) in [("riscv64", "linux"), ("x86_64", "freebsd")] {
            assert!(
                triple_for(arch, os).is_err(),
                "{arch}-{os} is not a published target"
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

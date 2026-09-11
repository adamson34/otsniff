//! Pack system (ADR-0019).
//!
//! A pack is an optional component distributed as its own binary,
//! `otsniff-<name>`, installed next to the core binary. `otsniff <name>
//! …` dispatches to it the way `git foo` finds `git-foo`, so an installed
//! pack behaves like a built-in subcommand.
//!
//! Everything here shells out to tools the operator already has (`curl`,
//! `tar`, `sha256sum`/`shasum`) rather than embedding an HTTP client —
//! same stance ADR-0007 took for the AI providers. `pack add` constructs
//! the release URL itself and verifies the checksum before placing
//! anything; it never executes downloaded shell code.

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
        return Ok(PathBuf::from(dir));
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

/// Locate an installed pack binary: next to the running `otsniff` first,
/// then `PATH` (ADR-0019 D2 — sibling-first so the common install layout
/// never consults `PATH`, and an unrelated `PATH` entry can't shadow an
/// installed pack).
pub fn resolve(name: &str) -> Option<PathBuf> {
    resolve_in(search_dirs(), &binary_name(name))
}

/// Search order as an iterator, split out so [`resolve_in`] is testable
/// without mutating the process environment.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    dirs
}

fn resolve_in(dirs: Vec<PathBuf>, binary: &str) -> Option<PathBuf> {
    dirs.into_iter()
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

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
        None => Err(unknown_error(&name)),
    }
}

/// Error for a subcommand that is neither built in nor an installed pack.
/// Distinguishes "known pack, not installed" from "no such thing" — clap's
/// generic "unrecognized subcommand" can't, now that unknown subcommands
/// are a meaningful category.
fn unknown_error(name: &str) -> OtError {
    if find(name).is_some() {
        OtError::Pack(format!(
            "the '{name}' pack is not installed — run `otsniff pack add {name}`"
        ))
    } else {
        OtError::Pack(format!(
            "unknown subcommand '{name}' — run `otsniff --help` for built-in commands \
             or `otsniff pack list` for optional packs"
        ))
    }
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
    Ok(format!("{arch}-{os}"))
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
    let pack = find(name).ok_or_else(|| unknown_error(name))?;

    if cfg!(windows) {
        return Err(OtError::Pack(format!(
            "`pack add` isn't supported on Windows yet — download \
             otsniff-{name} from https://github.com/{REPO}/releases and put it \
             next to otsniff.exe"
        )));
    }

    let target = target_triple()?;
    let tag = match version {
        Some(v) if v.starts_with('v') => v.to_string(),
        Some(v) => format!("v{v}"),
        None => format!("v{}", crate::VERSION),
    };
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
    run(
        Command::new("tar")
            .arg("xzf")
            .arg(&tarball)
            .current_dir(&tmp.0),
        "tar",
    )?;

    let binary = binary_name(pack.name);
    let extracted = tmp.0.join(&stem).join(&binary);
    if !extracted.is_file() {
        return Err(OtError::Pack(format!(
            "{tarball} did not contain {stem}/{binary} — the release artifact \
             looks malformed; please file a bug"
        )));
    }

    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| OtError::Pack(format!("could not create {}: {e}", dest_dir.display())))?;
    let dest = dest_dir.join(&binary);
    std::fs::copy(&extracted, &dest).map_err(|e| {
        OtError::Pack(format!(
            "could not install to {} ({e}) — re-run with write access to that \
             directory, or set OTSNIFF_INSTALL_DIR to somewhere you can write",
            dest.display()
        ))
    })?;
    make_executable(&dest)?;

    // The binary isn't notarized; without this macOS Gatekeeper blocks it.
    // Same step install.sh takes for the core binary.
    if std::env::consts::OS == "macos" {
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&dest)
            .status();
    }

    eprintln!("installed {} → {}", pack.name, dest.display());
    eprintln!("run it with: otsniff {} --help", pack.name);
    Ok(())
}

/// Deletes an installed pack's binary. Packs keep no state outside their
/// own data directories, so this never touches user data.
pub fn remove(name: &str) -> Result<()> {
    find(name).ok_or_else(|| unknown_error(name))?;
    let Some(path) = resolve(name) else {
        return Err(OtError::Pack(format!("the '{name}' pack is not installed")));
    };
    std::fs::remove_file(&path)
        .map_err(|e| OtError::Pack(format!("could not remove {}: {e}", path.display())))?;
    eprintln!("removed {} ({})", name, path.display());
    Ok(())
}

fn curl(url: &str, dest: &Path) -> Result<()> {
    run(
        Command::new("curl").args(["-fsSL", url, "-o"]).arg(dest),
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

/// Verifies with whichever checksum tool is present, and refuses to
/// install if neither is — the same fail-closed stance `install.sh` takes.
fn verify_checksum(dir: &Path, tarball: &str) -> Result<()> {
    let sidecar = format!("{tarball}.sha256");
    let ok = if which("sha256sum") {
        run(
            Command::new("sha256sum")
                .args(["-c", &sidecar])
                .current_dir(dir),
            "sha256sum",
        )
    } else if which("shasum") {
        run(
            Command::new("shasum")
                .args(["-a", "256", "-c", &sidecar])
                .current_dir(dir),
            "shasum",
        )
    } else {
        return Err(OtError::Pack(
            "neither sha256sum nor shasum is available; refusing to install \
             without checksum verification"
                .to_string(),
        ));
    };
    ok.map_err(|_| {
        OtError::Pack(format!(
            "checksum verification FAILED for {tarball} — refusing to install"
        ))
    })
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
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

/// Scratch directory that cleans itself up, including on the `?` early
/// returns above. `tempfile` is a dev-dependency only — promoting it to a
/// runtime dep for ten lines isn't worth it.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let nanos = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let dir = std::env::temp_dir().join(format!("otsniff-pack-{nanos:x}"));
        std::fs::create_dir_all(&dir)
            .map_err(|e| OtError::Pack(format!("could not create {}: {e}", dir.display())))?;
        Ok(TempDir(dir))
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
        std::fs::write(second.join("otsniff-web"), b"").unwrap();

        // Only the second directory has it.
        let found = resolve_in(vec![first.clone(), second.clone()], "otsniff-web");
        assert_eq!(found, Some(second.join("otsniff-web")));

        // Once both do, the earlier directory wins (sibling-before-PATH).
        std::fs::write(first.join("otsniff-web"), b"").unwrap();
        let found = resolve_in(vec![first.clone(), second], "otsniff-web");
        assert_eq!(found, Some(first.join("otsniff-web")));
    }

    #[test]
    fn resolve_in_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        assert!(resolve_in(vec![tmp.0.clone()], "otsniff-web").is_none());
    }

    #[test]
    fn unknown_error_distinguishes_uninstalled_from_nonexistent() {
        // A real pack that isn't installed points at `pack add`.
        let msg = unknown_error("web").to_string();
        assert!(msg.contains("pack add web"), "got: {msg}");

        // Something that isn't a pack at all points at help/list.
        let msg = unknown_error("frobnicate").to_string();
        assert!(msg.contains("unknown subcommand"), "got: {msg}");
        assert!(msg.contains("pack list"), "got: {msg}");
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

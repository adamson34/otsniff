//! End-to-end tests for `install.sh`.
//!
//! **ADV-P2 F-P2-018 / F-P2-008.** The installer was the least-tested and
//! most-exposed code in the repo: it is delivered via `curl … | sh`, four
//! security fixes landed in it across two review passes, and reverting any
//! of them broke nothing. Green CI was not evidence those fixes held.
//!
//! The script is untestable only in the sense that it downloads. So we stub
//! `curl` — a shell script early on `PATH` that serves a fixture directory
//! — and let everything else (`tar`, `install`, `mktemp`, `sha256sum`,
//! `mv`, the whole control flow) run for real against a real filesystem.
//! Each test below asserts a specific finding's fix, so deleting the fix
//! fails the suite.
//!
//! Unix-only: `install.sh` is not the Windows install path.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VERSION: &str = "v9.9.9";

/// The triple `install.sh` derives from `uname`, computed the same way the
/// script does so the fixture names match on every runner.
fn target() -> String {
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        other => panic!("install.sh has no branch for {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => panic!("install.sh has no branch for {other}"),
    };
    format!("{arch}-{os}")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A scratch area with a fixture "release server", a stub `curl`, and an
/// install directory.
struct Sandbox {
    root: PathBuf,
    serve: PathBuf,
    bin: PathBuf,
    install_dir: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "otsniff-install-test-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        let serve = root.join("serve");
        let bin = root.join("stubbin");
        let install_dir = root.join("install");
        for d in [&serve, &bin, &install_dir] {
            fs::create_dir_all(d).unwrap();
        }
        let sandbox = Sandbox {
            root,
            serve,
            bin,
            install_dir,
        };
        sandbox.write_stub_curl();
        sandbox
    }

    /// Serves `$OTSNIFF_TEST_SERVE/<basename of url>`, mimicking curl's
    /// exit 22 for a missing resource under `-f`. Parses only the flags
    /// `install.sh` actually passes.
    fn write_stub_curl(&self) {
        let script = r#"#!/bin/sh
dest=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) dest="$2"; shift 2 ;;
        --) shift; url="$1"; shift ;;
        *) shift ;;
    esac
done
[ -n "$url" ] || { echo "stub-curl: no url" >&2; exit 2; }
src="$OTSNIFF_TEST_SERVE/$(basename "$url")"
if [ ! -f "$src" ]; then
    echo "curl: (22) The requested URL returned error: 404" >&2
    exit 22
fi
cat "$src" > "$dest"
"#;
        let path = self.bin.join("curl");
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Builds `<base>-<VERSION>-<target>.tar.gz` containing a working
    /// stub binary, plus its sha256 sidecar, into the served directory.
    fn publish(&self, base: &str) {
        self.publish_with(base, PublishOpts::default());
    }

    fn publish_with(&self, base: &str, opts: PublishOpts) {
        let stem = format!("{base}-{VERSION}-{}", target());
        let staging = self.root.join("staging");
        let _ = fs::remove_dir_all(&staging);
        let dir = staging.join(&stem);
        fs::create_dir_all(&dir).unwrap();

        let member = dir.join(base);
        if opts.symlink_member {
            // F-P2-004: a release artifact whose binary member is a symlink.
            std::os::unix::fs::symlink(
                opts.symlink_target
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/etc/hosts")),
                &member,
            )
            .unwrap();
        } else {
            let body = if opts.broken {
                // Runs, but exits non-zero for every invocation.
                "#!/bin/sh\nexit 3\n".to_string()
            } else {
                format!("#!/bin/sh\necho '{base} {VERSION}'\n")
            };
            fs::write(&member, body).unwrap();
            fs::set_permissions(&member, fs::Permissions::from_mode(opts.mode)).unwrap();
        }

        let tarball = format!("{stem}.tar.gz");
        let status = Command::new("tar")
            .args(["czf", &tarball, &stem])
            .current_dir(&staging)
            .status()
            .unwrap();
        assert!(status.success(), "fixture tar failed");
        fs::rename(staging.join(&tarball), self.serve.join(&tarball)).unwrap();

        let digest = if opts.bad_digest {
            "0".repeat(64)
        } else {
            sha256_hex(&self.serve.join(&tarball))
        };
        let named = opts.sidecar_name.clone().unwrap_or_else(|| tarball.clone());
        fs::write(
            self.serve.join(format!("{tarball}.sha256")),
            format!("{digest}  {named}\n"),
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_dir(args, self.install_dir.to_str().unwrap())
    }

    fn run_with_dir(&self, args: &[&str], install_dir: &str) -> Output {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("sh")
            .arg(repo_root().join("install.sh"))
            .args(args)
            .env("PATH", path)
            .env("OTSNIFF_TEST_SERVE", &self.serve)
            .env("OTSNIFF_INSTALL_DIR", install_dir)
            .env("TMPDIR", self.root.join("tmp"))
            .current_dir(&self.root)
            .output()
            .unwrap()
    }

    fn installed(&self, base: &str) -> PathBuf {
        self.install_dir.join(base)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct PublishOpts {
    mode: u32,
    bad_digest: bool,
    symlink_member: bool,
    symlink_target: Option<PathBuf>,
    sidecar_name: Option<String>,
    broken: bool,
}

impl Default for PublishOpts {
    fn default() -> Self {
        PublishOpts {
            mode: 0o755,
            bad_digest: false,
            symlink_member: false,
            symlink_target: None,
            sidecar_name: None,
            broken: false,
        }
    }
}

/// Reuses the crate's own hasher so the fixture sidecars are generated by
/// exactly the code `pack add` verifies with.
fn sha256_hex(path: &Path) -> String {
    otsniff::audit::sha256_file_hex(path).unwrap().1
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ---------------------------------------------------------------------------
// Happy path — the baseline every negative test is measured against.
// ---------------------------------------------------------------------------

#[test]
fn installs_the_core_binary_and_makes_it_executable() {
    let sb = Sandbox::new("happy");
    sb.publish("otsniff");
    let out = sb.run(&[VERSION]);
    assert!(out.status.success(), "install failed: {}", combined(&out));

    let installed = sb.installed("otsniff");
    assert!(installed.is_file(), "binary not installed");
    let mode = fs::metadata(&installed).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "installed binary must be 0755, got {mode:o}");
    assert!(
        combined(&out).contains("Installed:"),
        "no success banner: {}",
        combined(&out)
    );

    // No staging leftovers in the install dir.
    let leftovers: Vec<_> = fs::read_dir(&sb.install_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files left behind: {leftovers:?}"
    );
}

// ---------------------------------------------------------------------------
// F-P2-002 — version charset validation (both entry points).
// ---------------------------------------------------------------------------

#[test]
fn a_traversing_version_is_refused_before_any_download() {
    let sb = Sandbox::new("traverse");
    sb.publish("otsniff");
    for bad in [
        "../../../../etc",
        "v1.0.0/../../other",
        "v1 0 0",
        "v1.0.0;id",
    ] {
        let out = sb.run(&[bad]);
        assert!(!out.status.success(), "{bad:?} must be refused");
        assert!(
            stderr(&out).contains("refusing version"),
            "{bad:?}: {}",
            stderr(&out)
        );
        assert!(
            !sb.installed("otsniff").exists(),
            "{bad:?} installed anyway"
        );
    }
}

#[test]
fn a_traversing_version_from_the_env_var_is_refused_too() {
    // The env var is the *other* entry point; ADV-P1 validated only one.
    let sb = Sandbox::new("traverse-env");
    sb.publish("otsniff");
    let path = format!(
        "{}:{}",
        sb.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("PATH", path)
        .env("OTSNIFF_TEST_SERVE", &sb.serve)
        .env("OTSNIFF_INSTALL_DIR", &sb.install_dir)
        .env("OTSNIFF_VERSION", "../../../../etc")
        .env("TMPDIR", sb.root.join("tmp"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("refusing version"),
        "{}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// F-P2-005 — a relative install dir must be refused, not silently diverge.
// ---------------------------------------------------------------------------

#[test]
fn a_relative_install_dir_is_refused() {
    let sb = Sandbox::new("relative");
    sb.publish("otsniff");
    for bad in [".", "relative/bin", ""] {
        let out = sb.run_with_dir(&[VERSION], bad);
        assert!(!out.status.success(), "{bad:?} must be refused");
        assert!(
            stderr(&out).contains("absolute path") || stderr(&out).contains("no default install"),
            "{bad:?}: {}",
            stderr(&out)
        );
    }
    assert!(
        !sb.root.join("otsniff").exists(),
        "a relative install dir wrote into the CWD"
    );
}

// ---------------------------------------------------------------------------
// F-P1-001 / F-P2-022 — checksum verification is fail-closed.
// ---------------------------------------------------------------------------

#[test]
fn a_mismatched_checksum_refuses_to_install() {
    let sb = Sandbox::new("badsum");
    sb.publish_with(
        "otsniff",
        PublishOpts {
            bad_digest: true,
            ..Default::default()
        },
    );
    let out = sb.run(&[VERSION]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("checksum verification FAILED"),
        "{}",
        stderr(&out)
    );
    assert!(
        !sb.installed("otsniff").exists(),
        "installed despite mismatch"
    );
}

#[test]
fn an_empty_or_html_sidecar_refuses_to_install() {
    // The macOS `sha256sum -c` fail-open case (F-P1-001), still closed.
    let sb = Sandbox::new("htmlsum");
    sb.publish("otsniff");
    let sidecar = sb
        .serve
        .join(format!("otsniff-{VERSION}-{}.tar.gz.sha256", target()));
    for body in ["", "\n", "<html><body>404 Not Found</body></html>\n"] {
        fs::write(&sidecar, body).unwrap();
        let out = sb.run(&[VERSION]);
        assert!(!out.status.success(), "sidecar {body:?} must be refused");
        assert!(
            stderr(&out).contains("does not contain a SHA-256 digest"),
            "sidecar {body:?}: {}",
            stderr(&out)
        );
        assert!(!sb.installed("otsniff").exists());
    }
}

/// F-P2-022: neither copy checked the sidecar's *filename* field, so a
/// sidecar naming a different artifact was accepted on digest alone.
#[test]
fn a_sidecar_naming_a_different_artifact_is_refused() {
    let sb = Sandbox::new("wrongname");
    sb.publish_with(
        "otsniff",
        PublishOpts {
            sidecar_name: Some("otsniff-v0.0.1-some-other-target.tar.gz".to_string()),
            ..Default::default()
        },
    );
    let out = sb.run(&[VERSION]);
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        stderr(&out).contains("names a different file"),
        "{}",
        stderr(&out)
    );
    assert!(!sb.installed("otsniff").exists());
}

// ---------------------------------------------------------------------------
// F-P2-004 — symlink archive member (root arbitrary-chmod primitive).
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_archive_member_is_refused_and_the_victim_is_untouched() {
    let sb = Sandbox::new("symmember");
    let victim = sb.root.join("victim");
    fs::write(&victim, b"secret").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();

    sb.publish_with(
        "otsniff",
        PublishOpts {
            symlink_member: true,
            symlink_target: Some(victim.clone()),
            ..Default::default()
        },
    );
    let out = sb.run(&[VERSION]);
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(stderr(&out).contains("symlink"), "{}", stderr(&out));

    let mode = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the victim file was chmod'd through the symlink (got {mode:o})"
    );
    assert!(!sb.installed("otsniff").exists());
}

// ---------------------------------------------------------------------------
// F-P2-003 — a symlink at the destination must be replaced, not written
// through. This is the stow/chezmoi/Homebrew upgrade shape.
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_at_the_destination_is_replaced_not_written_through() {
    let sb = Sandbox::new("destsym");
    sb.publish("otsniff");

    let victim = sb.root.join("managed-copy");
    fs::write(&victim, b"original contents").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&victim, sb.installed("otsniff")).unwrap();

    let out = sb.run(&[VERSION]);
    assert!(out.status.success(), "{}", combined(&out));

    assert_eq!(
        fs::read(&victim).unwrap(),
        b"original contents",
        "the installer wrote through the destination symlink"
    );
    let vmode = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        vmode, 0o600,
        "the victim's mode was changed (got {vmode:o})"
    );

    let installed = sb.installed("otsniff");
    assert!(
        !fs::symlink_metadata(&installed)
            .unwrap()
            .file_type()
            .is_symlink(),
        "destination is still a symlink — the rename did not replace it"
    );
    assert!(fs::read(&installed).unwrap().starts_with(b"#!/bin/sh"));
}

// ---------------------------------------------------------------------------
// F-P1-005 — the archive must not choose the installed mode.
// ---------------------------------------------------------------------------

#[test]
fn a_setuid_archive_member_does_not_install_setuid() {
    let sb = Sandbox::new("setuid");
    sb.publish_with(
        "otsniff",
        PublishOpts {
            mode: 0o4755,
            ..Default::default()
        },
    );
    let out = sb.run(&[VERSION]);
    assert!(out.status.success(), "{}", combined(&out));
    let mode = fs::metadata(sb.installed("otsniff"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        mode, 0o755,
        "archive member mode leaked into the install (got {mode:o})"
    );
}

// ---------------------------------------------------------------------------
// Packs: F-P1-020 (a pack failure must not sink the core), F-P2-014 (a pack
// that will not run must not be left installed), F-P2-043 (name handling).
// ---------------------------------------------------------------------------

#[test]
fn a_requested_pack_installs_alongside_the_core() {
    let sb = Sandbox::new("pack-ok");
    sb.publish("otsniff");
    sb.publish("otsniff-web");
    let out = sb.run(&[VERSION, "--packs", "web"]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(sb.installed("otsniff").is_file());
    assert!(sb.installed("otsniff-web").is_file());
    assert!(combined(&out).contains("Packs:"), "{}", combined(&out));
}

#[test]
fn a_failing_pack_does_not_sink_the_core_install() {
    let sb = Sandbox::new("pack-404");
    sb.publish("otsniff"); // no otsniff-web artifact published
    let out = sb.run(&[VERSION, "--packs", "web"]);
    assert!(
        !out.status.success(),
        "a failed pack must still be a non-zero overall status"
    );
    assert!(
        sb.installed("otsniff").is_file(),
        "the core was rolled back by a pack failure"
    );
    assert!(combined(&out).contains("FAILED:"), "{}", combined(&out));
    assert!(
        combined(&out).contains("Installed:"),
        "the success banner must still print: {}",
        combined(&out)
    );
}

/// F-P2-014: a pack that installs but cannot execute was reported FAILED
/// while staying mode-0755 in $INSTALL_DIR — where `otsniff pack list`
/// reports it installed and dispatch runs it.
#[test]
fn a_pack_that_cannot_run_is_not_left_installed() {
    let sb = Sandbox::new("pack-broken");
    sb.publish("otsniff");
    sb.publish_with(
        "otsniff-web",
        PublishOpts {
            broken: true,
            ..Default::default()
        },
    );
    let out = sb.run(&[VERSION, "--packs", "web"]);
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("FAILED:"), "{}", combined(&out));
    assert!(
        !sb.installed("otsniff-web").exists(),
        "reported FAILED but left the pack on disk — `pack list` would call it installed"
    );
    assert!(sb.installed("otsniff").is_file(), "the core must survive");
}

/// F-P2-043: `tr -d '[:space:]'` deleted *internal* whitespace, so
/// `--packs "we b"` silently installed `web`. The Rust copy rejects it.
#[test]
fn a_pack_name_with_internal_whitespace_is_rejected_not_squeezed() {
    let sb = Sandbox::new("pack-space");
    sb.publish("otsniff");
    sb.publish("otsniff-web");
    let out = sb.run(&[VERSION, "--packs", "we b"]);
    assert!(
        combined(&out).contains("invalid pack name"),
        "internal whitespace must be rejected: {}",
        combined(&out)
    );
    assert!(
        !sb.installed("otsniff-web").exists(),
        "'we b' was silently squeezed into 'web' and installed"
    );
}

#[test]
fn surrounding_whitespace_in_a_pack_list_is_still_trimmed() {
    let sb = Sandbox::new("pack-trim");
    sb.publish("otsniff");
    sb.publish("otsniff-web");
    let out = sb.run(&[VERSION, "--packs", "  web  "]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(sb.installed("otsniff-web").is_file());
}

// ---------------------------------------------------------------------------
// F-P1-021 — a glob in a pack name must not expand against the CWD.
// ---------------------------------------------------------------------------

#[test]
fn a_glob_in_a_pack_name_does_not_expand_against_the_cwd() {
    let sb = Sandbox::new("pack-glob");
    sb.publish("otsniff");
    fs::write(sb.root.join("web"), b"decoy").unwrap();
    let out = sb.run(&[VERSION, "--packs", "*"]);
    assert!(
        combined(&out).contains("invalid pack name '*'"),
        "the glob must reach validation unexpanded: {}",
        combined(&out)
    );
}

// ---------------------------------------------------------------------------
// F-P2-012 — a transport failure must be distinguishable from a 404.
// ---------------------------------------------------------------------------

#[test]
fn a_download_failure_surfaces_curls_own_error() {
    let sb = Sandbox::new("curl-err");
    // Nothing published, so the stub curl 404s and prints to stderr.
    let out = sb.run(&[VERSION]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("curl:"),
        "curl's diagnosis must not be swallowed: {}",
        stderr(&out)
    );
}

// ---------------------------------------------------------------------------
// F-P2-040 — $HOME unset, and a glob-shaped install dir.
// ---------------------------------------------------------------------------

#[test]
fn an_unset_home_gives_an_actionable_error_not_unbound_variable() {
    let sb = Sandbox::new("nohome");
    sb.publish("otsniff");
    let path = format!(
        "{}:{}",
        sb.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .arg(VERSION)
        .env_remove("HOME")
        .env_remove("OTSNIFF_INSTALL_DIR")
        .env("PATH", path)
        .env("OTSNIFF_TEST_SERVE", &sb.serve)
        .env("TMPDIR", sb.root.join("tmp"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("OTSNIFF_INSTALL_DIR"),
        "must name the fix, not die on `HOME: unbound variable`: {}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("unbound variable"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_glob_shaped_install_dir_reports_path_membership_correctly() {
    let sb = Sandbox::new("globdir");
    sb.publish("otsniff");
    let odd = sb.root.join("bin[x]");
    fs::create_dir_all(&odd).unwrap();

    let path = format!(
        "{}:{}:{}",
        sb.bin.display(),
        odd.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .arg(VERSION)
        .env("PATH", path)
        .env("OTSNIFF_TEST_SERVE", &sb.serve)
        .env("OTSNIFF_INSTALL_DIR", &odd)
        .env("TMPDIR", sb.root.join("tmp"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", combined(&out));
    assert!(
        !combined(&out).contains("is not on your PATH"),
        "the dir *is* on PATH; glob matching mis-reported it: {}",
        combined(&out)
    );
}

// ---------------------------------------------------------------------------
// F-P2-039 — the install dir must never be created world-writable.
// ---------------------------------------------------------------------------

#[test]
fn a_permissive_umask_does_not_create_a_world_writable_install_dir() {
    let sb = Sandbox::new("umask");
    sb.publish("otsniff");
    let fresh = sb.root.join("fresh-bin");

    let path = format!(
        "{}:{}",
        sb.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // `sh -c 'umask 000; …'` reproduces the reported shape.
    let script = format!(
        "umask 000; exec sh {} {VERSION}",
        repo_root().join("install.sh").display()
    );
    let out = Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("PATH", path)
        .env("OTSNIFF_TEST_SERVE", &sb.serve)
        .env("OTSNIFF_INSTALL_DIR", &fresh)
        .env("TMPDIR", sb.root.join("tmp"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", combined(&out));
    let mode = fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o755,
        "install dir created mode {mode:o} under umask 000"
    );
}

// ---------------------------------------------------------------------------
// F-P2-034 — the artifact naming scheme is defined in three places.
// ---------------------------------------------------------------------------

/// `release.yml` packages the artifacts, `install.sh` and
/// `packs::artifact_stem` independently reconstruct their names. Reordering
/// the stem in any one of them 404s every install while both existing drift
/// guards (which check only the pack *name list*) stay green.
#[test]
fn the_artifact_stem_format_is_the_same_in_all_three_definitions() {
    let workflow = fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    let script = fs::read_to_string(repo_root().join("install.sh")).unwrap();

    // release.yml, core and pack stems.
    assert!(
        workflow.contains(r#"name="otsniff-${GITHUB_REF_NAME}-${{ matrix.target }}""#),
        "release.yml's core stem format changed; update install.sh and packs::artifact_stem too"
    );
    assert!(
        workflow.contains(r#"stem="otsniff-${pack}-${GITHUB_REF_NAME}-${{ matrix.target }}""#),
        "release.yml's pack stem format changed; update install.sh and packs::artifact_stem too"
    );
    // install.sh reconstructs <base>-<version>-<target>.
    assert!(
        script.contains(r#"_stem="${_base}-${VERSION}-${TARGET}""#),
        "install.sh's stem format changed; update release.yml and packs::artifact_stem too"
    );
    // The Rust copy, through its public API.
    assert_eq!(
        otsniff::packs::artifact_stem("web", "v1.2.3", "x86_64-apple-darwin"),
        "otsniff-web-v1.2.3-x86_64-apple-darwin",
        "packs::artifact_stem's format changed; update release.yml and install.sh too"
    );

    // And the tarball suffix + sidecar suffix all three agree on.
    for needle in [".tar.gz", ".sha256"] {
        assert!(workflow.contains(needle), "release.yml lost {needle}");
        assert!(script.contains(needle), "install.sh lost {needle}");
    }
}

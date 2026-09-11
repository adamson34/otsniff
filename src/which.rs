//! Safe executable lookup on `PATH`.
//!
//! Shared by the AI providers (`ai::claude_cli`, `ai::ollama`) and the pack
//! system, because all three answer the same question — "where is this
//! executable?" — and all three got it wrong in the same way.
//!
//! **ADV-P2 F-P2-001 (CRITICAL).** The original per-module copies walked
//! `std::env::split_paths` unfiltered. `split_paths` preserves *empty*
//! components, and `PathBuf::new().join("claude")` is the relative path
//! `claude`, which resolves against the process working directory — so
//! `PATH="/usr/bin:"` made otsniff find and run a `./claude` planted in
//! whatever directory the analyst happened to be in. That is otsniff's
//! core use case: an operator sitting in a directory of third-party
//! captures. A planted binary got arbitrary code execution, the scrubbed
//! report on stdin, and control of a section of the rendered HTML.
//!
//! Two rules, both load-bearing:
//!
//! 1. Only **absolute** directories are searched.
//! 2. Callers must spawn the **returned absolute path**, never the bare
//!    name — `Command::new("claude")` hands resolution back to `execvp`,
//!    which re-walks the raw `PATH` with the same empty-component
//!    semantics and undoes rule 1.

use std::path::{Path, PathBuf};

/// Absolute `PATH` directories, in order. Empty and relative entries are
/// dropped: they resolve against the current working directory.
pub fn path_dirs() -> Vec<PathBuf> {
    match std::env::var_os("PATH") {
        Some(path) => std::env::split_paths(&path)
            .filter(|dir| dir.is_absolute())
            .collect(),
        None => Vec::new(),
    }
}

/// True for a regular file with at least one execute bit.
///
/// `is_file()` alone matches a non-executable file, which would then be
/// handed to `exec` for a confusing failure — and could mask a real
/// executable further down the search path.
#[cfg(unix)]
pub fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Resolves `bin` against the absolute entries of `PATH`.
///
/// Returns the **absolute path**, which the caller must spawn directly.
/// Passing the bare name to `Command::new` instead would defeat the point:
/// `execvp` re-resolves it against the unfiltered `PATH`.
pub fn find_executable(bin: &str) -> Option<PathBuf> {
    find_in(&path_dirs(), bin)
}

/// Search a caller-supplied directory list — the testable core, so tests
/// never have to mutate the process environment.
pub fn find_in(dirs: &[PathBuf], bin: &str) -> Option<PathBuf> {
    dirs.iter()
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(bin))
        .find(|candidate| is_executable_file(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_executable(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn scratch() -> PathBuf {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(std::process::id() as u64);
        let dir = std::env::temp_dir().join(format!("otsniff-which-{:016x}", h.finish()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The CRITICAL: a relative or empty search entry must never be used,
    /// because it resolves against the process CWD.
    #[test]
    fn relative_and_empty_dirs_are_never_searched() {
        let dir = scratch();
        write_executable(&dir.join("claude"));

        // An empty component (what `PATH="/usr/bin:"` produces) and a
        // literal "." must both be ignored, even though a matching file
        // exists relative to the CWD.
        let hostile = vec![
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("relative/dir"),
        ];
        assert_eq!(find_in(&hostile, "claude"), None);

        // The same binary in an absolute dir is found.
        assert_eq!(
            find_in(std::slice::from_ref(&dir), "claude"),
            Some(dir.join("claude"))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_dirs_are_all_absolute() {
        for dir in path_dirs() {
            assert!(dir.is_absolute(), "non-absolute PATH dir leaked: {dir:?}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn non_executable_files_do_not_resolve() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let dud = dir.join("claude");
        std::fs::write(&dud, b"").unwrap();
        std::fs::set_permissions(&dud, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find_in(std::slice::from_ref(&dir), "claude"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_matching_directory_wins() {
        let first = scratch();
        let second = scratch();
        write_executable(&second.join("claude"));
        assert_eq!(
            find_in(&[first.clone(), second.clone()], "claude"),
            Some(second.join("claude"))
        );
        write_executable(&first.join("claude"));
        assert_eq!(
            find_in(&[first.clone(), second.clone()], "claude"),
            Some(first.join("claude"))
        );
        std::fs::remove_dir_all(&first).ok();
        std::fs::remove_dir_all(&second).ok();
    }
}

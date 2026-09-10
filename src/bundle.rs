//! `otsniff bundle` / `unbundle` — encrypted report bundle (P2-7, ADR-0017).
//!
//! The BCSI handling commitment (NERC CIP-011 alignment) is currently a
//! documentation claim — otsniff *says* the scrub map and audit log are
//! sensitive and should be protected at rest, and relies on the operator to
//! do so themselves. `bundle` zips `<stem>.html` / `<stem>.map.json` /
//! `<stem>.audit.json` (whichever exist — missing sidecars are skipped, not
//! an error) into one `age`-encrypted file; `unbundle` reverses it. This
//! doesn't change the privacy invariant (the AI still never sees real
//! values) but closes the at-rest exposure window between `scrub` and
//! `unscrub`, moving BCSI protection from "guidance" to "default behavior."
//!
//! **Container format:** a minimal, otsniff-specific binary framing (magic +
//! count + `[name_len][name][content_len][content]` per file) — not a real
//! ZIP. `bundle`/`unbundle` are always used as a pair by otsniff itself; a
//! real archive format would add a dependency for compatibility nobody
//! needs. See ADR-0017 for the full design (including why passphrases are
//! read from an environment variable, never a bare CLI argument).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;

use crate::error::{OtError, Result};

const MAGIC: &[u8; 8] = b"OTBNDL01";

/// One file as read off disk, ready to be packed into a bundle.
struct BundleEntry {
    name: &'static str,
    content: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct BundleSummary {
    pub files: Vec<String>,
}

/// Derives `<stem>.html` / `<stem>.map.json` / `<stem>.audit.json` from
/// `stem`, reads whichever exist, packs them into the container format, and
/// writes the `age`-encrypted result to `output`. At least one of the three
/// files must exist — an empty bundle is almost certainly a typo'd stem, not
/// intentional.
pub fn bundle(stem: &Path, output: &Path, passphrase: SecretString) -> Result<BundleSummary> {
    let mut entries = Vec::new();
    for (name, path) in candidate_paths(stem) {
        if path.exists() {
            let content = std::fs::read(&path).map_err(|source| OtError::InputOpen {
                path: path.clone(),
                source,
            })?;
            entries.push(BundleEntry { name, content });
        }
    }
    if entries.is_empty() {
        return Err(OtError::Parse(format!(
            "no bundle input found for stem '{}' — expected at least one of \
             {}.html, {}.map.json, {}.audit.json",
            stem.display(),
            stem.display(),
            stem.display(),
            stem.display(),
        )));
    }

    let summary = BundleSummary {
        files: entries.iter().map(|e| e.name.to_string()).collect(),
    };
    let plaintext = encode_container(&entries);

    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| OtError::Parse(format!("could not initialize bundle encryption: {e}")))?;
    writer
        .write_all(&plaintext)
        .map_err(|source| OtError::WriteOutput {
            path: output.to_path_buf(),
            source,
        })?;
    writer
        .finish()
        .map_err(|e| OtError::Parse(format!("could not finalize bundle encryption: {e}")))?;

    std::fs::write(output, ciphertext).map_err(|source| OtError::WriteOutput {
        path: output.to_path_buf(),
        source,
    })?;

    Ok(summary)
}

/// Decrypts `bundle_path` with `passphrase` and writes every contained file
/// into `output_dir` (created if missing), under its stored name. Rejects
/// any stored name that isn't a bare filename (no path separators, no
/// `..`) — the bundle's plaintext is attacker-controlled the moment someone
/// else can produce a file that decrypts under a guessed/shared passphrase,
/// so extraction must not be able to write outside `output_dir`.
pub fn unbundle(
    bundle_path: &Path,
    output_dir: &Path,
    passphrase: SecretString,
) -> Result<Vec<String>> {
    let ciphertext = std::fs::read(bundle_path).map_err(|source| OtError::InputOpen {
        path: bundle_path.to_path_buf(),
        source,
    })?;

    let decryptor = age::Decryptor::new(&ciphertext[..]).map_err(|e| {
        OtError::Parse(format!(
            "'{}' is not a valid otsniff bundle: {e}",
            bundle_path.display()
        ))
    })?;
    let identity = age::scrypt::Identity::new(passphrase);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| {
            OtError::Parse(format!(
                "could not decrypt '{}': {e} (wrong passphrase, or the file is corrupted)",
                bundle_path.display()
            ))
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|source| OtError::InputOpen {
            path: bundle_path.to_path_buf(),
            source,
        })?;

    let entries = decode_container(&plaintext, bundle_path)?;

    std::fs::create_dir_all(output_dir).map_err(|source| OtError::WriteOutput {
        path: output_dir.to_path_buf(),
        source,
    })?;

    let mut written = Vec::with_capacity(entries.len());
    for (name, content) in entries {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
        {
            return Err(OtError::Parse(format!(
                "bundle contains an unsafe entry name '{name}' — refusing to extract"
            )));
        }
        let out_path = output_dir.join(&name);
        std::fs::write(&out_path, &content).map_err(|source| OtError::WriteOutput {
            path: out_path.clone(),
            source,
        })?;
        written.push(name);
    }
    Ok(written)
}

/// `(stored name, expected on-disk path)` for the three sidecars a bundle
/// can contain, derived from `stem` the same way `analyze`'s audit-log path
/// derives from `-o` (ADR-0012): `set_extension` replaces the file's
/// existing extension (if any) with the given one.
fn candidate_paths(stem: &Path) -> [(&'static str, PathBuf); 3] {
    let html = {
        let mut p = stem.to_path_buf();
        p.set_extension("html");
        p
    };
    let map = {
        let mut p = stem.to_path_buf();
        p.set_extension("map.json");
        p
    };
    let audit = {
        let mut p = stem.to_path_buf();
        p.set_extension("audit.json");
        p
    };
    [
        ("report.html", html),
        ("map.json", map),
        ("audit.json", audit),
    ]
}

fn encode_container(entries: &[BundleEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let name_bytes = e.name.as_bytes();
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&(e.content.len() as u64).to_le_bytes());
        out.extend_from_slice(&e.content);
    }
    out
}

fn decode_container(data: &[u8], bundle_path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let corrupt = |reason: &str| {
        OtError::Parse(format!(
            "'{}' does not contain a valid otsniff bundle: {reason}",
            bundle_path.display()
        ))
    };

    let mut pos = 0usize;
    let take = |data: &[u8], pos: &mut usize, n: usize, what: &str| -> Result<Vec<u8>> {
        if data.len() < *pos + n {
            return Err(corrupt(&format!("truncated while reading {what}")));
        }
        let slice = data[*pos..*pos + n].to_vec();
        *pos += n;
        Ok(slice)
    };

    let magic = take(data, &mut pos, MAGIC.len(), "magic")?;
    if magic != MAGIC {
        return Err(corrupt("bad magic bytes"));
    }
    let count_bytes = take(data, &mut pos, 4, "entry count")?;
    let count = u32::from_le_bytes(count_bytes.try_into().unwrap());

    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name_len_bytes = take(data, &mut pos, 2, "name length")?;
        let name_len = u16::from_le_bytes(name_len_bytes.try_into().unwrap()) as usize;
        let name_bytes = take(data, &mut pos, name_len, "name")?;
        let name =
            String::from_utf8(name_bytes).map_err(|_| corrupt("entry name is not valid UTF-8"))?;
        let content_len_bytes = take(data, &mut pos, 8, "content length")?;
        let content_len = u64::from_le_bytes(content_len_bytes.try_into().unwrap());
        let content = take(data, &mut pos, content_len as usize, "content")?;
        entries.push((name, content));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn bundle_round_trips_all_three_sidecars() {
        let tmp = TempDir::new().unwrap();
        let stem = tmp.path().join("report");
        std::fs::write(stem.with_extension("html"), b"<html>hi</html>").unwrap();
        std::fs::write(
            {
                let mut p = stem.clone();
                p.set_extension("map.json");
                p
            },
            b"{\"ips\":{}}",
        )
        .unwrap();
        std::fs::write(
            {
                let mut p = stem.clone();
                p.set_extension("audit.json");
                p
            },
            b"{\"schema_version\":2}",
        )
        .unwrap();

        let out = tmp.path().join("bundle.age");
        let summary = bundle(&stem, &out, pass("correct horse battery staple")).unwrap();
        assert_eq!(summary.files.len(), 3);

        let extract_dir = tmp.path().join("extracted");
        let written = unbundle(&out, &extract_dir, pass("correct horse battery staple")).unwrap();
        assert_eq!(written.len(), 3);
        assert_eq!(
            std::fs::read(extract_dir.join("report.html")).unwrap(),
            b"<html>hi</html>"
        );
        assert_eq!(
            std::fs::read(extract_dir.join("map.json")).unwrap(),
            b"{\"ips\":{}}"
        );
        assert_eq!(
            std::fs::read(extract_dir.join("audit.json")).unwrap(),
            b"{\"schema_version\":2}"
        );
    }

    #[test]
    fn bundle_skips_missing_sidecars() {
        let tmp = TempDir::new().unwrap();
        let stem = tmp.path().join("report");
        std::fs::write(stem.with_extension("html"), b"<html>only</html>").unwrap();
        // No map.json / audit.json — a non-`--ai` run.

        let out = tmp.path().join("bundle.age");
        let summary = bundle(&stem, &out, pass("pw")).unwrap();
        assert_eq!(summary.files, vec!["report.html".to_string()]);
    }

    #[test]
    fn bundle_errors_when_nothing_exists_for_the_stem() {
        let tmp = TempDir::new().unwrap();
        let stem = tmp.path().join("nonexistent-report");
        let out = tmp.path().join("bundle.age");
        let err = bundle(&stem, &out, pass("pw")).unwrap_err();
        assert!(err.to_string().contains("no bundle input found"));
    }

    #[test]
    fn unbundle_with_wrong_passphrase_fails_clearly() {
        let tmp = TempDir::new().unwrap();
        let stem = tmp.path().join("report");
        std::fs::write(stem.with_extension("html"), b"secret content").unwrap();
        let out = tmp.path().join("bundle.age");
        bundle(&stem, &out, pass("right-passphrase")).unwrap();

        let extract_dir = tmp.path().join("extracted");
        let err = unbundle(&out, &extract_dir, pass("wrong-passphrase")).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"));
    }

    /// A bundle's plaintext is attacker-controlled the moment someone else
    /// can produce one that decrypts under a guessed/shared passphrase —
    /// forge a container with a path-traversal entry name directly (bundle
    /// itself never emits one) and confirm extraction refuses it rather
    /// than writing outside `output_dir`.
    #[test]
    fn unbundle_refuses_path_traversal_entry_names() {
        let tmp = TempDir::new().unwrap();
        let malicious = encode_container(&[BundleEntry {
            name: "../evil.txt",
            content: b"pwned".to_vec(),
        }]);
        let out = tmp.path().join("malicious.age");
        let encryptor = age::Encryptor::with_user_passphrase(pass("pw"));
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(&malicious).unwrap();
        writer.finish().unwrap();
        std::fs::write(&out, ciphertext).unwrap();

        let extract_dir = tmp.path().join("extracted");
        let err = unbundle(&out, &extract_dir, pass("pw")).unwrap_err();
        assert!(err.to_string().contains("unsafe entry name"));
        assert!(
            !tmp.path().join("evil.txt").exists(),
            "must not have escaped output_dir"
        );
    }

    #[test]
    fn unbundle_rejects_a_non_bundle_file() {
        let tmp = TempDir::new().unwrap();
        let not_a_bundle = tmp.path().join("plain.txt");
        std::fs::write(&not_a_bundle, b"just some text, not age-encrypted at all").unwrap();
        let extract_dir = tmp.path().join("extracted");
        let err = unbundle(&not_a_bundle, &extract_dir, pass("pw")).unwrap_err();
        assert!(err.to_string().contains("not a valid otsniff bundle"));
    }
}

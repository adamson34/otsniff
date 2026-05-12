//! Claude Code CLI provider.
//!
//! Spawns `claude -p "<system prompt>"`, pipes the scrubbed markdown to
//! stdin, captures stdout. Inherits whatever auth, billing, and model
//! access the user has configured for Claude Code — no API key in
//! otsniff's environment, no HTTP client, no SDK.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::error::{OtError, Result};

use super::AiProvider;

pub struct ClaudeCliProvider {
    /// Optional model override passed through as `--model <m>`.
    /// `None` lets Claude Code pick its default.
    pub model: Option<String>,
}

impl ClaudeCliProvider {
    pub fn new(model: Option<String>) -> Self {
        Self { model }
    }
}

impl AiProvider for ClaudeCliProvider {
    fn name(&self) -> &str {
        "claude-cli"
    }

    fn analyze(&self, system_prompt: &str, scrubbed_md: &str) -> Result<String> {
        // Verify claude is installed before doing anything else. A clear
        // error is far better than a cryptic NotFound from spawn().
        if which_claude().is_none() {
            return Err(OtError::Parse(
                "Claude Code CLI not found on PATH. Install from https://claude.com/code, \
                 then run `claude` once to authenticate."
                    .to_string(),
            ));
        }

        let mut cmd = build_command(self.model.as_deref(), system_prompt);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|source| OtError::InputOpen {
            path: "<spawn:claude>".into(),
            source,
        })?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| OtError::Parse("could not open stdin to claude".to_string()))?;
            stdin
                .write_all(scrubbed_md.as_bytes())
                .map_err(|source| OtError::WriteOutput {
                    path: "<stdin:claude>".into(),
                    source,
                })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|source| OtError::InputOpen {
                path: "<wait:claude>".into(),
                source,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OtError::Parse(format!(
                "claude exited with code {:?}: {}",
                output.status.code(),
                stderr.trim()
            )));
        }

        String::from_utf8(output.stdout)
            .map_err(|e| OtError::Parse(format!("claude stdout was not valid UTF-8: {e}")))
    }
}

fn which_claude() -> Option<std::path::PathBuf> {
    // Minimal `which`. Don't pull in a crate for this.
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("claude");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Disallowed Claude Code tools. The leak detector covers prompt bytes;
/// this flag prevents the spawned claude instance from using its own
/// tools to read the source PCAP, the scrub map file, or anything else
/// on disk / over the network. Defense-in-depth per S-5.04.
pub(crate) const DISALLOWED_TOOLS: &str =
    "Bash,Read,Write,Edit,WebFetch,WebSearch,Glob,Grep,Task,NotebookEdit";

/// Build the `claude -p` command with all required flags.
///
/// Always includes `--disallowed-tools` to prevent the spawned claude
/// instance from reading the filesystem or reaching the network at
/// runtime. Two airlocks: the leak detector enforces prompt bytes;
/// this flag enforces runtime access.
pub(crate) fn build_command(model: Option<&str>, system_prompt: &str) -> Command {
    let mut cmd = Command::new("claude");
    cmd.arg("-p").arg(system_prompt);
    cmd.args(["--disallowed-tools", DISALLOWED_TOOLS]);
    if let Some(m) = model {
        cmd.args(["--model", m]);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// BC-6.03.002: the spawned command MUST always include --disallowed-tools.
    #[test]
    fn test_bc_6_03_002_build_command_includes_disallowed_tools_flag() {
        let cmd = build_command(None, "system prompt");
        let args: Vec<&OsStr> = cmd.get_args().collect();
        let strs: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
        assert!(
            strs.contains(&"--disallowed-tools"),
            "claude command must always pass --disallowed-tools; got args: {strs:?}"
        );
    }

    /// BC-6.03.002: the --disallowed-tools value must enumerate every
    /// Claude Code tool capable of reading the filesystem or reaching
    /// the network, as defined in AC-001.
    #[test]
    fn test_bc_6_03_002_disallowed_tools_lists_all_filesystem_and_network_tools() {
        let cmd = build_command(None, "system prompt");
        let strs: Vec<String> = cmd
            .get_args()
            .filter_map(|a| a.to_str().map(String::from))
            .collect();
        let pos = strs
            .iter()
            .position(|s| s == "--disallowed-tools")
            .expect("--disallowed-tools flag must be present in command args");
        let value = strs
            .get(pos + 1)
            .expect("--disallowed-tools must be followed by a value argument");
        for tool in [
            "Bash",
            "Read",
            "Write",
            "Edit",
            "WebFetch",
            "WebSearch",
            "Glob",
            "Grep",
            "Task",
            "NotebookEdit",
        ] {
            assert!(
                value.contains(tool),
                "--disallowed-tools value is missing '{tool}'; full value: {value:?}",
            );
        }
    }

    /// BC-6.03.002: model flag is threaded through correctly.
    /// (Secondary concern — the real Red Gate is the --disallowed-tools tests above.)
    #[test]
    fn test_bc_6_03_002_build_command_passes_model_when_provided() {
        let cmd = build_command(Some("claude-opus-4-5"), "system prompt");
        let strs: Vec<String> = cmd
            .get_args()
            .filter_map(|a| a.to_str().map(String::from))
            .collect();
        // --disallowed-tools must still be present even with a model override
        assert!(
            strs.contains(&"--disallowed-tools".to_string()),
            "--disallowed-tools must be present even when --model is supplied; args: {strs:?}"
        );
        // --model must be present
        assert!(
            strs.windows(2)
                .any(|w| w[0] == "--model" && w[1] == "claude-opus-4-5"),
            "--model claude-opus-4-5 must appear in command args; got: {strs:?}"
        );
    }
}

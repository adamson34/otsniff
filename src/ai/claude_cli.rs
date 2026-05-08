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

        let mut cmd = Command::new("claude");
        cmd.arg("-p").arg(system_prompt);
        if let Some(model) = &self.model {
            cmd.args(["--model", model]);
        }
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

//! Ollama local-model provider (P2-6).
//!
//! Shells out to `ollama run <model>`, piping the combined system prompt +
//! scrubbed markdown to stdin and capturing stdout. Fulfills the air-gap
//! promise from ADR-0007: an `analyze --ai` pipeline that never leaves the
//! host, for an operator who cannot use any external AI service at all.
//!
//! Unlike the Claude Code CLI, plain `ollama run` has no separate
//! system-prompt channel (that's a Modelfile concept) and no built-in
//! filesystem/network tool surface to sandbox — it's a bare model REPL, not
//! an agent — so there's no `--disallowed-tools` equivalent here. The
//! system prompt and scrubbed report are simply concatenated into one
//! prompt sent over stdin.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::ai::claude_cli::run_with_heartbeat;
use crate::error::{OtError, Result};

use super::AiProvider;

pub struct OllamaProvider {
    /// Model name passed to `ollama run <model>` (e.g. `"llama3.1"`,
    /// `"qwen2.5:7b"`). Required — unlike Claude Code, there's no
    /// meaningful default across installs.
    pub model: String,
    /// See [`crate::ai::claude_cli::ClaudeCliProvider::verbose`] — same
    /// heartbeat-visibility semantics.
    pub(crate) verbose: bool,
}

impl OllamaProvider {
    pub fn new(model: String) -> Self {
        Self {
            model,
            verbose: false,
        }
    }

    pub fn new_verbose(model: String, verbose: bool) -> Self {
        Self { model, verbose }
    }
}

impl AiProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn analyze(&self, system_prompt: &str, scrubbed_md: &str) -> Result<String> {
        run(
            &self.model,
            self.verbose,
            "ollama",
            system_prompt,
            scrubbed_md,
        )
    }

    fn augment(&self, system_prompt: &str, scrubbed_md: &str) -> Result<String> {
        run(
            &self.model,
            self.verbose,
            "ollama (augment)",
            system_prompt,
            scrubbed_md,
        )
    }
}

fn run(
    model: &str,
    verbose_flag: bool,
    heartbeat_label: &'static str,
    system_prompt: &str,
    scrubbed_md: &str,
) -> Result<String> {
    use std::io::IsTerminal as _;

    let ollama = which_ollama().ok_or_else(|| {
        OtError::Parse(
            "Ollama not found on PATH. Install from https://ollama.com, pull a model \
             (e.g. `ollama pull llama3.1`), then pass --provider ollama --model llama3.1."
                .to_string(),
        )
    })?;

    let verbose = verbose_flag || std::io::stderr().is_terminal();
    // No separate system-prompt channel on the plain CLI — concatenate.
    let combined = format!("{system_prompt}\n\n{scrubbed_md}");
    let prompt_bytes = combined.into_bytes();
    let model = model.to_string();

    let task = move || -> crate::error::Result<Vec<u8>> {
        let mut cmd = build_command(&ollama, &model);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|source| OtError::InputOpen {
            path: "<spawn:ollama>".into(),
            source,
        })?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| OtError::Parse("could not open stdin to ollama".to_string()))?;
            stdin
                .write_all(&prompt_bytes)
                .map_err(|source| OtError::WriteOutput {
                    path: "<stdin:ollama>".into(),
                    source,
                })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|source| OtError::InputOpen {
                path: "<wait:ollama>".into(),
                source,
            })?;

        if !output.status.success() {
            let stderr_text = String::from_utf8_lossy(&output.stderr);
            return Err(OtError::Parse(format!(
                "ollama exited with code {:?}: {}",
                output.status.code(),
                stderr_text.trim()
            )));
        }

        Ok(output.stdout)
    };

    let clock = crate::progress::SystemClock;
    let mut stderr = std::io::stderr();
    let response_bytes = run_with_heartbeat(heartbeat_label, task, &mut stderr, &clock, verbose)?;

    String::from_utf8(response_bytes)
        .map_err(|e| OtError::Parse(format!("ollama stdout was not valid UTF-8: {e}")))
}

/// Resolves the `ollama` binary to an absolute path. Same CRITICAL as
/// `claude_cli::which_claude` — see [`crate::which`] (ADV-P2 F-P2-001).
fn which_ollama() -> Option<std::path::PathBuf> {
    crate::which::find_executable("ollama")
}

/// Build the `ollama run <model>` command.
pub(crate) fn build_command(program: &std::path::Path, model: &str) -> Command {
    // Spawn the resolved absolute path, not the bare name (ADV-P2 F-P2-001).
    let mut cmd = Command::new(program);
    cmd.arg("run").arg(model);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_runs_the_given_model() {
        let cmd = build_command(std::path::Path::new("/usr/local/bin/ollama"), "llama3.1");
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        let strs: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
        assert_eq!(strs, vec!["run", "llama3.1"]);
    }

    /// CI never has `ollama` on PATH, so this exercises the real, deterministic
    /// not-found path without a live model invocation — same pattern as
    /// `claude_cli`'s equivalent guard.
    #[test]
    fn analyze_without_ollama_on_path_gives_a_clear_actionable_error() {
        let provider = OllamaProvider::new("llama3.1".to_string());
        let err = provider.analyze("system", "scrubbed body").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Ollama not found on PATH"), "got: {msg}");
        assert!(msg.contains("ollama.com"), "got: {msg}");
    }

    #[test]
    fn name_is_ollama() {
        let provider = OllamaProvider::new("llama3.1".to_string());
        assert_eq!(provider.name(), "ollama");
    }
}

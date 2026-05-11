//! AI provider abstraction.
//!
//! v0.3 ships one provider: the Claude Code CLI. v0.4 adds Ollama via the
//! same trait. We deliberately do *not* embed an HTTP client or vendor SDK —
//! shelling out to whatever CLI the user already has installed is the
//! cleanest supply-chain story we can offer.
//!
//! Every call into a provider runs a fail-closed leak check first. The
//! provider implementations themselves can assume their input is already
//! scrubbed.

pub mod claude_cli;
pub mod html_render;
pub mod leak_detector;
pub mod prompts;

use crate::error::Result;

/// An AI backend that takes scrubbed markdown and returns a (still-scrubbed)
/// analysis. Implementations must not modify the pseudonym vocabulary the
/// caller depends on for unscrub.
pub trait AiProvider {
    /// Short, stable name used in logs and CLI flags (e.g., "claude-cli").
    fn name(&self) -> &str;

    /// Run the analysis. `scrubbed_md` is the report body; `system_prompt`
    /// is the analyst persona / instructions. Returns the raw response
    /// text (unmodified, still in pseudonym terms).
    fn analyze(&self, system_prompt: &str, scrubbed_md: &str) -> Result<String>;
}

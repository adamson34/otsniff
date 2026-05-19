//! Claude Code CLI provider.
//!
//! Spawns `claude -p "<system prompt>"`, pipes the scrubbed markdown to
//! stdin, captures stdout. Inherits whatever auth, billing, and model
//! access the user has configured for Claude Code — no API key in
//! otsniff's environment, no HTTP client, no SDK.
//!
//! ## S-5.02 heartbeat surface
//!
//! [`run_with_heartbeat`] drives the background-thread heartbeat introduced
//! in S-5.02. It is `pub(crate)` so unit tests in this module (and integration
//! tests under `tests/`) can construct test doubles and assert on the heartbeat
//! protocol without going through `analyze`.
//!
//! Visibility choice: `pub(crate)` (not `pub`) because the heartbeat
//! mechanism is an implementation detail of the AI subsystem and no
//! external crate consumer should call it directly.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::progress::Clock;

use crate::error::{OtError, Result};

use super::AiProvider;

/// Heartbeat fires every 3 seconds of simulated (clock-based) time.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

pub struct ClaudeCliProvider {
    /// Optional model override passed through as `--model <m>`.
    /// `None` lets Claude Code pick its default.
    pub model: Option<String>,
    /// When `true`, emit heartbeat lines and the final "done in" summary to
    /// stderr while the claude subprocess runs.
    ///
    /// AC-004: heartbeats fire when `verbose` is `true` OR when stderr is a
    /// TTY (`std::io::IsTerminal`). Production callers should set this to
    /// `args.verbose || std::io::stderr().is_terminal()` so that the TTY path
    /// is also covered. The field is kept separate from the TTY check so that
    /// unit tests can assert on verbose=true/false behaviour without needing a
    /// real terminal attached.
    pub(crate) verbose: bool,
}

impl ClaudeCliProvider {
    /// Construct with verbose mode off. Heartbeats are still emitted when
    /// stderr is a TTY at invocation time (see [`analyze`]).
    pub fn new(model: Option<String>) -> Self {
        Self {
            model,
            verbose: false,
        }
    }

    /// Construct with an explicit verbose flag.
    pub fn new_verbose(model: Option<String>, verbose: bool) -> Self {
        Self { model, verbose }
    }
}

impl AiProvider for ClaudeCliProvider {
    fn name(&self) -> &str {
        "claude-cli"
    }

    fn analyze(&self, system_prompt: &str, scrubbed_md: &str) -> Result<String> {
        use std::io::IsTerminal as _;

        // Verify claude is installed before doing anything else. A clear
        // error is far better than a cryptic NotFound from spawn().
        if which_claude().is_none() {
            return Err(OtError::Parse(
                "Claude Code CLI not found on PATH. Install from https://claude.com/code, \
                 then run `claude` once to authenticate."
                    .to_string(),
            ));
        }

        // AC-004: emit heartbeats when the caller set verbose=true OR when
        // stderr is a TTY. Combining both lets `-v` work in piped shells while
        // also giving interactive users feedback without needing to pass `-v`.
        let verbose = self.verbose || std::io::stderr().is_terminal();

        // Clone the values the task closure needs to own.
        let prompt_bytes = scrubbed_md.as_bytes().to_vec();
        let model = self.model.clone();
        let system = system_prompt.to_string();

        // Task closure: runs on a background thread inside run_with_heartbeat.
        // Spawns the claude subprocess, feeds stdin, waits for output, and
        // returns stdout bytes (or an error). Returning Vec<u8> satisfies the
        // R: AsRef<[u8]> bound required for byte-count reporting.
        let task = move || -> crate::error::Result<Vec<u8>> {
            let mut cmd = build_command(model.as_deref(), &system);
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
                    .write_all(&prompt_bytes)
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
                let stderr_text = String::from_utf8_lossy(&output.stderr);
                return Err(OtError::Parse(format!(
                    "claude exited with code {:?}: {}",
                    output.status.code(),
                    stderr_text.trim()
                )));
            }

            Ok(output.stdout)
        };

        // SystemClock is constructed here so the heartbeat loop measures
        // actual wall-clock time for the subprocess invocation.
        let clock = crate::progress::SystemClock;
        let mut stderr = std::io::stderr();
        let response_bytes = run_with_heartbeat("claude", task, &mut stderr, &clock, verbose)?;

        String::from_utf8(response_bytes)
            .map_err(|e| OtError::Parse(format!("claude stdout was not valid UTF-8: {e}")))
    }
}

/// Drive a task on a background thread while emitting `[Ns] <label> still working...`
/// heartbeats to `writer` every 3 seconds of clock time.
///
/// The `task` closure runs on a background thread; the calling thread polls
/// `clock.now()` in a tight loop and emits heartbeat lines on each 3-second
/// boundary. On task completion a final summary line is emitted:
///   `done in N.Ns, B bytes response`
///
/// AC-004: when `verbose` is `false`, no output is written at all (neither
/// heartbeats nor the summary). The `verbose` flag also lets tests exercise
/// the verbose path without touching the real TTY. In production callers,
/// combine: `verbose = explicit_verbose_flag || stderr.is_terminal()`.
///
/// The bound `R: AsRef<[u8]>` lets us measure the response byte count for
/// the summary line without an extra size-hint parameter. For S-5.02 the
/// production return type is `Vec<u8>` which satisfies this trivially.
pub(crate) fn run_with_heartbeat<W, C, T, R>(
    label: &str,
    task: T,
    writer: &mut W,
    clock: &C,
    verbose: bool,
) -> crate::error::Result<R>
where
    W: Write + Send,
    C: Clock + Send,
    T: FnOnce() -> crate::error::Result<R> + Send + 'static,
    R: AsRef<[u8]> + Send + 'static,
{
    let start = clock.now();

    // Spawn the task on a background thread. We use a channel to signal
    // completion; the result is retrieved via the JoinHandle after the
    // loop exits.
    let (tx, rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let result = task();
        // Signal completion. Ignore send errors — the receiver may have
        // gone away on panic, but we retrieve the real result from join().
        let _ = tx.send(());
        result
    });

    // Heartbeat loop: poll the channel with a short real-time timeout so we
    // don't spin at 100 % CPU. On each 3-second clock boundary, emit a line.
    let mut next_beat_at = start + HEARTBEAT_INTERVAL;
    loop {
        // 50 ms real-time poll keeps latency low without wasting cycles.
        match rx.recv_timeout(Duration::from_millis(50)) {
            // Task finished (or sender dropped).
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if verbose {
                    let now = clock.now();
                    // Use `while` rather than `if` so that if the clock
                    // skips multiple 3-second boundaries in one poll
                    // (e.g., a mock clock advancing in large steps) every
                    // missed interval still fires a heartbeat line.
                    while now >= next_beat_at {
                        let elapsed_secs = next_beat_at.duration_since(start).as_secs();
                        let _ = writeln!(writer, "[{elapsed_secs}s] {label} still working...");
                        next_beat_at += HEARTBEAT_INTERVAL;
                    }
                }
            }
        }
    }

    let result = handle
        .join()
        .map_err(|_| OtError::Parse("ai task thread panicked".to_string()))??;

    if verbose {
        // After the task completes, drain any heartbeat intervals that
        // elapsed while the loop was blocked waiting on the channel.
        // This handles the case where the clock advanced past one or more
        // 3-second boundaries inside the final recv_timeout window.
        let now = clock.now();
        while now >= next_beat_at {
            let elapsed_secs = next_beat_at.duration_since(start).as_secs();
            let _ = writeln!(writer, "[{elapsed_secs}s] {label} still working...");
            next_beat_at += HEARTBEAT_INTERVAL;
        }

        let elapsed = now.duration_since(start);
        let bytes = result.as_ref().len();
        let _ = writeln!(
            writer,
            "done in {:.1}s, {bytes} bytes response",
            elapsed.as_secs_f64()
        );
    }

    Ok(result)
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
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    // ── MockClock ────────────────────────────────────────────────────────────
    //
    // Inline re-implementation: stores a base Instant captured at construction
    // time plus a synthetic offset advanced via `advance()`.  Cloneable so the
    // same clock can be shared between the test thread and the task closure.

    #[derive(Clone)]
    struct MockClock {
        base: Instant,
        offset: Arc<Mutex<Duration>>,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset: Arc::new(Mutex::new(Duration::ZERO)),
            }
        }

        fn advance(&self, d: Duration) {
            *self.offset.lock().unwrap() += d;
        }
    }

    impl crate::progress::Clock for MockClock {
        fn now(&self) -> Instant {
            self.base + *self.offset.lock().unwrap()
        }
    }

    // ── BC-6.04.001 heartbeat tests ──────────────────────────────────────────

    /// AC-001: over a simulated 10-second task the heartbeat loop must emit at
    /// least 3 "still working" lines (at ~3, ~6, ~9 s) plus a final summary
    /// line containing "done in" and the byte count.
    ///
    /// Cross-thread synchronisation: the task closure holds a clone of the
    /// MockClock and busy-waits (yielding every 10 ms) until the shared offset
    /// reaches 10 s.  A separate thread advances the clock in 1-second steps
    /// while the heartbeat loop runs on the calling thread.
    #[test]
    fn test_bc_6_04_001_emits_heartbeat_every_3s() {
        let clock = MockClock::new();
        let mut writer = Vec::<u8>::new();

        let clock_for_task = clock.clone();
        let task = move || -> crate::error::Result<Vec<u8>> {
            let start = clock_for_task.now();
            loop {
                if clock_for_task.now().duration_since(start) >= Duration::from_secs(10) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(b"response-body".to_vec())
        };

        let clock_for_advancer = clock.clone();
        let advance_thread = std::thread::spawn(move || {
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(20));
                clock_for_advancer.advance(Duration::from_secs(1));
            }
        });

        let result = run_with_heartbeat("claude", task, &mut writer, &clock, true).unwrap();
        advance_thread.join().unwrap();

        let output = String::from_utf8(writer).unwrap();
        assert!(
            output.matches("still working").count() >= 3,
            "expected >= 3 'still working' lines; got:\n{output}"
        );
        assert!(
            output.contains("done in"),
            "expected final 'done in' summary; got:\n{output}"
        );
        assert!(
            output.contains("13 bytes"),
            "summary must mention response byte count (13); got:\n{output}"
        );
        assert_eq!(result, b"response-body");
    }

    /// AC-002: when the task completes in less than 3 simulated seconds the
    /// writer must contain ONLY the summary line — no "still working" lines.
    #[test]
    fn test_bc_6_04_001_no_heartbeat_for_fast_task() {
        let clock = MockClock::new();
        let mut writer = Vec::<u8>::new();

        // Task completes immediately; clock barely advances (well under 3 s).
        let clock_for_task = clock.clone();
        let task = move || -> crate::error::Result<Vec<u8>> {
            clock_for_task.advance(Duration::from_millis(500));
            Ok(b"fast".to_vec())
        };

        let _ = run_with_heartbeat("claude", task, &mut writer, &clock, true).unwrap();

        let output = String::from_utf8(writer).unwrap();
        assert!(
            !output.contains("still working"),
            "no 'still working' line expected for a fast task; got:\n{output}"
        );
        assert!(
            output.contains("done in"),
            "summary line must still be emitted; got:\n{output}"
        );
    }

    /// AC-001 (format): the summary line must include both the elapsed seconds
    /// and the exact byte count of the response.
    #[test]
    fn test_bc_6_04_001_summary_includes_duration_and_byte_count() {
        let clock = MockClock::new();
        let mut writer = Vec::<u8>::new();

        let response_bytes: Vec<u8> = vec![0u8; 4127];
        let clock_for_task = clock.clone();
        let task = move || -> crate::error::Result<Vec<u8>> {
            clock_for_task.advance(Duration::from_millis(1500));
            Ok(response_bytes)
        };

        let _ = run_with_heartbeat("claude", task, &mut writer, &clock, true).unwrap();

        let output = String::from_utf8(writer).unwrap();
        assert!(
            output.contains("4127 bytes"),
            "summary must include '4127 bytes'; got:\n{output}"
        );
        // Elapsed should be > 0 s (1.5 s in this case).
        assert!(
            output.contains("done in"),
            "summary must contain 'done in'; got:\n{output}"
        );
        // The summary must not show 0.0 s because time advanced by 1.5 s.
        assert!(
            !output.contains("done in 0.0s") && !output.contains("done in 0s"),
            "summary must show non-zero elapsed time; got:\n{output}"
        );
    }

    /// AC-004: when `verbose` is `false` the writer must remain completely
    /// empty — no heartbeats and no summary line.
    #[test]
    fn test_bc_6_04_001_silent_when_not_verbose() {
        let clock = MockClock::new();
        let mut writer = Vec::<u8>::new();

        let clock_for_task = clock.clone();
        let task = move || -> crate::error::Result<Vec<u8>> {
            // Simulate a 10-second task so heartbeats would fire if verbose.
            clock_for_task.advance(Duration::from_secs(10));
            Ok(b"response".to_vec())
        };

        let _ = run_with_heartbeat("claude", task, &mut writer, &clock, false).unwrap();

        assert!(
            writer.is_empty(),
            "verbose=false must produce no output at all; got:\n{}",
            String::from_utf8_lossy(&writer)
        );
    }

    /// EC-002: when the task returns an `Err`, `run_with_heartbeat` must
    /// propagate the error unchanged and not panic.
    #[test]
    fn test_bc_6_04_001_propagates_task_error() {
        let clock = MockClock::new();
        let mut writer = Vec::<u8>::new();

        let task = move || -> crate::error::Result<Vec<u8>> {
            Err(crate::error::OtError::Parse(
                "simulated claude failure".to_string(),
            ))
        };

        let result = run_with_heartbeat("claude", task, &mut writer, &clock, true);

        assert!(result.is_err(), "expected Err from failing task; got Ok");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("simulated claude failure"),
            "error message must pass through unchanged; got: {msg}"
        );
    }

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

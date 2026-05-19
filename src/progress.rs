//! Periodic parse-loop progress reporter.
//!
//! Emits lines of the form:
//!   `[parse] processed 2,500,000 packets / 1.2 GB ...`
//! to a caller-supplied writer (typically `stderr`) when `-v` is set.
//!
//! Accepts any `io::Write` so tests can inject a `Vec<u8>` and assert
//! on the captured bytes without touching real stderr.

use std::io;
use std::time::Instant;

/// Emit a progress line every N packets.
pub const PROGRESS_PACKET_INTERVAL: u64 = 100_000;

/// Emit a progress line every N bytes read.
pub const PROGRESS_BYTE_INTERVAL: u64 = 10 * 1024 * 1024; // 10 MB

/// Minimum wall-clock gap between successive emissions (rate-limit).
pub const PROGRESS_MIN_INTERVAL_SECS: u64 = 2;

/// Tracks packet / byte counts and emits periodic progress lines.
///
/// Construct with [`ProgressReporter::new`], call [`record_packet`] once
/// per decoded packet, and call [`finish`] when the parse loop exits.
///
/// [`record_packet`]: ProgressReporter::record_packet
/// [`finish`]: ProgressReporter::finish
// Fields are populated by `new` and read by `record_packet` / `finish`.
// Until those bodies are implemented the compiler warns about reads; suppress
// at struct level rather than per-field so clippy stays clean once real logic
// is present and the allow can be dropped.
#[allow(dead_code)]
pub struct ProgressReporter<W: io::Write> {
    writer: W,
    verbose: bool,
    packets: u64,
    bytes: u64,
    last_emit_packets: u64,
    last_emit_bytes: u64,
    last_emit_time: Instant,
}

impl<W: io::Write> ProgressReporter<W> {
    /// Create a new reporter.
    ///
    /// When `verbose` is `false` every call to [`record_packet`] and
    /// [`finish`] is a no-op; nothing is written to `writer`.
    ///
    /// [`record_packet`]: ProgressReporter::record_packet
    pub fn new(writer: W, verbose: bool) -> Self {
        Self {
            writer,
            verbose,
            packets: 0,
            bytes: 0,
            last_emit_packets: 0,
            last_emit_bytes: 0,
            last_emit_time: Instant::now(),
        }
    }

    /// Record one decoded packet of `packet_size` bytes and emit a
    /// progress line if either the packet-count or byte-count threshold
    /// has been crossed since the last emission, subject to the
    /// wall-clock rate-limit.
    pub fn record_packet(&mut self, _packet_size: usize) {
        todo!()
    }

    /// Emit the final summary line (always emitted when `verbose` is
    /// `true`, regardless of thresholds).
    pub fn finish(&mut self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}

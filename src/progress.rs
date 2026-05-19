//! Periodic parse-loop progress reporter.
//!
//! Emits lines of the form:
//!   `[parse] processed 2,500,000 packets / 1.2 GB ...`
//! to a caller-supplied writer (typically `stderr`) when `-v` is set.
//!
//! Accepts any `io::Write` so tests can inject a `Vec<u8>` and assert
//! on the captured bytes without touching real stderr.

use std::io;
use std::time::{Duration, Instant};

/// Emit a progress line every N packets.
pub const PROGRESS_PACKET_INTERVAL: u64 = 100_000;

/// Emit a progress line every N bytes read.
pub const PROGRESS_BYTE_INTERVAL: u64 = 10 * 1024 * 1024; // 10 MB

/// Minimum wall-clock gap between successive emissions (rate-limit).
pub const PROGRESS_MIN_INTERVAL_SECS: u64 = 2;

const PACKET_THRESHOLD: u64 = PROGRESS_PACKET_INTERVAL;
const BYTE_THRESHOLD: u64 = PROGRESS_BYTE_INTERVAL;
const RATE_LIMIT: Duration = Duration::from_secs(PROGRESS_MIN_INTERVAL_SECS);

/// Format `n` with comma thousands separators.
fn format_count(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + (len - 1) / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

/// Format `n` bytes as a human-readable string (KB / MB / GB, 1 decimal).
fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{} B", n)
    }
}

/// Abstraction over a time source so tests can control the clock without
/// sleeping.  The production path uses [`SystemClock`]; tests use a
/// [`MockClock`] defined in the test module.
pub trait Clock: Send {
    fn now(&self) -> Instant;
}

/// Production clock — delegates to [`Instant::now`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Tracks packet / byte counts and emits periodic progress lines.
///
/// Construct with [`ProgressReporter::new`], call [`record_packet`] once
/// per decoded packet, and call [`finish`] when the parse loop exits.
///
/// For test code that needs a controllable clock, use
/// [`ProgressReporter::new_with_clock`] and supply a [`MockClock`].
///
/// [`record_packet`]: ProgressReporter::record_packet
/// [`finish`]: ProgressReporter::finish
pub struct ProgressReporter<W: io::Write> {
    writer: W,
    verbose: bool,
    packets: u64,
    bytes: u64,
    last_emit_packets: u64,
    last_emit_bytes: u64,
    last_emit_time: Instant,
    clock: Box<dyn Clock>,
}

impl<W: io::Write> ProgressReporter<W> {
    /// Create a new reporter backed by the real wall clock.
    ///
    /// When `verbose` is `false` every call to [`record_packet`] and
    /// [`finish`] is a no-op; nothing is written to `writer`.
    ///
    /// [`record_packet`]: ProgressReporter::record_packet
    pub fn new(writer: W, verbose: bool) -> Self {
        Self::new_with_clock(writer, verbose, Box::new(SystemClock))
    }

    /// Create a new reporter with an injected clock.
    ///
    /// Intended for tests that need to advance time without sleeping.
    /// Pass a [`Box<dyn Clock>`] — typically a `MockClock` defined in
    /// the test module.
    pub fn new_with_clock(writer: W, verbose: bool, clock: Box<dyn Clock>) -> Self {
        // Subtract RATE_LIMIT from the initial time so that the very first
        // threshold crossing is not suppressed by the rate-limit gate.
        let now = clock.now();
        // Instant::checked_sub returns None on underflow (near epoch); fall
        // back to `now` in that case (suppresses only the very first emission
        // which is acceptable during startup on constrained platforms).
        let last_emit_time = now.checked_sub(RATE_LIMIT).unwrap_or(now);
        Self {
            writer,
            verbose,
            packets: 0,
            bytes: 0,
            last_emit_packets: 0,
            last_emit_bytes: 0,
            last_emit_time,
            clock,
        }
    }

    /// Record one decoded packet of `packet_size` bytes and emit a
    /// progress line if either the packet-count or byte-count threshold
    /// has been crossed since the last emission, subject to the
    /// wall-clock rate-limit.
    pub fn record_packet(&mut self, packet_size: usize) {
        self.packets += 1;
        self.bytes += packet_size as u64;

        if !self.verbose {
            return;
        }

        let packet_threshold_crossed = self.packets - self.last_emit_packets >= PACKET_THRESHOLD;
        let byte_threshold_crossed = self.bytes - self.last_emit_bytes >= BYTE_THRESHOLD;

        if !(packet_threshold_crossed || byte_threshold_crossed) {
            return;
        }

        let now = self.clock.now();
        if now.duration_since(self.last_emit_time) < RATE_LIMIT {
            return;
        }

        let _ = writeln!(
            self.writer,
            "[parse] processed {} packets / {}",
            format_count(self.packets),
            format_bytes(self.bytes),
        );

        self.last_emit_packets = self.packets;
        self.last_emit_bytes = self.bytes;
        self.last_emit_time = now;
    }

    /// Emit the final summary line (always emitted when `verbose` is
    /// `true`, regardless of thresholds).
    pub fn finish(&mut self) {
        if !self.verbose {
            return;
        }
        let _ = writeln!(
            self.writer,
            "[parse] processed {} packets / {}",
            format_count(self.packets),
            format_bytes(self.bytes),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Controllable clock for tests: stores a base `Instant` plus a
    /// `Duration` offset that the test can advance via [`advance`].
    ///
    /// `Instant` arithmetic (subtraction) is defined for instants drawn
    /// from the same clock but `Instant::now()` is the only stable
    /// constructor on stable Rust.  We work around this by capturing one
    /// real `Instant` at construction time and adding a synthetic offset.
    struct MockClock {
        base: Instant,
        offset: Arc<Mutex<Duration>>,
    }

    impl MockClock {
        fn new() -> (Self, Arc<Mutex<Duration>>) {
            let offset = Arc::new(Mutex::new(Duration::ZERO));
            let clock = MockClock {
                base: Instant::now(),
                offset: Arc::clone(&offset),
            };
            (clock, offset)
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            self.base + *self.offset.lock().unwrap()
        }
    }

    /// Advance the shared offset handle by `d`.
    fn advance(offset: &Arc<Mutex<Duration>>, d: Duration) {
        *offset.lock().unwrap() += d;
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    fn captured_output(reporter: &ProgressReporter<Vec<u8>>) -> String {
        String::from_utf8(reporter.writer.clone()).expect("reporter wrote non-UTF-8")
    }

    fn count_progress_lines(output: &str) -> usize {
        output.lines().filter(|l| l.contains("[parse]")).count()
    }

    // ── BC-9.04.001 tests ────────────────────────────────────────────────────

    /// AC-001: after 100,000 packets the reporter must emit at least one
    /// `[parse]` progress line.
    ///
    /// Clock is advanced past the 2-second rate-limit gate before the
    /// threshold is crossed so that the rate-limiter does not suppress the
    /// emission.
    #[test]
    fn test_bc_9_04_001_emits_after_100k_packets() {
        let (mock, offset) = MockClock::new();
        // Advance past the rate-limit gate so the first emission is not
        // suppressed.
        advance(&offset, Duration::from_secs(3));
        let mut reporter = ProgressReporter::new_with_clock(Vec::<u8>::new(), true, Box::new(mock));

        for _ in 0..100_000 {
            reporter.record_packet(64);
        }

        let output = captured_output(&reporter);
        assert!(
            count_progress_lines(&output) >= 1,
            "expected at least 1 [parse] line after 100,000 packets; got:\n{output}"
        );
        // The line must mention the packet count in some form.
        assert!(
            output.contains("100,000") || output.contains("100000"),
            "progress line must include the packet count; got:\n{output}"
        );
    }

    /// AC-001: after enough large packets to cross 10 MB (100 × 105,000 B =
    /// ~10 MB) the reporter must emit at least one `[parse]` line — even
    /// though the 100k-packet threshold has not been reached.
    #[test]
    fn test_bc_9_04_001_emits_after_10mb_bytes() {
        let (mock, offset) = MockClock::new();
        advance(&offset, Duration::from_secs(3));
        let mut reporter = ProgressReporter::new_with_clock(Vec::<u8>::new(), true, Box::new(mock));

        // 100 packets × 105,000 bytes = 10,500,000 bytes (>10 MB), well
        // below the 100k-packet threshold.
        for _ in 0..100 {
            reporter.record_packet(105_000);
        }

        let output = captured_output(&reporter);
        assert!(
            count_progress_lines(&output) >= 1,
            "expected at least 1 [parse] line after >10 MB; got:\n{output}"
        );
        // The line should reference the byte volume in some human-readable
        // unit.  Accept "10 MB", "10.0 MB", "10.5 MB", "10,500,000 bytes" etc.
        let has_byte_info = output.contains("MB")
            || output.contains("GB")
            || output.contains("bytes")
            || output.contains("10,5")  // 10,500,000
            || output.contains("10.5");
        assert!(
            has_byte_info,
            "progress line must include the byte volume; got:\n{output}"
        );
    }

    /// AC-002: when verbose=false no output must be produced, even with
    /// many packets and time advances.
    #[test]
    fn test_bc_9_04_001_no_emission_when_verbose_false() {
        let (mock, offset) = MockClock::new();
        // Advance clock way past any threshold.
        advance(&offset, Duration::from_secs(100));
        let mut reporter =
            ProgressReporter::new_with_clock(Vec::<u8>::new(), false, Box::new(mock));

        for i in 0..1_000_000 {
            // Also advance the clock periodically so we don't rely on wall-clock
            // rate-limit to suppress output.
            if i % 100_000 == 0 {
                advance(&offset, Duration::from_secs(3));
            }
            reporter.record_packet(64);
        }
        reporter.finish();

        let output = captured_output(&reporter);
        assert!(
            output.is_empty(),
            "verbose=false must produce no output; got:\n{output}"
        );
    }

    /// AC-003: the rate-limit must suppress a second emission when fewer
    /// than 2 seconds have elapsed since the first.
    ///
    /// Feed 200,000 packets (two threshold crossings) without advancing
    /// the clock.  Only the first crossing should emit; the second is
    /// suppressed by the 2-second gate.  Then advance by 2.1 s and feed
    /// 100,000 more; the third crossing should now emit.
    #[test]
    fn test_bc_9_04_001_rate_limited_to_2s() {
        let (mock, offset) = MockClock::new();
        // Start past the gate so the very first threshold crossing fires.
        advance(&offset, Duration::from_secs(3));
        let mut reporter = ProgressReporter::new_with_clock(Vec::<u8>::new(), true, Box::new(mock));

        // First 100k — should produce exactly 1 emission.
        for _ in 0..100_000 {
            reporter.record_packet(64);
        }
        let after_first = count_progress_lines(&captured_output(&reporter));
        assert_eq!(
            after_first, 1,
            "expected exactly 1 emission after first 100k packets; got {after_first}"
        );

        // Second 100k — clock has NOT advanced past the 2-second gate.
        // Emission should be suppressed.
        for _ in 0..100_000 {
            reporter.record_packet(64);
        }
        let after_second = count_progress_lines(&captured_output(&reporter));
        assert_eq!(
            after_second, 1,
            "rate-limit must suppress the second emission; got {after_second}"
        );

        // Advance clock past the gate and feed another 100k.
        advance(&offset, Duration::from_millis(2100));
        for _ in 0..100_000 {
            reporter.record_packet(64);
        }
        let after_third = count_progress_lines(&captured_output(&reporter));
        assert_eq!(
            after_third, 2,
            "expected 2 total emissions after clock advance; got {after_third}"
        );
    }

    /// EC-002: a single packet (well below all thresholds) must produce no
    /// progress lines from `record_packet`, and `finish()` must produce
    /// exactly one final summary line.
    #[test]
    fn test_bc_9_04_001_finish_emits_summary_even_if_no_progress() {
        let (mock, _offset) = MockClock::new();
        let mut reporter = ProgressReporter::new_with_clock(Vec::<u8>::new(), true, Box::new(mock));

        for _ in 0..50 {
            reporter.record_packet(64);
        }
        let before_finish = captured_output(&reporter);
        assert_eq!(
            count_progress_lines(&before_finish),
            0,
            "50 packets must not trigger any progress lines; got:\n{before_finish}"
        );

        reporter.finish();

        let after_finish = captured_output(&reporter);
        // finish() must have written exactly one additional line.
        assert_eq!(
            count_progress_lines(&after_finish),
            1,
            "finish() must emit exactly 1 summary line; got:\n{after_finish}"
        );
    }

    /// AC-001: the progress line must contain a human-readable packet count
    /// and a human-readable byte volume.  We use a known-size batch so both
    /// values are predictable.
    ///
    /// 100,000 packets × 64 bytes = 6,400,000 bytes (~6.4 MB).
    /// The line must match the pattern:
    ///   `[parse] processed <count> packet(s) / <size> <unit>`
    #[test]
    fn test_bc_9_04_001_format_includes_count_and_bytes() {
        let (mock, offset) = MockClock::new();
        advance(&offset, Duration::from_secs(3));
        let mut reporter = ProgressReporter::new_with_clock(Vec::<u8>::new(), true, Box::new(mock));

        for _ in 0..100_000 {
            reporter.record_packet(64);
        }

        let output = captured_output(&reporter);
        let progress_lines: Vec<&str> = output.lines().filter(|l| l.contains("[parse]")).collect();

        assert!(
            !progress_lines.is_empty(),
            "expected at least one [parse] line; got:\n{output}"
        );

        let line = progress_lines[0];
        // Must contain a packet count — either with commas ("100,000") or
        // without ("100000").
        assert!(
            line.contains("100,000") || line.contains("100000"),
            "progress line must include packet count 100,000; got: {line:?}"
        );
        // Must include some byte / size information.
        let has_size = line.contains("MB")
            || line.contains("KB")
            || line.contains("GB")
            || line.contains("bytes")
            || line.contains("6,400") // "6,400,000 bytes"
            || line.contains("6.4")   // "6.4 MB"
            || line.contains("6400"); // "6400000"
        assert!(
            has_size,
            "progress line must include byte volume (6,400,000 bytes ≈ 6.4 MB); got: {line:?}"
        );
    }
}

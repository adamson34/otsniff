//! Capture-window sanity detector (S-10.01).
//!
//! A pure sibling of [`crate::capture_source`]: an enum plus a pure function
//! over [`Observations`], with a stable `message()` per variant (mirroring
//! `Classification::report_line` / `guard_warning`). It inspects only the
//! observed packet *timestamps* and reports when the time base is degenerate —
//! all-zero / epoch-1970, a sub-second window, or non-monotonic ordering — so a
//! reader knows that any time-dependent result (capture-source heuristic, flow
//! rate, port-scan window, capture-window display) may be unreliable.
//!
//! Pure-core: no I/O, never panics, and selects only constant English strings
//! (no observed identifier is read or interpolated — see the story's Scrub
//! Stance), so it is inert with respect to the scrub layer and leak detector.

use crate::observe::Observations;

/// A degenerate-timestamp condition detected over a capture's time base.
///
/// Returned in a fixed evaluation order by [`assess`] so the output `Vec` is
/// deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureWarning {
    /// Every packet sits at or before Unix epoch second 0 — there is no real
    /// time base (all-zero legacy captures, pcapng SimplePacket captures).
    EpochZeroTimestamps,
    /// The whole capture spans less than one second — too narrow for per-second
    /// rates or time-window findings to mean anything.
    SubSecondWindow,
    /// Timestamps are not monotonically increasing (reorder / clock skew).
    NonMonotonicTimestamps,
}

impl CaptureWarning {
    /// Stable, human-readable description of the condition. Constant English —
    /// no observed identifiers — so it is safe to render anywhere.
    pub fn message(&self) -> &'static str {
        match self {
            Self::EpochZeroTimestamps => {
                "capture has no real timestamps (all at/before the Unix epoch); \
                 time-based findings are unreliable"
            }
            Self::SubSecondWindow => {
                "capture spans less than one second; per-second rates and \
                 time-window findings are unreliable"
            }
            Self::NonMonotonicTimestamps => {
                "capture timestamps are not monotonically increasing (packets \
                 out of order or clock skew); the capture window and \
                 time-ordered findings may be misleading"
            }
        }
    }
}

/// Inspect the capture's time base and return every degenerate-timestamp
/// condition, in a fixed order. Empty when the time base is sane (multi-second,
/// monotonic, post-epoch) or when there are no timestamps at all.
pub fn assess(obs: &Observations) -> Vec<CaptureWarning> {
    let mut out = Vec::new();

    // No decodable timestamps at all (EC-008): the report already shows
    // "(no timestamps)" — emit no second signal. This also makes a never-
    // observed `Observations` inert.
    let (min_ts, max_ts) = match (obs.min_ts, obs.max_ts) {
        (Some(min), Some(max)) => (min, max),
        _ => return out,
    };

    // Rule 1 (epoch-zero) and Rule 2 (sub-second) are mutually exclusive: a
    // capture sitting entirely at/before epoch second 0 has no real time base,
    // so the sub-second observation would be noise.
    if obs.total_packets >= 1 && max_ts.timestamp() <= 0 {
        out.push(CaptureWarning::EpochZeroTimestamps);
    } else if obs.total_packets >= 2 && (max_ts - min_ts) < chrono::Duration::seconds(1) {
        out.push(CaptureWarning::SubSecondWindow);
    }

    // Rule 3 (non-monotonic) is independent — it can accompany a sub-second
    // window (see the combo test).
    if !obs.timestamps_monotonic {
        out.push(CaptureWarning::NonMonotonicTimestamps);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    fn epoch() -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(0, 0).single().unwrap()
    }

    fn t(secs: i64) -> chrono::DateTime<Utc> {
        // Post-epoch base (2023-11-14T22:13:20Z) + `secs`.
        Utc.timestamp_opt(1_700_000_000 + secs, 0).single().unwrap()
    }

    /// Build an `Observations` carrying only the fields `assess` reads.
    fn obs(
        min_ts: Option<chrono::DateTime<Utc>>,
        max_ts: Option<chrono::DateTime<Utc>>,
        total_packets: u64,
        timestamps_monotonic: bool,
    ) -> Observations {
        Observations {
            min_ts,
            max_ts,
            total_packets,
            timestamps_monotonic,
            ..Default::default()
        }
    }

    #[test]
    fn all_epoch_capture_is_epoch_zero() {
        let o = obs(Some(epoch()), Some(epoch()), 3, true);
        assert_eq!(assess(&o), vec![CaptureWarning::EpochZeroTimestamps]);
    }

    #[test]
    fn three_packets_spanning_sub_second_is_sub_second() {
        let min = t(0);
        let max = min + Duration::milliseconds(400);
        let o = obs(Some(min), Some(max), 3, true);
        assert_eq!(assess(&o), vec![CaptureWarning::SubSecondWindow]);
    }

    #[test]
    fn out_of_order_spanning_minutes_is_non_monotonic_only() {
        let o = obs(Some(t(0)), Some(t(300)), 3, false);
        assert_eq!(assess(&o), vec![CaptureWarning::NonMonotonicTimestamps]);
    }

    #[test]
    fn out_of_order_and_sub_second_reports_both_in_order() {
        let min = t(0);
        let max = min + Duration::milliseconds(400);
        let o = obs(Some(min), Some(max), 3, false);
        assert_eq!(
            assess(&o),
            vec![
                CaptureWarning::SubSecondWindow,
                CaptureWarning::NonMonotonicTimestamps,
            ]
        );
    }

    #[test]
    fn sane_multi_second_monotonic_capture_is_empty() {
        let o = obs(Some(t(0)), Some(t(10)), 100, true);
        assert!(assess(&o).is_empty());
    }

    #[test]
    fn exactly_one_second_window_is_empty_strict_boundary() {
        // EC-003: strict `< 1s`, so a full 1.000s window is sane.
        let o = obs(Some(t(0)), Some(t(1)), 2, true);
        assert!(assess(&o).is_empty());
    }

    #[test]
    fn single_post_epoch_packet_is_empty() {
        // EC-002: SubSecond needs >= 2 packets; one packet is sane.
        let o = obs(Some(t(0)), Some(t(0)), 1, true);
        assert!(assess(&o).is_empty());
    }

    #[test]
    fn empty_observations_is_empty() {
        // EC-008: no decodable timestamps -> no signal.
        let o = obs(None, None, 0, true);
        assert!(assess(&o).is_empty());
    }

    #[test]
    fn default_observations_never_panics_and_is_empty() {
        assert!(assess(&Observations::default()).is_empty());
    }

    #[test]
    fn every_message_is_non_empty_and_stable() {
        for w in [
            CaptureWarning::EpochZeroTimestamps,
            CaptureWarning::SubSecondWindow,
            CaptureWarning::NonMonotonicTimestamps,
        ] {
            assert!(!w.message().is_empty(), "{w:?} must have a message");
        }
    }
}

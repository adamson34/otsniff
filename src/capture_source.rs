//! Heuristic capture-source classifier.
//!
//! Decides whether the input PCAP looks like a SPAN/mirror, a host-side
//! `tcpdump`, a TAP on a single link, or something we can't tell. The
//! result feeds into the report and the AI prompt — see
//! `docs/specs/capture-source-detector.md`.

use serde::Serialize;

use crate::observe::Observations;
use crate::oui;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureSource {
    /// Probable SPAN / mirror port. Many MACs visible, broadcasts present,
    /// no host dominates.
    Span {
        distinct_macs: usize,
        broadcasts: u64,
    },
    /// Probable host-side `tcpdump`. One MAC dominates because the
    /// capturing host's NIC is on either side of nearly every frame.
    HostSide {
        dominant_mac: [u8; 6],
        appearance_pct: f32,
    },
    /// Probable TAP on a single link — two MACs dominate as endpoints.
    Tap {
        endpoint_a: [u8; 6],
        endpoint_b: [u8; 6],
        coverage_pct: f32,
    },
    /// Heuristic was inconclusive. Don't make confident topology claims.
    Ambiguous { reason: String },
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// User-declared capture source from the `--source-type` CLI flag.
/// When present, this is authoritative for the report's first-line
/// description and the AI prompt qualifier — the heuristic verdict
/// is preserved on `Classification::source` for auditability and
/// powers the guard warning when the two disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeclaredSource {
    Span,
    HostSide,
    Tap,
}

impl DeclaredSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Span => "span",
            Self::HostSide => "host-side",
            Self::Tap => "tap",
        }
    }

    /// Whether this declared type matches the kind of the heuristic
    /// verdict. `Ambiguous` is treated as agreement (the heuristic
    /// didn't form an opinion, so any declared type is consistent).
    fn agrees_with(&self, source: &CaptureSource) -> bool {
        matches!(
            (self, source),
            (Self::Span, CaptureSource::Span { .. })
                | (Self::HostSide, CaptureSource::HostSide { .. })
                | (Self::Tap, CaptureSource::Tap { .. })
                | (_, CaptureSource::Ambiguous { .. })
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    /// Heuristic verdict over the observed frame distribution.
    /// Always present — even when the user passed `--source-type`,
    /// we keep the heuristic's view for the guard warning.
    pub source: CaptureSource,
    pub confidence: Confidence,
    pub frames_analyzed: u64,
    /// User-declared source type from `--source-type`, if any. When
    /// set, drives `report_line()` and `ai_qualifier_tag()`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared: Option<DeclaredSource>,
}

const HOST_SIDE_DOMINANCE_THRESHOLD: f32 = 0.95;
const HOST_SIDE_BORDERLINE_THRESHOLD: f32 = 0.80;
/// Maximum fraction the *second* MAC can have for a host-side classification.
/// In a real host-side `tcpdump`, only the capturing host's NIC appears in
/// most frames; its single most-talked-to peer rarely exceeds ~30% of
/// frames. Above this, the dominance pattern is more consistent with a
/// SPAN observing a hub-and-spoke topology.
const HOST_SIDE_SECOND_MAC_MAX: f32 = 0.30;
const TAP_COVERAGE_THRESHOLD: f32 = 0.95;
const SPAN_MIN_DISTINCT_MACS: usize = 10;
const SPAN_NO_DOMINANT_THRESHOLD: f32 = 0.60;
const HIGH_CONFIDENCE_MIN_FRAMES: u64 = 1_000;

pub fn classify(obs: &Observations) -> Classification {
    let total = obs.total_packets;

    if total == 0 {
        return Classification {
            source: CaptureSource::Ambiguous {
                reason: "no frames parsed".to_string(),
            },
            confidence: Confidence::Low,
            frames_analyzed: 0,
            declared: None,
        };
    }

    let total_f = total as f32;
    let mut sorted: Vec<(&[u8; 6], u64)> =
        obs.mac_frame_counts.iter().map(|(m, c)| (m, *c)).collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    let distinct = sorted.len();

    // Fraction of frames where each MAC appeared.
    let pct_of = |count: u64| count as f32 / total_f;

    // 1. TAP: top two MACs both have very high coverage and the third
    //    drops off sharply. Must be checked BEFORE host-side because in
    //    a TAP both endpoints appear in ~100% of frames, which would
    //    otherwise trip the single-MAC-dominance test.
    if sorted.len() >= 2 {
        let a = sorted[0];
        let b = sorted[1];
        let third_pct = sorted.get(2).map(|(_, c)| pct_of(*c)).unwrap_or(0.0);
        let coverage = (pct_of(a.1) + pct_of(b.1)) / 2.0;
        if pct_of(a.1) >= TAP_COVERAGE_THRESHOLD
            && pct_of(b.1) >= TAP_COVERAGE_THRESHOLD
            && third_pct < 0.10
        {
            return Classification {
                source: CaptureSource::Tap {
                    endpoint_a: *a.0,
                    endpoint_b: *b.0,
                    coverage_pct: coverage,
                },
                confidence: confidence_for(total, true),
                frames_analyzed: total,
                declared: None,
            };
        }
    }

    // 2. Host-side: one MAC dominates AND the second MAC is well below
    //    HOST_SIDE_SECOND_MAC_MAX. The second-MAC test is the critical
    //    one — without it, a SPAN observing a chatty PLC (where one
    //    device naturally appears in most frames because everyone talks
    //    to it) gets misclassified as host-side.
    if let Some((mac, count)) = sorted.first() {
        let pct = pct_of(*count);
        let second_pct = sorted.get(1).map(|(_, c)| pct_of(*c)).unwrap_or(0.0);
        if pct >= HOST_SIDE_DOMINANCE_THRESHOLD && second_pct < HOST_SIDE_SECOND_MAC_MAX {
            return Classification {
                source: CaptureSource::HostSide {
                    dominant_mac: **mac,
                    appearance_pct: pct,
                },
                confidence: confidence_for(total, true),
                frames_analyzed: total,
                declared: None,
            };
        }
        if pct >= HOST_SIDE_BORDERLINE_THRESHOLD && second_pct < HOST_SIDE_SECOND_MAC_MAX {
            return Classification {
                source: CaptureSource::HostSide {
                    dominant_mac: **mac,
                    appearance_pct: pct,
                },
                confidence: Confidence::Medium,
                frames_analyzed: total,
                declared: None,
            };
        }
    }

    // 3. SPAN: many distinct MACs, no dominant one, broadcasts present.
    let dominant_pct = sorted.first().map(|(_, c)| pct_of(*c)).unwrap_or(0.0);
    let has_broadcasts = obs.broadcast_frames > 0;
    if distinct >= SPAN_MIN_DISTINCT_MACS
        && dominant_pct < SPAN_NO_DOMINANT_THRESHOLD
        && has_broadcasts
    {
        return Classification {
            source: CaptureSource::Span {
                distinct_macs: distinct,
                broadcasts: obs.broadcast_frames,
            },
            confidence: confidence_for(total, true),
            frames_analyzed: total,
            declared: None,
        };
    }

    // 4. Otherwise: ambiguous, with a reason that helps the user.
    let reason = if distinct < SPAN_MIN_DISTINCT_MACS {
        format!(
            "only {distinct} distinct MAC(s) — too few to confirm SPAN, no single MAC dominant enough for host-side"
        )
    } else if !has_broadcasts {
        "no broadcast/multicast frames seen — atypical for SPAN".to_string()
    } else if dominant_pct >= SPAN_NO_DOMINANT_THRESHOLD {
        format!(
            "top MAC accounts for {:.0}% of frames, neither full host-side nor balanced enough for SPAN",
            dominant_pct * 100.0
        )
    } else {
        "no clear pattern".to_string()
    };
    Classification {
        source: CaptureSource::Ambiguous { reason },
        confidence: confidence_for(total, false),
        frames_analyzed: total,
        declared: None,
    }
}

fn confidence_for(frames: u64, clear_pattern: bool) -> Confidence {
    match (frames >= HIGH_CONFIDENCE_MIN_FRAMES, clear_pattern) {
        (true, true) => Confidence::High,
        (true, false) => Confidence::Low,
        (false, true) => Confidence::Medium,
        (false, false) => Confidence::Low,
    }
}

impl Classification {
    /// Attach a user-declared source type. The declared type drives
    /// `report_line()` and `ai_qualifier_tag()`; the heuristic verdict
    /// is preserved on `source` so a future audit / `guard_warning()`
    /// call still has the data.
    pub fn with_declared(mut self, declared: Option<DeclaredSource>) -> Self {
        self.declared = declared;
        self
    }

    /// If `declared` is set and disagrees with the heuristic, return a
    /// stderr-ready warning. Otherwise `None`. Callers (currently each
    /// `run_*` subcommand in `cli.rs`) should emit this before any
    /// further processing — the warning is the only visible signal
    /// when the user-declared type conflicts with what the frame
    /// distribution looks like.
    pub fn guard_warning(&self) -> Option<String> {
        let declared = self.declared?;
        if declared.agrees_with(&self.source) {
            return None;
        }
        let heuristic_tag = match &self.source {
            CaptureSource::Span { .. } => "span",
            CaptureSource::HostSide { .. } => "host-side",
            CaptureSource::Tap { .. } => "tap",
            CaptureSource::Ambiguous { .. } => "ambiguous",
        };
        let detail = match &self.source {
            CaptureSource::HostSide {
                dominant_mac,
                appearance_pct,
            } => format!(
                "{:.0}% of frames involve MAC {}",
                appearance_pct * 100.0,
                oui::format_mac(dominant_mac),
            ),
            CaptureSource::Span {
                distinct_macs,
                broadcasts,
            } => format!(
                "{distinct_macs} distinct MAC(s), {broadcasts} broadcast/multicast frame(s)"
            ),
            CaptureSource::Tap {
                endpoint_a,
                endpoint_b,
                coverage_pct,
            } => format!(
                "{:.0}% coverage between MACs {} and {}",
                coverage_pct * 100.0,
                oui::format_mac(endpoint_a),
                oui::format_mac(endpoint_b),
            ),
            CaptureSource::Ambiguous { .. } => return None,
        };
        Some(format!(
            "--source-type {} declared, but heuristic suggests {} ({}). \
             Findings that depend on the declared assumption (gateway inference, \
             \"no HMI seen\", egress reads) may be misleading. Re-run with \
             --source-type {} or investigate the capture.",
            declared.label(),
            heuristic_tag,
            detail,
            heuristic_tag,
        ))
    }

    /// Human-readable single-line description for the report. Real MAC
    /// addresses pass through here unscrambled — the existing scrub
    /// pipeline replaces them with pseudonyms when this string is sent
    /// to an AI provider.
    pub fn report_line(&self) -> String {
        let conf = match self.confidence {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        };
        // If the user passed --source-type, that's authoritative for the
        // report's first line. The heuristic verdict is still kept on
        // `source` for the guard warning path.
        if let Some(declared) = self.declared {
            let suffix = match &self.source {
                CaptureSource::HostSide {
                    dominant_mac,
                    appearance_pct,
                } if declared == DeclaredSource::HostSide => format!(
                    " — {:.1}% of frames involve MAC {}",
                    appearance_pct * 100.0,
                    oui::format_mac(dominant_mac),
                ),
                CaptureSource::Tap {
                    endpoint_a,
                    endpoint_b,
                    coverage_pct,
                } if declared == DeclaredSource::Tap => format!(
                    " — {:.1}% coverage between MACs {} and {}",
                    coverage_pct * 100.0,
                    oui::format_mac(endpoint_a),
                    oui::format_mac(endpoint_b),
                ),
                CaptureSource::Span {
                    distinct_macs,
                    broadcasts,
                } if declared == DeclaredSource::Span => format!(
                    " — {distinct_macs} distinct MAC(s), {broadcasts} broadcast/multicast frame(s)"
                ),
                _ => String::new(),
            };
            let qualifier = match declared {
                DeclaredSource::Span => "user-declared SPAN".to_string(),
                DeclaredSource::HostSide => "user-declared host-side tcpdump. Findings about \"internet egress\" or \"missing HMI\" should be read as \"from this host's vantage point,\" not as a network-level claim.".to_string(),
                DeclaredSource::Tap => "user-declared TAP on a single link. Topology view is limited to that one cable.".to_string(),
            };
            return format!("{qualifier}{suffix}");
        }
        match &self.source {
            CaptureSource::Span {
                distinct_macs,
                broadcasts,
            } => format!(
                "probable SPAN ({conf} confidence) — {distinct_macs} distinct MAC(s), no host dominates, {broadcasts} broadcast/multicast frame(s) seen."
            ),
            CaptureSource::HostSide {
                dominant_mac,
                appearance_pct,
            } => format!(
                "probable host-side tcpdump ({conf} confidence) — {:.1}% of frames involve MAC {}. Findings about \"internet egress\" or \"missing HMI\" should be read as \"from this host's vantage point,\" not as a network-level claim.",
                appearance_pct * 100.0,
                oui::format_mac(dominant_mac),
            ),
            CaptureSource::Tap {
                endpoint_a,
                endpoint_b,
                coverage_pct,
            } => format!(
                "probable TAP on a single link ({conf} confidence) — {:.1}% coverage between MACs {} and {}. Topology view is limited to that one cable.",
                coverage_pct * 100.0,
                oui::format_mac(endpoint_a),
                oui::format_mac(endpoint_b),
            ),
            CaptureSource::Ambiguous { reason } => format!(
                "ambiguous ({conf} confidence) — {reason}. Topology / gateway inferences are unreliable on this capture."
            ),
        }
    }

    /// Short tag used by the AI prompt assembler to decide whether to
    /// append a qualifier clause. User-declared type is authoritative
    /// when set.
    pub fn ai_qualifier_tag(&self) -> &'static str {
        if let Some(d) = self.declared {
            return d.label();
        }
        match &self.source {
            CaptureSource::Span { .. } => "span",
            CaptureSource::HostSide { .. } => "host-side",
            CaptureSource::Tap { .. } => "tap",
            CaptureSource::Ambiguous { .. } => "ambiguous",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Observations;
    use std::collections::BTreeMap;

    fn obs_with(mac_counts: &[([u8; 6], u64)], broadcasts: u64, total: u64) -> Observations {
        let mut mac_frame_counts = BTreeMap::new();
        for (m, c) in mac_counts {
            mac_frame_counts.insert(*m, *c);
        }
        Observations {
            mac_frame_counts,
            broadcast_frames: broadcasts,
            total_packets: total,
            ..Default::default()
        }
    }

    fn mac(b: u8) -> [u8; 6] {
        [b, b, b, b, b, b]
    }

    #[test]
    fn empty_capture_is_ambiguous_low_confidence() {
        let obs = obs_with(&[], 0, 0);
        let c = classify(&obs);
        assert!(matches!(c.source, CaptureSource::Ambiguous { .. }));
        assert!(matches!(c.confidence, Confidence::Low));
    }

    #[test]
    fn host_side_dominance_classifies_correctly() {
        // 9,800 / 10,000 frames involve the same MAC; second MAC at 1%.
        let obs = obs_with(&[(mac(1), 9_800), (mac(2), 100), (mac(3), 100)], 0, 10_000);
        let c = classify(&obs);
        match c.source {
            CaptureSource::HostSide {
                dominant_mac,
                appearance_pct,
            } => {
                assert_eq!(dominant_mac, mac(1));
                assert!(appearance_pct > 0.95);
            }
            other => panic!("expected HostSide, got {other:?}"),
        }
        assert!(matches!(c.confidence, Confidence::High));
    }

    #[test]
    fn span_pattern_classifies_correctly() {
        // 12 distinct MACs, no dominance, broadcasts present.
        let mut counts: Vec<([u8; 6], u64)> = Vec::new();
        for i in 1..=12 {
            counts.push((mac(i), 1_000));
        }
        let obs = obs_with(&counts, 200, 10_000);
        let c = classify(&obs);
        assert!(
            matches!(c.source, CaptureSource::Span { .. }),
            "got {:?}",
            c.source
        );
        assert!(matches!(c.confidence, Confidence::High));
    }

    #[test]
    fn tap_pattern_classifies_correctly() {
        // Two MACs at 9,950 each, one stray broadcast contributor.
        let obs = obs_with(
            &[(mac(1), 9_950), (mac(2), 9_950), (mac(0xff), 100)],
            100,
            10_000,
        );
        let c = classify(&obs);
        assert!(
            matches!(c.source, CaptureSource::Tap { .. }),
            "got {:?}",
            c.source
        );
    }

    #[test]
    fn small_capture_no_pattern_is_ambiguous() {
        let obs = obs_with(&[(mac(1), 50), (mac(2), 50)], 0, 100);
        let c = classify(&obs);
        assert!(matches!(c.source, CaptureSource::Ambiguous { .. }));
        // 100 frames with no clear pattern — low confidence is correct.
        assert!(matches!(c.confidence, Confidence::Low));
    }

    #[test]
    fn span_with_chatty_hub_is_not_misclassified_as_host_side() {
        // Real-world case (4SICS-20): top MAC at 87%, second at 60%.
        // That's a hub-and-spoke SPAN, not host-side. The host-side
        // classification requires the second MAC to be well below 30%.
        let obs = obs_with(
            &[
                (mac(1), 8_700),
                (mac(2), 6_000),
                (mac(3), 2_600),
                (mac(4), 1_000),
                (mac(5), 1_000),
            ],
            0,
            10_000,
        );
        let c = classify(&obs);
        assert!(
            !matches!(c.source, CaptureSource::HostSide { .. }),
            "must not classify chatty-hub SPAN as host-side; got {:?}",
            c.source
        );
    }

    #[test]
    fn declared_source_matching_heuristic_produces_no_warning() {
        // 9,800 / 10,000 frames involve the same MAC → heuristic says
        // host-side; user declares host-side → no warning.
        let obs = obs_with(&[(mac(1), 9_800), (mac(2), 100), (mac(3), 100)], 0, 10_000);
        let c = classify(&obs).with_declared(Some(DeclaredSource::HostSide));
        assert!(c.guard_warning().is_none());
    }

    #[test]
    fn declared_source_disagreeing_with_heuristic_produces_warning() {
        // SPAN-looking traffic (12 distinct MACs, broadcasts) but user
        // declared --source-type host-side → warning.
        let mut counts: Vec<([u8; 6], u64)> = Vec::new();
        for i in 1..=12 {
            counts.push((mac(i), 1_000));
        }
        let obs = obs_with(&counts, 200, 10_000);
        let c = classify(&obs).with_declared(Some(DeclaredSource::HostSide));
        let warning = c.guard_warning().expect("expected a guard warning");
        assert!(warning.contains("host-side declared"));
        assert!(warning.contains("span"));
    }

    #[test]
    fn declared_source_is_authoritative_for_report_line() {
        // Heuristic would say SPAN; user declares host-side. report_line
        // should reflect the user-declared type, not the heuristic.
        let mut counts: Vec<([u8; 6], u64)> = Vec::new();
        for i in 1..=12 {
            counts.push((mac(i), 1_000));
        }
        let obs = obs_with(&counts, 200, 10_000);
        let c = classify(&obs).with_declared(Some(DeclaredSource::HostSide));
        let line = c.report_line();
        assert!(line.contains("user-declared host-side"));
    }

    #[test]
    fn ai_qualifier_tag_uses_declared_when_set() {
        let obs = obs_with(&[(mac(1), 9_800), (mac(2), 100)], 0, 10_000);
        let heuristic_only = classify(&obs);
        assert_eq!(heuristic_only.ai_qualifier_tag(), "host-side");
        let with_span = heuristic_only
            .clone()
            .with_declared(Some(DeclaredSource::Span));
        assert_eq!(with_span.ai_qualifier_tag(), "span");
        let with_tap = heuristic_only.with_declared(Some(DeclaredSource::Tap));
        assert_eq!(with_tap.ai_qualifier_tag(), "tap");
    }

    #[test]
    fn declared_with_ambiguous_heuristic_produces_no_warning() {
        // Heuristic returns Ambiguous (small capture, no clear pattern).
        // User declaring any type does not produce a warning — the
        // heuristic didn't form an opinion to disagree with.
        let obs = obs_with(&[(mac(1), 50), (mac(2), 50)], 0, 100);
        let c = classify(&obs).with_declared(Some(DeclaredSource::Span));
        assert!(c.guard_warning().is_none());
    }

    #[test]
    fn report_line_does_not_panic_for_any_variant() {
        let cases = vec![
            CaptureSource::Span {
                distinct_macs: 12,
                broadcasts: 200,
            },
            CaptureSource::HostSide {
                dominant_mac: mac(1),
                appearance_pct: 0.99,
            },
            CaptureSource::Tap {
                endpoint_a: mac(1),
                endpoint_b: mac(2),
                coverage_pct: 0.98,
            },
            CaptureSource::Ambiguous {
                reason: "test".to_string(),
            },
        ];
        for src in cases {
            let c = Classification {
                source: src,
                confidence: Confidence::High,
                frames_analyzed: 10_000,
                declared: None,
            };
            let _ = c.report_line();
        }
    }
}

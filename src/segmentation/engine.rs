//! Run the Zonewarden conformance pipeline over bridged flows.
//!
//! Per flow: classify the destination (multicast/broadcast vs normal) → resolve
//! both endpoints to zones → classify the verdict against the policy's conduits
//! → materialize violation rows. Then aggregate into a [`ConformanceResult`]
//! (tallies + violations + deterministic `policy_digest`). This is the
//! orchestration ported from the standalone zonewarden CLI (ADR-0013); the
//! per-flow logic is the pure, Kani-verified engine.

use zonewarden::classifier::{self, ClassifyCtx};
use zonewarden::errors::SysError;
use zonewarden::types::{ConformanceResult, Flow, ValidatedPolicy, Verdict, Violation};
use zonewarden::{aggregator, multicast, resolver};

/// Classify every flow against the validated policy and aggregate the result.
/// `skipped` is 0 here — otsniff's flows arrive already parsed from the PCAP, so
/// there is no per-record ingest-skip channel (unlike the Zeek conn.log path).
pub fn run(validated: &ValidatedPolicy, flows: &[Flow]) -> Result<ConformanceResult, SysError> {
    let ctx = ClassifyCtx { policy: validated };
    let items: Vec<(Verdict, Vec<Violation>)> = flows
        .iter()
        .map(|flow| {
            let dst_kind = multicast::classify_dst(flow.dst_ip, &validated.prefix_index);
            let pair = resolver::resolve_pair(&validated.prefix_index, flow.src_ip, flow.dst_ip);
            let verdict = classifier::classify(&ctx, flow, &pair, dst_kind);
            let violations = classifier::violations_for(flow, &pair, &verdict);
            (verdict, violations)
        })
        .collect();
    aggregator::aggregate(items, validated, 0, validated.warnings.clone())
}

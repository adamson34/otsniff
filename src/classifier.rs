//! Per-flow classifier — the verdict engine (pure core, S-4.03).
//!
//! Assigns a deterministic [`Verdict`] to every resolved, non-multicast flow:
//! `IntraZone` (same zone, no conduit eval — DI-002/BC-1.04.001), `Allowed`
//! (≥1 conduit permits the zone-pair + proto + port + direction, union
//! semantics — BC-1.04.003), `WrongDirection` (a conduit matches proto+port but
//! only in the reverse orientation — BC-1.04.004), or `NoMatchingConduit`
//! (deny-by-default — BC-1.04.002). The IDMZ-bypass finding is computed
//! additively for every non-IntraZone flow (BC-1.04.007).
//!
//! Multicast/broadcast dsts never reach the classifier (they short-circuit to
//! `MulticastExempt` upstream — S-4.04), so the IDMZ check is called with
//! `DstKind::Normal`. Severity is attached only when violations are materialized
//! ([`violations_for`], BC-1.04.009) — never on the `Verdict` itself.

use crate::types::{
    ConduitId, Direction, DstKind, Flow, ResolvedPair, ValidatedPolicy, Verdict, VerdictKind,
    Violation, ViolationKind,
};
use crate::{idmz, severity};

/// Read-only context for classification: the validated policy (its conduits and
/// zone metadata). The resolver index is not needed here — the pair is already
/// resolved.
pub struct ClassifyCtx<'a> {
    pub policy: &'a ValidatedPolicy,
}

/// Classify a resolved flow pair into a [`Verdict`] (kind + additive idmz_bypass).
pub fn classify(ctx: &ClassifyCtx, flow: &Flow, pair: &ResolvedPair) -> Verdict {
    let src_zone = pair.src.zone_id.clone();
    let dst_zone = pair.dst.zone_id.clone();

    // IntraZone short-circuit (DI-002 / BC-1.04.001): same zone is implicitly
    // allowed — no conduit evaluation, and no IDMZ check (endpoints share a zone
    // and level, so a bypass is impossible by definition).
    if pair.same_zone() {
        return Verdict {
            flow_index: flow.flow_index,
            src_zone,
            dst_zone,
            kind: VerdictKind::IntraZone,
            idmz_bypass: false,
        };
    }

    // Conduit matching, union semantics (BC-1.04.003). A conduit must match
    // proto AND port (portless flows match only `PortSet::Any`, BC-1.04.006);
    // then the zone-pair orientation decides direction. The first fully-matching
    // conduit wins (order-independent result); a proto+port match in the reverse
    // orientation of a Forward conduit is remembered as a WrongDirection signal
    // that outranks the generic deny (BC-1.04.004).
    let mut allowed: Option<u32> = None;
    let mut wrong_direction = false;
    for (i, c) in ctx.policy.policy.conduits.iter().enumerate() {
        if c.proto != flow.proto || !c.ports.matches_port(flow.dst_port) {
            continue;
        }
        let forward = src_zone == c.from_zone && dst_zone == c.to_zone;
        let reverse = src_zone == c.to_zone && dst_zone == c.from_zone;
        match c.direction {
            Direction::Bidirectional => {
                if forward || reverse {
                    allowed = Some(i as u32);
                    break;
                }
            }
            Direction::Forward => {
                if forward {
                    allowed = Some(i as u32);
                    break;
                } else if reverse {
                    wrong_direction = true;
                }
            }
        }
    }

    let kind = match allowed {
        Some(idx) => VerdictKind::Allowed(ConduitId(idx)),
        None if wrong_direction => VerdictKind::WrongDirection,
        None => VerdictKind::NoMatchingConduit,
    };

    // IDMZ bypass is an additive finding evaluated for every non-IntraZone flow
    // (BC-1.04.007), independent of the conduit verdict. Multicast dsts never
    // reach the classifier (S-4.04 handles them), so dst_kind is Normal.
    let idmz_bypass = idmz::check(&pair.src, &pair.dst, DstKind::Normal, ctx.policy);

    Verdict {
        flow_index: flow.flow_index,
        src_zone,
        dst_zone,
        kind,
        idmz_bypass,
    }
}

/// Materialize the violation rows for a classified flow (BC-1.04.009): a conduit
/// violation (`NoMatchingConduit`/`WrongDirection`) and/or an additive
/// `IdmzBypass`, each graded by `severity::grade(conn_state)`. Empty for
/// `IntraZone`/`Allowed`/`MulticastExempt` flows with no idmz bypass.
pub fn violations_for(flow: &Flow, pair: &ResolvedPair, verdict: &Verdict) -> Vec<Violation> {
    let mut out = Vec::new();
    let severity = severity::grade(flow.conn_state.as_ref());

    let row = |kind: ViolationKind, explanation: String| Violation {
        flow_index: flow.flow_index,
        src_zone: pair.src.zone_id.clone(),
        dst_zone: pair.dst.zone_id.clone(),
        kind,
        severity,
        idmz_bypass: verdict.idmz_bypass,
        explanation,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        proto: flow.proto.clone(),
        service: flow.service.clone(),
        service_source: flow.service_source,
        conn_state: flow.conn_state.clone(),
    };

    let src = &pair.src.zone_id.0;
    let dst = &pair.dst.zone_id.0;
    match verdict.kind {
        VerdictKind::NoMatchingConduit => out.push(row(
            ViolationKind::NoMatchingConduit,
            format!("no conduit permits flow {src} -> {dst}"),
        )),
        VerdictKind::WrongDirection => out.push(row(
            ViolationKind::WrongDirection,
            format!("flow {src} -> {dst} matches a conduit only in the reverse direction"),
        )),
        // IntraZone / Allowed / MulticastExempt are not conduit violations.
        _ => {}
    }
    if verdict.idmz_bypass {
        out.push(row(
            ViolationKind::IdmzBypass,
            "direct OT-IT flow without an IDMZ endpoint".to_string(),
        ));
    }
    out
}

//! Per-flow classifier — the verdict engine (pure core, S-4.03 + S-4.04).
//!
//! Assigns exactly one deterministic [`Verdict`] to every resolved flow, in
//! ST-6 precedence order (BC-1.04.010 totality): `MulticastExempt` (multicast/
//! broadcast dst short-circuit — BC-1.04.011) → `IntraZone` (same zone, no
//! conduit eval — DI-002/BC-1.04.001) → conduit matching, which yields `Allowed`
//! (≥1 conduit permits the zone-pair + proto + port + direction, union
//! semantics — BC-1.04.003), `WrongDirection` (proto+port match in the reverse
//! orientation of a Forward conduit — BC-1.04.004), or `NoMatchingConduit`
//! (deny-by-default — BC-1.04.002).
//!
//! The IDMZ-bypass finding is computed additively for every non-IntraZone,
//! non-multicast flow (BC-1.04.007); it adds no `VerdictKind`. Severity is
//! attached only when violations are materialized ([`violations_for`],
//! BC-1.04.009) — never on the `Verdict` itself.

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
pub fn classify(ctx: &ClassifyCtx, flow: &Flow, pair: &ResolvedPair, dst_kind: DstKind) -> Verdict {
    let src_zone = pair.src.zone_id.clone();
    let dst_zone = pair.dst.zone_id.clone();

    // MulticastExempt — highest precedence (ST-6 / BC-1.04.011), checked BEFORE
    // IntraZone and conduit evaluation. A multicast/broadcast dst short-circuits
    // here so dominant cyclic OT I/O never generates false violations;
    // idmz_bypass is forced false and idmz::check is not called (DI-016).
    if dst_kind == DstKind::MulticastBroadcast {
        return Verdict {
            flow_index: flow.flow_index,
            src_zone,
            dst_zone,
            kind: VerdictKind::MulticastExempt,
            idmz_bypass: false,
        };
    }

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
        if c.proto != flow.proto {
            continue;
        }
        let forward = src_zone == c.from_zone && dst_zone == c.to_zone;
        let reverse = src_zone == c.to_zone && dst_zone == c.from_zone;
        // In the forward orientation the service port is the responder (dst) port.
        let dst_match = c.ports.matches_port(flow.dst_port);
        match c.direction {
            Direction::Bidirectional => {
                if (forward || reverse) && dst_match {
                    allowed = Some(i as u32);
                    break;
                }
            }
            Direction::Forward => {
                if forward && dst_match {
                    allowed = Some(i as u32);
                    break;
                } else if reverse && (dst_match || c.ports.matches_port(flow.src_port)) {
                    // Reverse orientation is WrongDirection (BC-1.04.004) when the
                    // conduit's service port appears on EITHER side: dst-port match
                    // is a flow reaching into from_zone's service (EC-001/EC-005);
                    // src-port match is the return/reverse 4-tuple of a permitted
                    // flow (HS-010) — the canonical wrong-direction case.
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
        ts: flow.ts,
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

/// Formal-verification harness (VP-1.04.010). Compiled only under `cargo kani`.
#[cfg(kani)]
mod kani_harness {
    use super::*;
    use crate::types::{MatchKind, Policy, ResolvedEndpoint, Timestamp, ZoneId};
    use std::net::{IpAddr, Ipv4Addr};

    fn empty_policy() -> ValidatedPolicy {
        ValidatedPolicy {
            policy: Policy {
                zones: Vec::new(),
                conduits: Vec::new(),
            },
            prefix_index: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn endpoint(id: &str) -> ResolvedEndpoint {
        ResolvedEndpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            zone_id: ZoneId(id.to_string()),
            match_kind: MatchKind::ImplicitExternal,
        }
    }

    fn a_flow() -> Flow {
        Flow {
            flow_index: 0,
            ts: Timestamp(0),
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: None,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: None,
            proto: crate::types::Proto::Tcp,
            service: None,
            service_source: crate::types::ServiceSource::Unknown,
            conn_state: None,
        }
    }

    /// Verdict totality (VP-1.04.010-a/b): `classify` always returns a `Verdict`
    /// with exactly one kind, and the precedence holds — multicast outranks
    /// same-zone, which outranks the (empty-policy) deny. No panic path.
    #[kani::proof]
    fn verdict_total() {
        let vp = empty_policy();
        let ctx = ClassifyCtx { policy: &vp };
        let is_mc: bool = kani::any();
        let same_zone: bool = kani::any();
        let dst_kind = if is_mc {
            DstKind::MulticastBroadcast
        } else {
            DstKind::Normal
        };
        let pair = ResolvedPair {
            src: endpoint("a"),
            dst: endpoint(if same_zone { "a" } else { "b" }),
        };
        let v = classify(&ctx, &a_flow(), &pair, dst_kind);
        if is_mc {
            assert!(matches!(v.kind, VerdictKind::MulticastExempt));
            assert!(!v.idmz_bypass);
        } else if same_zone {
            assert!(matches!(v.kind, VerdictKind::IntraZone));
        } else {
            // empty policy, distinct zones, normal dst → deny-by-default
            assert!(matches!(v.kind, VerdictKind::NoMatchingConduit));
        }
    }
}

//! Zonewarden segmentation-conformance findings (ADR-0013).
//!
//! Unlike the zero-config rules, these fire only when a `--policy` is supplied:
//! they translate the conformance engine's verdicts (a [`ConformanceResult`])
//! into otsniff findings. Violations are **rolled up by kind** — a real plant
//! capture can produce hundreds of thousands of violation rows, so emitting one
//! finding per flow would bury the report. Each finding leads with the
//! *Established* (actually-connected) count, which is the actionable subset, and
//! lists the top offending flows as evidence.

use zonewarden::types::{
    ConformanceResult, Service, Severity as ZwSeverity, Violation, ViolationKind,
};

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};
use crate::observe::Observations;

pub const IDMZ_BYPASS_METADATA: RuleMetadata = RuleMetadata {
    id: "zonewarden.idmz_bypass",
    title: "IDMZ bypass — direct OT↔IT flow",
    severity: Severity::Critical,
    trigger: "Fires when the segmentation policy resolves a flow's endpoints to \
              an OT zone (Purdue ≤ L3) and an IT zone (≥ L4) with no IDMZ (L3.5) \
              hop between them — the headline IEC 62443 Restricted Data Flow \
              control. Requires a `--policy`. Rolled up to one finding; the \
              count and top offenders are in the evidence.",
    data_source: &["segmentation_policy", "flows"],
    references: &[
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-3 SR-5.1 — Network segmentation",
            url: None,
        },
        Reference {
            kind: ReferenceKind::Spec,
            label: "ISA/IEC 62443-3-2 — Zones & conduits (Purdue L3.5 IDMZ)",
            url: None,
        },
    ],
};

pub const WRONG_DIRECTION_METADATA: RuleMetadata = RuleMetadata {
    id: "zonewarden.wrong_direction",
    title: "Conduit used in the wrong direction",
    severity: Severity::High,
    trigger: "Fires when a flow matches a Forward conduit's protocol and \
              responder port but in the reverse zone orientation — traffic \
              flowing opposite to the declared, permitted direction. Requires \
              a `--policy`. Rolled up to one finding.",
    data_source: &["segmentation_policy", "flows"],
    references: &[Reference {
        kind: ReferenceKind::Spec,
        label: "ISA/IEC 62443-3-2 — Conduit directionality",
        url: None,
    }],
};

pub const DENY_BY_DEFAULT_METADATA: RuleMetadata = RuleMetadata {
    id: "zonewarden.deny_by_default",
    title: "Cross-zone flow not permitted by any conduit",
    severity: Severity::High,
    trigger: "Fires when a cross-zone flow is permitted by no conduit in the \
              policy (deny-by-default). Requires a `--policy`. Rolled up to one \
              finding; the Established (actually-connected) subset is called out \
              separately from refused/no-response attempts.",
    data_source: &["segmentation_policy", "flows"],
    references: &[Reference {
        kind: ReferenceKind::Spec,
        label: "ISA/IEC 62443-3-3 SR-5.1 — Restricted data flow (deny-by-default)",
        url: None,
    }],
};

/// Translate conformance verdicts into rolled-up findings. Empty when the
/// policy is fully satisfied (no violations).
pub fn detect(result: &ConformanceResult, obs: &Observations) -> Vec<Finding> {
    let mut out = Vec::new();

    let bypass = filter(result, ViolationKind::IdmzBypass);
    if let Some(f) = rollup(
        &bypass,
        &IDMZ_BYPASS_METADATA,
        "Route OT↔IT traffic through the IDMZ (L3.5). Each pair below is a direct \
         cross-Purdue flow with no broker/jump-host in the path.",
        obs,
    ) {
        out.push(f);
    }

    let wrong = filter(result, ViolationKind::WrongDirection);
    if let Some(f) = rollup(
        &wrong,
        &WRONG_DIRECTION_METADATA,
        "Confirm the intended direction of these conduits; a reverse-direction \
         match usually means the conduit orientation or the asset roles are wrong.",
        obs,
    ) {
        out.push(f);
    }

    let deny = filter(result, ViolationKind::NoMatchingConduit);
    if let Some(f) = rollup(
        &deny,
        &DENY_BY_DEFAULT_METADATA,
        "Triage the Established flows first — those connected. Either add a \
         conduit for legitimate traffic or investigate the source.",
        obs,
    ) {
        out.push(f);
    }

    out
}

fn filter(result: &ConformanceResult, kind: ViolationKind) -> Vec<&Violation> {
    result
        .violations
        .iter()
        .filter(|v| v.kind == kind)
        .collect()
}

/// Build one finding from all violations of a kind. `None` when there are none.
fn rollup(
    vios: &[&Violation],
    meta: &RuleMetadata,
    recommendation: &'static str,
    obs: &Observations,
) -> Option<Finding> {
    if vios.is_empty() {
        return None;
    }
    let total = vios.len();
    let established = vios
        .iter()
        .filter(|v| v.severity == ZwSeverity::Established)
        .count();
    let attempted = total - established;

    // Evidence: Established (connected) flows first, then attempted, deterministic.
    let mut ordered: Vec<&&Violation> = vios.iter().collect();
    ordered.sort_by(|a, b| {
        sev_rank(a.severity)
            .cmp(&sev_rank(b.severity))
            .then(a.src_ip.cmp(&b.src_ip))
            .then(a.dst_ip.cmp(&b.dst_ip))
            .then(a.dst_port.cmp(&b.dst_port))
    });
    let evidence: Vec<String> = ordered
        .iter()
        .take(15)
        .map(|v| evidence_line(v, obs))
        .collect();

    let summary = format!(
        "{total} flow(s) — {established} established (connected), {attempted} attempted \
         (refused/no-response). Established flows are the actionable subset.",
    );

    Some(Finding {
        id: meta.id,
        severity: meta.severity,
        title: meta.title.to_string(),
        summary,
        evidence,
        recommendation,
        playbook: vec![],
    })
}

fn sev_rank(s: ZwSeverity) -> u8 {
    match s {
        ZwSeverity::Established => 0, // sorts first
        ZwSeverity::Attempted => 1,
    }
}

fn evidence_line(v: &Violation, obs: &Observations) -> String {
    let port = v.dst_port.map(|p| format!(":{p}")).unwrap_or_default();
    let svc = match &v.service {
        Some(s) => format!(" {}", service_label(s)),
        None => String::new(),
    };
    format!(
        "{} {} -> {} {}{} {}{} [{}]",
        v.src_zone.0,
        host_label(v.src_ip, obs),
        v.dst_zone.0,
        host_label(v.dst_ip, obs),
        port,
        proto_label(&v.proto),
        svc,
        sev_label(v.severity),
    )
}

fn proto_label(p: &zonewarden::types::Proto) -> &'static str {
    use zonewarden::types::Proto;
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => "icmp",
        Proto::Other(_) => "ip",
    }
}

fn service_label(s: &Service) -> &'static str {
    match s {
        Service::Modbus => "modbus",
        Service::Dnp3 => "dnp3",
        Service::EtherNetIp => "enip",
        Service::S7comm => "s7comm",
        Service::Bacnet => "bacnet",
        Service::OpcUa => "opcua",
        Service::Other(_) => "svc?",
    }
}

fn sev_label(s: ZwSeverity) -> &'static str {
    match s {
        ZwSeverity::Established => "Established",
        ZwSeverity::Attempted => "Attempted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segmentation;
    use chrono::DateTime;
    use std::collections::HashSet;
    use std::net::IpAddr;

    const POLICY: &str = r#"
zones:
  - id: plc
    name: PLC
    purdue_level: L1
    members: ["10.0.1.0/24"]
  - id: it
    name: Enterprise
    purdue_level: L4
    members: ["10.0.5.0/24"]
conduits: []
"#;

    fn obs_flow(src: &str, dst: &str, dport: u16) -> crate::observe::FlowObs {
        let t = DateTime::from_timestamp(1_717_200_000, 0).unwrap();
        crate::observe::FlowObs {
            key: crate::observe::FlowKey {
                src: src.parse::<IpAddr>().unwrap(),
                dst: dst.parse::<IpAddr>().unwrap(),
                dst_port: dport,
                proto: 6,
            },
            packets: 3,
            bytes: 300,
            first_seen: t,
            last_seen: t,
            label: None,
            unique_src_ports: HashSet::from([40000]),
        }
    }

    #[test]
    fn idmz_bypass_rolls_up_to_one_critical_finding() {
        // plc(L1) -> it(L4) with no conduit: NoMatchingConduit + IDMZ bypass.
        let flows = vec![
            obs_flow("10.0.1.5", "10.0.5.9", 80),
            obs_flow("10.0.1.6", "10.0.5.9", 502),
        ];
        let result = segmentation::run_conformance(POLICY, &flows).unwrap();
        let findings = detect(&result, &Observations::default());

        let bypass = findings
            .iter()
            .find(|f| f.id == "zonewarden.idmz_bypass")
            .expect("an idmz_bypass finding");
        assert_eq!(bypass.severity, Severity::Critical);
        assert!(bypass.summary.contains("2 flow(s)"));
        assert!(!bypass.evidence.is_empty());
        // Two distinct kinds present → at most 3 findings, one per kind.
        assert!(findings
            .iter()
            .any(|f| f.id == "zonewarden.deny_by_default"));
        assert!(findings.len() <= 3);
    }

    #[test]
    fn clean_policy_yields_no_findings() {
        let result = segmentation::run_conformance(POLICY, &[]).unwrap();
        assert!(detect(&result, &Observations::default()).is_empty());
    }

    #[test]
    fn policy_aware_run_dedups_egress_and_adds_zonewarden() {
        use crate::findings::{run_all, run_with_conformance};
        use crate::observe::ExternalFlow;

        // An Observations with an OT→internet flow → the subnet-based egress
        // rule fires on its own.
        let mut obs = Observations::default();
        obs.external_flows.insert(
            "k".to_string(),
            ExternalFlow {
                src: "10.0.1.5".parse().unwrap(),
                dst: "8.8.8.8".parse().unwrap(),
                dst_port: 53,
                proto: 17,
                packets: 10,
                bytes: 1000,
            },
        );
        assert!(
            run_all(&obs, &[])
                .iter()
                .any(|f| f.id == "egress.ot_to_internet"),
            "egress rule fires without a policy"
        );

        // With a policy + conformance result, egress is owned by the engine:
        // the subnet rule is dropped and zonewarden findings are added.
        let result =
            segmentation::run_conformance(POLICY, &[obs_flow("10.0.1.5", "10.0.5.9", 80)]).unwrap();
        let findings = run_with_conformance(&obs, &[], &result);
        assert!(
            !findings.iter().any(|f| f.id == "egress.ot_to_internet"),
            "egress is deduped when a policy is present"
        );
        assert!(
            findings.iter().any(|f| f.id.starts_with("zonewarden.")),
            "conformance findings are present"
        );
    }
}

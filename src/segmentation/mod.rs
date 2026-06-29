//! Zonewarden — segmentation-conformance integration (ADR-0013).
//!
//! otsniff is the effectful shell; the `zonewarden` crate is the pure, formally
//! verified conformance engine. This module is the glue between them: it loads
//! policies ([`policy`]), bridges otsniff's observed flows into the engine's
//! `Flow` input ([`bridge`]), and runs the conformance pipeline ([`engine`]).
//!
//! The `zonewarden.*` findings, report section, and `otsniff zonewarden`
//! subcommand are the remaining ADR-0013 follow-ups.

pub mod bridge;
pub mod engine;
pub mod policy;

use zonewarden::errors::ZonewardenError;
use zonewarden::types::ConformanceResult;
use zonewarden::validator;

use crate::observe::FlowObs;

/// End-to-end conformance: parse + validate a YAML policy, bridge otsniff's
/// observed flows into engine flows, and classify them. Returns the full
/// [`ConformanceResult`] (tallies, violations, deterministic `policy_digest`).
pub fn run_conformance(
    policy_yaml: &str,
    obs: &[FlowObs],
) -> Result<ConformanceResult, ZonewardenError> {
    let parsed = policy::load_str(policy_yaml)?;
    run_validated(parsed, obs)
}

/// Same as [`run_conformance`], reading the policy from a YAML file on disk.
pub fn run_conformance_path(
    policy_path: &std::path::Path,
    obs: &[FlowObs],
) -> Result<ConformanceResult, ZonewardenError> {
    let parsed = policy::load(policy_path)?;
    run_validated(parsed, obs)
}

fn run_validated(
    parsed: zonewarden::types::Policy,
    obs: &[FlowObs],
) -> Result<ConformanceResult, ZonewardenError> {
    let validated = validator::validate(parsed)?;
    let flows = bridge::flows_from_observations(obs);
    Ok(engine::run(&validated, &flows)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{FlowKey, FlowObs};
    use chrono::DateTime;
    use std::collections::HashSet;
    use std::net::IpAddr;

    const POLICY: &str = r#"
zones:
  - id: plc
    name: PLC Cell
    purdue_level: L1
    members: ["10.0.1.0/24"]
  - id: hist
    name: Historian
    purdue_level: L3
    members: ["10.0.3.0/24"]
  - id: it
    name: Enterprise
    purdue_level: L4
    members: ["10.0.5.0/24"]
conduits:
  - from_zone: plc
    to_zone: hist
    direction: forward
    proto: tcp
    ports: [502]
"#;

    fn obs(src: &str, dst: &str, dport: u16, proto: u8, label: Option<&str>) -> FlowObs {
        let t = DateTime::from_timestamp(1_717_200_000, 0).unwrap();
        FlowObs {
            key: FlowKey {
                src: src.parse::<IpAddr>().unwrap(),
                dst: dst.parse::<IpAddr>().unwrap(),
                dst_port: dport,
                proto,
            },
            packets: 5,
            bytes: 500,
            first_seen: t,
            last_seen: t,
            label: label.map(str::to_string),
            unique_src_ports: HashSet::from([40000]),
        }
    }

    #[test]
    fn classifies_real_verdicts_end_to_end() {
        let flows = vec![
            obs("10.0.1.5", "10.0.3.9", 502, 6, Some("modbus")), // plc->hist:502  Allowed
            obs("10.0.1.6", "10.0.3.9", 9999, 6, None),          // plc->hist:9999 NoMatchingConduit
            obs("10.0.1.7", "10.0.5.9", 502, 6, None), // plc(L1)->it(L4):502  IDMZ bypass (no conduit)
        ];
        let r = run_conformance(POLICY, &flows).expect("conformance runs");

        assert_eq!(r.total_flows, 3);
        assert_eq!(r.allowed, 1, "plc->hist:502 is permitted");
        assert_eq!(r.no_matching_conduit, 2, "the 9999 flow + the OT->IT flow");
        assert_eq!(r.idmz_bypasses, 1, "plc(L1)->it(L4) with no IDMZ hop");
        assert_eq!(r.distinct_violating_flows, 2);
        assert_eq!(r.skipped, 0);
        assert_eq!(r.policy_digest.len(), 64, "sha-256 hex digest");
    }

    #[test]
    fn digest_is_deterministic_and_flow_order_independent() {
        let a = obs("10.0.1.5", "10.0.3.9", 502, 6, None);
        let b = obs("10.0.1.6", "10.0.5.9", 80, 6, None);
        let r1 = run_conformance(POLICY, &[a.clone(), b.clone()]).unwrap();
        let r2 = run_conformance(POLICY, &[b, a]).unwrap();
        assert_eq!(r1.policy_digest, r2.policy_digest);
        assert_eq!(r1.idmz_bypasses, r2.idmz_bypasses);
        assert_eq!(r1.no_matching_conduit, r2.no_matching_conduit);
    }

    #[test]
    fn empty_policy_is_rejected_or_runs_clean() {
        // An invalid (empty-string) policy surfaces a ZonewardenError, not a panic.
        assert!(run_conformance("", &[]).is_err());
    }
}

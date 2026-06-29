//! Bridge otsniff's observed flows into the Zonewarden engine's `Flow` input.
//!
//! otsniff's [`FlowObs`] is a *logical* flow aggregated by `(src, dst, dst_port,
//! proto)` with a set of source ports (see `docs/specs/flow-grouping.md`); the
//! Zonewarden engine classifies one `Flow` per logical flow. The mapping is:
//!
//! - `src_port` → `None`. A logical flow aggregates over many ephemeral source
//!   ports, and the conformance verdict never depends on the source port (zone
//!   resolution is by IP; conduit matching is by responder/`dst_port`; direction
//!   is by zone-pair). Collapsing to `None` is therefore lossless for the verdict.
//! - `dst_port` → `Some(port)` for port-bearing transports; `None` for portless
//!   protocols (ICMP / other), which the engine matches only against `PortSet::Any`.
//! - `conn_state` → `None` for now. otsniff's `FlowObs` does not yet carry a TCP
//!   connection state; the engine grades `None` conservatively as `Established`.
//!   Deriving real SF/REJ/S0 from otsniff's TCP tracking is a tracked ADR-0013
//!   follow-up (it restores the Established-vs-Attempted severity split).
//!
//! Flows are emitted in a deterministic canonical order (sorted by the flow key)
//! and assigned dense `flow_index` values, so the engine's `policy_digest` and
//! sort keys stay reproducible even though otsniff's upstream parse order is not.

use chrono::{DateTime, Utc};
use zonewarden::types::{Flow, Proto, Service, ServiceSource, Timestamp};

use crate::observe::FlowObs;

/// Convert otsniff's observed logical flows into Zonewarden engine flows, in a
/// deterministic order with dense `flow_index` values.
pub fn flows_from_observations(obs: &[FlowObs]) -> Vec<Flow> {
    let mut sorted: Vec<&FlowObs> = obs.iter().collect();
    sorted.sort_by(|a, b| {
        a.key
            .src
            .cmp(&b.key.src)
            .then(a.key.dst.cmp(&b.key.dst))
            .then(a.key.dst_port.cmp(&b.key.dst_port))
            .then(a.key.proto.cmp(&b.key.proto))
    });

    sorted
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let proto = map_proto(o.key.proto);
            let portless = proto.is_portless();
            let (service, service_source) = map_service(o.label.as_deref());
            Flow {
                flow_index: i as u64,
                ts: Timestamp(to_unix_nanos(o.first_seen)),
                src_ip: o.key.src,
                src_port: None,
                dst_ip: o.key.dst,
                dst_port: if portless { None } else { Some(o.key.dst_port) },
                proto,
                service,
                service_source,
                // TODO(ADR-0013): derive from otsniff TCP tracking to restore the
                // Established/Attempted severity split. None grades as Established.
                conn_state: None,
            }
        })
        .collect()
}

/// IP-protocol number → transport [`Proto`].
fn map_proto(ip_proto: u8) -> Proto {
    match ip_proto {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        1 => Proto::Icmp,
        other => Proto::Other(other),
    }
}

/// otsniff's flow label → engine [`Service`] + its provenance. The OT protocols
/// otsniff parses at the payload level are `DpiConfirmed`; any other non-empty
/// label is a heuristic; absence is `Unknown`. (Service identity is carried for
/// reporting; it does not affect the conformance verdict.)
fn map_service(label: Option<&str>) -> (Option<Service>, ServiceSource) {
    let Some(raw) = label else {
        return (None, ServiceSource::Unknown);
    };
    let l = raw.to_ascii_lowercase();
    match l.as_str() {
        "modbus" => (Some(Service::Modbus), ServiceSource::DpiConfirmed),
        "dnp3" | "dnp3_tcp" => (Some(Service::Dnp3), ServiceSource::DpiConfirmed),
        "enip" | "ethernetip" | "ethernet-ip" | "cip" => {
            (Some(Service::EtherNetIp), ServiceSource::DpiConfirmed)
        }
        "s7" | "s7comm" => (Some(Service::S7comm), ServiceSource::DpiConfirmed),
        "bacnet" => (Some(Service::Bacnet), ServiceSource::DpiConfirmed),
        "opcua" | "opc_ua" | "opc-ua" => (Some(Service::OpcUa), ServiceSource::DpiConfirmed),
        _ => (
            Some(Service::Other(raw.to_string())),
            ServiceSource::PortHeuristic,
        ),
    }
}

/// `DateTime<Utc>` → nanoseconds since the Unix epoch (the engine's `Timestamp`).
fn to_unix_nanos(dt: DateTime<Utc>) -> i128 {
    dt.timestamp_nanos_opt()
        .map(i128::from)
        .unwrap_or_else(|| i128::from(dt.timestamp()) * 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::FlowKey;
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn obs(src: &str, dst: &str, dport: u16, proto: u8, label: Option<&str>) -> FlowObs {
        let t = DateTime::from_timestamp(1_717_200_000, 0).unwrap();
        FlowObs {
            key: FlowKey {
                src: src.parse::<IpAddr>().unwrap(),
                dst: dst.parse::<IpAddr>().unwrap(),
                dst_port: dport,
                proto,
            },
            packets: 10,
            bytes: 1000,
            first_seen: t,
            last_seen: t,
            label: label.map(str::to_string),
            unique_src_ports: HashSet::from([40000, 40001]),
        }
    }

    #[test]
    fn tcp_modbus_maps_with_dpi_service() {
        let f = &flows_from_observations(&[obs("10.0.1.5", "10.0.3.9", 502, 6, Some("modbus"))])[0];
        assert_eq!(f.proto, Proto::Tcp);
        assert_eq!(f.dst_port, Some(502));
        assert_eq!(f.src_port, None);
        assert_eq!(f.service, Some(Service::Modbus));
        assert_eq!(f.service_source, ServiceSource::DpiConfirmed);
        assert_eq!(f.conn_state, None);
    }

    #[test]
    fn portless_icmp_drops_dst_port() {
        let f = &flows_from_observations(&[obs("10.0.1.5", "10.0.3.9", 0, 1, None)])[0];
        assert_eq!(f.proto, Proto::Icmp);
        assert_eq!(f.dst_port, None, "portless proto must not carry a dst_port");
        assert_eq!(f.service, None);
        assert_eq!(f.service_source, ServiceSource::Unknown);
    }

    #[test]
    fn proto_number_mapping() {
        assert_eq!(map_proto(6), Proto::Tcp);
        assert_eq!(map_proto(17), Proto::Udp);
        assert_eq!(map_proto(1), Proto::Icmp);
        assert_eq!(map_proto(47), Proto::Other(47));
    }

    #[test]
    fn unknown_label_is_port_heuristic_other() {
        let (svc, src) = map_service(Some("http"));
        assert_eq!(svc, Some(Service::Other("http".to_string())));
        assert_eq!(src, ServiceSource::PortHeuristic);
    }

    #[test]
    fn ordering_is_deterministic_and_dense() {
        // Same set in two different input orders must yield identical flow_index
        // assignments (the engine's digest/sort depend on it).
        let a = obs("10.0.1.5", "10.0.3.9", 502, 6, None);
        let b = obs("10.0.1.6", "10.0.3.9", 9999, 6, None);
        let c = obs("10.0.1.5", "10.0.5.9", 502, 6, None);
        let one = flows_from_observations(&[a.clone(), b.clone(), c.clone()]);
        let two = flows_from_observations(&[c, a, b]);
        let key = |f: &Flow| (f.src_ip, f.dst_ip, f.dst_port);
        assert_eq!(
            one.iter().map(key).collect::<Vec<_>>(),
            two.iter().map(key).collect::<Vec<_>>(),
            "flow order must be input-order-independent"
        );
        assert_eq!(
            one.iter().map(|f| f.flow_index).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "flow_index must be dense and gap-free"
        );
    }
}

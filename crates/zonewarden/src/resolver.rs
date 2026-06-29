//! Zone resolution — longest-prefix match over the validated policy index
//! (pure core, S-3.01).
//!
//! Resolves each flow endpoint IP to exactly one zone (DI-003/DI-004). The
//! `PrefixIndex` is built and sorted (descending by prefix length) by the
//! validator (S-1.03); the resolver does NOT re-sort (ADR-003) — it scans and
//! returns the first containing entry, which is therefore the longest-prefix
//! match. A tie-free index (BC-1.01.005) guarantees uniqueness. Endpoints that
//! match no declared matcher resolve to the reserved EXTERNAL zone
//! (BC-1.03.002). Pure: `(&PrefixIndex, IpAddr) -> value`, no I/O, no mutation.
//!
//! Preconditions (upstream): the IP is already canonicalized (IPv4-mapped IPv6
//! folded, BC-1.02.005), non-unspecified (BC-1.02.003), and non-multicast
//! (BC-1.03.003 handles those before this step).

use std::net::IpAddr;

use crate::types::{MatchKind, PrefixIndex, ResolvedEndpoint, ResolvedPair, ZoneId};

/// Resolve a single endpoint IP to its zone via longest-prefix match
/// (BC-1.03.001), falling back to EXTERNAL when nothing matches (BC-1.03.002).
///
/// The index is sorted descending by prefix length (validator, ADR-003), so the
/// first containing entry is the longest match. A tie-free index (BC-1.01.005)
/// makes that match unique. Total by construction — always returns a value.
pub fn resolve(index: &PrefixIndex, ip: IpAddr) -> ResolvedEndpoint {
    for (net, zone_id) in index {
        if net.contains(&ip) {
            return ResolvedEndpoint {
                ip,
                zone_id: zone_id.clone(),
                match_kind: MatchKind::Explicit {
                    prefix_len: net.prefix_len(),
                },
            };
        }
    }
    ResolvedEndpoint {
        ip,
        zone_id: ZoneId(ZoneId::EXTERNAL.to_string()),
        match_kind: MatchKind::ImplicitExternal,
    }
}

/// Resolve both endpoints of a flow (the classifier's input). Both-EXTERNAL /
/// same-zone handling is exposed via [`ResolvedPair`] (BC-1.03.005).
pub fn resolve_pair(index: &PrefixIndex, src_ip: IpAddr, dst_ip: IpAddr) -> ResolvedPair {
    ResolvedPair {
        src: resolve(index, src_ip),
        dst: resolve(index, dst_ip),
    }
}

/// Formal-verification harness (VP-1.03.001-a). Compiled only under `cargo kani`
/// (`--cfg kani`); excluded from normal builds and tests.
#[cfg(kani)]
mod kani_harness {
    use super::*;
    use ipnet::IpNet;
    use std::net::Ipv4Addr;

    /// Totality (DI-003): with no declared matcher, every endpoint resolves to
    /// EXTERNAL — `resolve` always returns a value and never panics.
    #[kani::proof]
    fn resolve_is_total_on_empty_index() {
        let octets: [u8; 4] = kani::any();
        let ip = IpAddr::V4(Ipv4Addr::from(octets));
        let index: PrefixIndex = PrefixIndex::new();
        let r = resolve(&index, ip);
        assert!(r.zone_id.is_external());
        assert!(matches!(r.match_kind, MatchKind::ImplicitExternal));
    }

    /// Longest-prefix selection + uniqueness (VP-002 / BC-1.03.001): given a
    /// validator-sorted index where a /24 precedes an overlapping /16, every IP
    /// inside the /24 resolves to the /24's zone (the longer prefix wins), an IP
    /// in the /16 but not the /24 resolves to the /16's zone, and anything else
    /// is EXTERNAL. Concrete nets + a symbolic IP prove the selection over the
    /// whole IPv4 space.
    #[kani::proof]
    fn longest_prefix_wins() {
        let index: PrefixIndex = vec![
            (
                IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)), 24).unwrap(),
                ZoneId("inner".to_string()),
            ),
            (
                IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 16).unwrap(),
                ZoneId("outer".to_string()),
            ),
        ];
        let octets: [u8; 4] = kani::any();
        let ip = IpAddr::V4(Ipv4Addr::from(octets));
        let r = resolve(&index, ip);

        // Assert on the matched prefix length (a u8) rather than the zone-id
        // String — a String comparison makes CBMC unwind memcmp unboundedly,
        // and the prefix length uniquely identifies which entry was selected.
        let in_24 = octets[0] == 10 && octets[1] == 0 && octets[2] == 1;
        let in_16 = octets[0] == 10 && octets[1] == 0;
        match r.match_kind {
            MatchKind::Explicit { prefix_len } => {
                if in_24 {
                    assert_eq!(prefix_len, 24); // the /24 wins over the overlapping /16
                } else {
                    assert!(in_16);
                    assert_eq!(prefix_len, 16);
                }
            }
            MatchKind::ImplicitExternal => assert!(!in_16),
            // resolve never produces MulticastBroadcast (multicast is handled
            // upstream); proving this arm unreachable is part of the property.
            MatchKind::MulticastBroadcast => unreachable!(),
        }
    }
}

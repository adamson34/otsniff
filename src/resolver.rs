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
}

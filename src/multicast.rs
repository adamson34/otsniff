//! Multicast / broadcast destination detection (pure core, S-3.02).
//!
//! Implements DI-016 Steps 1-2, run on the destination IP before zone-pair
//! classification. A dst flagged `MulticastBroadcast` short-circuits to the
//! `MulticastExempt` verdict (BC-1.03.003 / BC-1.03.004), so dominant cyclic OT
//! I/O (BACnet broadcasts, EtherNet/IP implicit multicast) does not generate
//! false `NoMatchingConduit` violations.
//!
//! - **Step 1 (family-wide):** IPv4 multicast `224.0.0.0/4`, IPv4 limited
//!   broadcast `255.255.255.255`, IPv6 multicast `ff00::/8`. No zone context.
//! - **Step 2 (directed broadcast, IPv4 only):** the dst is the all-ones host of
//!   its longest-prefix-matched zone CIDR with prefix length ≤ 30. `/31` and
//!   `/32` are excluded (no usable broadcast — closes silent-allow vector R-002).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::types::{DstKind, PrefixIndex};

/// Classify a flow destination as `Normal` or `MulticastBroadcast` (DI-016).
pub fn classify_dst(dst: IpAddr, index: &PrefixIndex) -> DstKind {
    // Step 1 — family-wide multicast / limited broadcast (no zone context).
    let step1 = match dst {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    };
    if step1 {
        return DstKind::MulticastBroadcast;
    }

    // Step 2 — directed broadcast (IPv4 only) of the longest-prefix-matched zone.
    // The index is sorted descending by prefix length, so the first containing
    // entry is the longest match; only that zone's CIDR is considered
    // (BC-1.03.004 inv 3). `/31` and `/32` are excluded (no usable broadcast).
    for (net, _zone) in index {
        if net.contains(&dst) {
            if matches!(net, IpNet::V4(_)) && net.prefix_len() <= 30 && net.broadcast() == dst {
                return DstKind::MulticastBroadcast;
            }
            break;
        }
    }
    DstKind::Normal
}

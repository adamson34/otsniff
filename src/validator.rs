//! Policy semantic validation (pure core, S-1.03).
//!
//! Runs after structural parse (BC-1.01.001) as pipeline stage ST-2. Rejects
//! every semantically-invalid policy with a precise `PolicyError` before any flow
//! is processed (all-or-nothing — DI-011), and builds the longest-prefix index
//! the resolver consumes. Non-fatal observations (zero-member zones, very-short
//! prefixes) are returned as `warnings`, never printed here (purity).
//!
//! Token legality for `direction`/`proto` (BC-1.01.007) is enforced upstream at
//! load time (S-1.02): a typed `Policy` cannot represent an invalid token, so the
//! type system makes that contract unrepresentable here.

use std::collections::{HashMap, HashSet};

use ipnet::IpNet;

use crate::errors::PolicyError;
use crate::types::{AssetMatcher, Policy, PrefixIndex, ValidatedPolicy, ZoneId};

/// Validate a parsed `Policy`, returning a `ValidatedPolicy` (with its prefix
/// index and warnings) or the first `PolicyError` encountered (BC-1.01.004–008).
pub fn validate(policy: Policy) -> Result<ValidatedPolicy, PolicyError> {
    let mut warnings = Vec::new();

    // 1. Zone ids unique; the reserved EXTERNAL id may not be redeclared
    //    (BC-1.01.004 / DI-010 / AC-001 / AC-007).
    let mut ids: HashSet<String> = HashSet::new();
    for z in &policy.zones {
        if z.id.0 == ZoneId::EXTERNAL || !ids.insert(z.id.0.clone()) {
            return Err(PolicyError::DuplicateZoneId { id: z.id.0.clone() });
        }
    }

    // 2. Every conduit endpoint must be a declared zone or the reserved EXTERNAL
    //    (BC-1.01.004 / AC-002).
    for c in &policy.conduits {
        for zid in [&c.from_zone, &c.to_zone] {
            if zid.0 != ZoneId::EXTERNAL && !ids.contains(zid.0.as_str()) {
                return Err(PolicyError::UnknownConduitZone {
                    from: c.from_zone.0.clone(),
                    to: c.to_zone.0.clone(),
                    zone: zid.0.clone(),
                });
            }
        }
    }

    // 3. Members: reject /0 catch-alls (AC-004), warn on zero-member zones
    //    (AC-006) and very-short prefixes (AC-008/OQ-004), and build the index.
    let mut index: PrefixIndex = Vec::new();
    for z in &policy.zones {
        if z.members.is_empty() {
            warnings.push(format!("zone '{}' has no members", z.id.0));
        }
        for m in &z.members {
            if let AssetMatcher::Cidr { prefix_len: 0, .. } = m {
                return Err(PolicyError::CatchAllPrefix {
                    zone: z.id.0.clone(),
                    cidr: matcher_str(m),
                });
            }
            let net = matcher_to_net(m)?;
            let plen = net.prefix_len();
            if plen > 0 && plen < 8 {
                warnings.push(format!(
                    "zone '{}': member '{}' has very short prefix (< /8); may partially shadow EXTERNAL",
                    z.id.0,
                    matcher_str(m)
                ));
            }
            index.push((net, z.id.clone()));
        }
    }

    // 4. Equal-prefix ties: the same canonical network in two distinct zones is
    //    ambiguous for longest-prefix resolution (BC-1.01.005 / AC-003). A
    //    duplicate within one zone is merely redundant, not a tie.
    let mut by_net: HashMap<IpNet, ZoneId> = HashMap::new();
    for (net, zid) in &index {
        match by_net.get(net) {
            Some(existing) if existing != zid => {
                return Err(PolicyError::PrefixTie {
                    cidr: net.to_string(),
                    zone_a: existing.0.clone(),
                    zone_b: zid.0.clone(),
                });
            }
            _ => {
                by_net.insert(*net, zid.clone());
            }
        }
    }

    // 5. Sort descending by prefix length so the first containing entry is the
    //    most specific match (ADR-003 / AC-009).
    index.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));

    Ok(ValidatedPolicy {
        policy,
        prefix_index: index,
        warnings,
    })
}

/// Convert a zone member to its canonical network (host bits cleared). A bare
/// `IpAddr` is a host route (`/32` or `/128`).
fn matcher_to_net(m: &AssetMatcher) -> Result<IpNet, PolicyError> {
    let net = match m {
        AssetMatcher::Ip(ip) => {
            let plen = if ip.is_ipv4() { 32 } else { 128 };
            IpNet::new(*ip, plen)
        }
        AssetMatcher::Cidr { addr, prefix_len } => IpNet::new(*addr, *prefix_len),
    };
    net.map(|n| n.trunc())
        .map_err(|_| PolicyError::InvalidToken {
            field: "members".to_string(),
            value: matcher_str(m),
        })
}

/// Render a member as the user wrote it, for diagnostics.
fn matcher_str(m: &AssetMatcher) -> String {
    match m {
        AssetMatcher::Ip(ip) => ip.to_string(),
        AssetMatcher::Cidr { addr, prefix_len } => format!("{addr}/{prefix_len}"),
    }
}

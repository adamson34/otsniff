//! Policy digest — canonical JSON + SHA-256 (pure core, S-5.01).
//!
//! Produces a stable `policy_digest`: the SHA-256 (lowercase hex) of a canonical
//! JSON serialization of the policy *model* (BC-1.05.003, ADR-004, DI-018). Two
//! model-equivalent policies — differing only in YAML whitespace, comments, key
//! order, member/zone/conduit order, or duplicate conduits — hash identically.
//!
//! Canonical form (DI-018): object keys sorted lexicographically (via the default
//! `serde_json::Map` = `BTreeMap`); zones sorted by `id`; members sorted by their
//! string form; conduits de-duplicated then sorted by
//! `(from_zone, to_zone, proto, direction, ports)`; `PortSet` normalized
//! (already canonical at load, BC-1.01.009); `None` fields omitted; compact
//! output (no whitespace). Only `Policy` fields are digested — never
//! `prefix_index`/`warnings` (ADR-004).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::portset::PortSet;
use crate::types::{AssetMatcher, Conduit, Direction, Policy, Proto, PurdueLevel, SlTarget, Zone};

/// Compute the lowercase-hex SHA-256 digest of the policy's canonical JSON form.
pub fn compute(policy: &Policy) -> String {
    let canonical = canonical_json(policy);
    // `to_string` (not pretty) → compact, no whitespace (ADR-004 step 7). Object
    // keys are emitted in sorted order because `serde_json::Map` is a `BTreeMap`.
    let bytes = serde_json::to_string(&canonical).expect("canonical Value always serializes");

    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    let out = hasher.finalize();

    let mut hex = String::with_capacity(64);
    for byte in out {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Build the canonical JSON `Value` for the policy model.
fn canonical_json(policy: &Policy) -> Value {
    let mut zones: Vec<&Zone> = policy.zones.iter().collect();
    zones.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    let zones_json: Vec<Value> = zones.iter().map(|z| zone_json(z)).collect();

    // De-duplicate then sort conduits by (from, to, proto, direction, ports).
    let mut conduits: Vec<(String, Value)> = policy.conduits.iter().map(conduit_entry).collect();
    conduits.sort_by(|a, b| a.0.cmp(&b.0));
    conduits.dedup_by(|a, b| a.0 == b.0);
    let conduits_json: Vec<Value> = conduits.into_iter().map(|(_, v)| v).collect();

    let mut root = Map::new();
    root.insert("zones".to_string(), Value::Array(zones_json));
    root.insert("conduits".to_string(), Value::Array(conduits_json));
    Value::Object(root)
}

fn zone_json(z: &Zone) -> Value {
    let mut m = Map::new();
    m.insert("id".to_string(), Value::String(z.id.0.clone()));
    m.insert("name".to_string(), Value::String(z.name.clone()));
    m.insert(
        "purdue_level".to_string(),
        Value::String(purdue_token(z.purdue_level).to_string()),
    );
    // None is omitted entirely (not serialized as null) — BC-1.05.003 postcond 5.
    if let Some(sl) = &z.sl_t {
        m.insert("sl_t".to_string(), sl_target_json(sl));
    }
    let mut members: Vec<String> = z.members.iter().map(matcher_repr).collect();
    members.sort();
    m.insert(
        "members".to_string(),
        Value::Array(members.into_iter().map(Value::String).collect()),
    );
    Value::Object(m)
}

fn sl_target_json(sl: &SlTarget) -> Value {
    let mut m = Map::new();
    if let Some(overall) = sl.overall {
        m.insert("overall".to_string(), Value::from(overall));
    }
    if let Some(v) = sl.fr_vector {
        m.insert(
            "fr_vector".to_string(),
            Value::Array(v.iter().map(|&n| Value::from(n)).collect()),
        );
    }
    Value::Object(m)
}

/// Build a conduit's canonical JSON plus the string key used to sort/de-duplicate
/// it: `(from_zone, to_zone, proto, direction, ports)` (BC-1.05.003 / DI-018).
fn conduit_entry(c: &Conduit) -> (String, Value) {
    let proto = proto_token(&c.proto);
    let direction = direction_token(c.direction);
    let ports = ports_repr(&c.ports);
    // Unit separator keeps the composite key unambiguous across fields.
    let key = format!(
        "{}\u{1f}{}\u{1f}{proto}\u{1f}{direction}\u{1f}{ports}",
        c.from_zone.0, c.to_zone.0
    );

    let mut m = Map::new();
    m.insert(
        "from_zone".to_string(),
        Value::String(c.from_zone.0.clone()),
    );
    m.insert("to_zone".to_string(), Value::String(c.to_zone.0.clone()));
    m.insert(
        "direction".to_string(),
        Value::String(direction.to_string()),
    );
    m.insert("proto".to_string(), Value::String(proto));
    m.insert("ports".to_string(), ports_json(&c.ports));
    (key, Value::Object(m))
}

fn matcher_repr(m: &AssetMatcher) -> String {
    match m {
        AssetMatcher::Ip(ip) => ip.to_string(),
        AssetMatcher::Cidr { addr, prefix_len } => format!("{addr}/{prefix_len}"),
    }
}

fn purdue_token(level: PurdueLevel) -> &'static str {
    match level {
        PurdueLevel::L0 => "L0",
        PurdueLevel::L1 => "L1",
        PurdueLevel::L2 => "L2",
        PurdueLevel::L3 => "L3",
        PurdueLevel::Idmz => "IDMZ",
        PurdueLevel::L4 => "L4",
        PurdueLevel::L5 => "L5",
    }
}

fn direction_token(d: Direction) -> &'static str {
    match d {
        Direction::Forward => "forward",
        Direction::Bidirectional => "bidirectional",
    }
}

fn proto_token(p: &Proto) -> String {
    match p {
        Proto::Tcp => "tcp".to_string(),
        Proto::Udp => "udp".to_string(),
        Proto::Icmp => "icmp".to_string(),
        Proto::Other(n) => format!("other:{n}"),
    }
}

/// Stable string form of a `PortSet` used for both sorting and serialization.
/// `Any` is the distinct sentinel `"any"` (DI-020); ranges are `"lo-hi"`.
fn ports_repr(p: &PortSet) -> String {
    match p {
        PortSet::Any => "any".to_string(),
        PortSet::Ranges(rs) => rs
            .iter()
            .map(|r| format!("{}-{}", r.lo, r.hi))
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn ports_json(p: &PortSet) -> Value {
    match p {
        PortSet::Any => Value::String("any".to_string()),
        PortSet::Ranges(rs) => Value::Array(
            rs.iter()
                .map(|r| Value::String(format!("{}-{}", r.lo, r.hi)))
                .collect(),
        ),
    }
}

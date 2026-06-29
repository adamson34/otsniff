//! Zonewarden policy loading (effectful shell). Reads a YAML segmentation policy
//! and maps it into the pure-engine `Policy` model. All YAML wire-format quirks
//! live here (proto `other:<u8>`, `ports` lists/ranges, `sl_t` scalar-or-vector,
//! the `unidirectional` alias); the `zonewarden` engine stays free of
//! serialization. Ported from the standalone zonewarden CLI (ADR-0013).
//!
//! Parse-only. Cross-reference / tie / `/0`-member validation is
//! `zonewarden::validator::validate`.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

use zonewarden::errors::{IoError, PolicyError, ZonewardenError};
use zonewarden::portset::PortSet;
use zonewarden::types::{
    AssetMatcher, Conduit, Direction, Policy, Proto, PurdueLevel, SlTarget, Zone, ZoneId,
};

/// Load and parse a YAML policy file into the engine `Policy` model.
pub fn load(path: &Path) -> Result<Policy, ZonewardenError> {
    let text = read_policy_file(path)?;
    load_str(&text)
}

/// Parse a YAML policy from an in-memory string (the pure parse step of [`load`]).
pub fn load_str(text: &str) -> Result<Policy, ZonewardenError> {
    if text.trim().is_empty() {
        return Err(PolicyError::Empty.into()); // E-POL-001
    }
    let dto: PolicyYaml = serde_norway::from_str(text).map_err(classify_yaml_error)?;
    Ok(dto.into_policy()?)
}

fn read_policy_file(path: &Path) -> Result<String, IoError> {
    fs::read_to_string(path).map_err(|e| {
        let p = path.display().to_string();
        match e.kind() {
            std::io::ErrorKind::NotFound => IoError::NotFound { path: p },
            std::io::ErrorKind::PermissionDenied => IoError::PermissionDenied { path: p },
            _ => IoError::Read {
                path: p,
                detail: e.to_string(),
            },
        }
    })
}

/// Map a serde/YAML error to the policy error taxonomy (E-POL-002/003/004).
fn classify_yaml_error(e: serde_norway::Error) -> ZonewardenError {
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    let err = if lower.contains("duplicate") {
        PolicyError::DuplicateKey { detail: msg } // E-POL-004
    } else if lower.contains("missing field") {
        PolicyError::MissingField {
            field: first_backticked(&msg).unwrap_or_else(|| "?".to_string()),
            location: String::new(),
        } // E-POL-002
    } else {
        PolicyError::InvalidToken {
            field: "policy".to_string(),
            value: msg,
        } // E-POL-003
    };
    err.into()
}

fn first_backticked(s: &str) -> Option<String> {
    let start = s.find('`')? + 1;
    let rest = &s[start..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

// ── YAML DTOs (wire format) ──────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyYaml {
    #[serde(default)]
    zones: Vec<ZoneYaml>,
    #[serde(default)]
    conduits: Vec<ConduitYaml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneYaml {
    id: String,
    name: String,
    purdue_level: String,
    #[serde(default)]
    sl_t: Option<SlTargetYaml>,
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConduitYaml {
    from_zone: String,
    to_zone: String,
    direction: String,
    proto: String,
    ports: PortsYaml,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SlTargetYaml {
    Scalar(u8),
    Vector {
        #[serde(default)]
        overall: Option<u8>,
        #[serde(default)]
        fr_vector: Option<[u8; 7]>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PortsYaml {
    Keyword(String),      // "any"
    List(Vec<PortEntry>), // [502, "500-510"]
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PortEntry {
    Num(u16),
    Token(String), // "500-510" (unquoted YAML ranges arrive as strings)
}

// ── DTO → engine conversion ──────────────────────────────────────────────────

impl PolicyYaml {
    fn into_policy(self) -> Result<Policy, PolicyError> {
        let zones = self
            .zones
            .into_iter()
            .map(ZoneYaml::into_zone)
            .collect::<Result<Vec<_>, _>>()?;
        let conduits = self
            .conduits
            .into_iter()
            .map(ConduitYaml::into_conduit)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Policy { zones, conduits })
    }
}

impl ZoneYaml {
    fn into_zone(self) -> Result<Zone, PolicyError> {
        let purdue_level = parse_purdue(&self.purdue_level)?;
        let sl_t = self.sl_t.map(SlTargetYaml::into_core);
        let members = self
            .members
            .iter()
            .map(|m| parse_matcher(m))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Zone {
            id: ZoneId(self.id),
            name: self.name,
            purdue_level,
            sl_t,
            members,
        })
    }
}

impl ConduitYaml {
    fn into_conduit(self) -> Result<Conduit, PolicyError> {
        Ok(Conduit {
            from_zone: ZoneId(self.from_zone),
            to_zone: ZoneId(self.to_zone),
            direction: parse_direction(&self.direction)?,
            proto: parse_proto(&self.proto)?,
            ports: self.ports.into_portset()?,
        })
    }
}

impl SlTargetYaml {
    fn into_core(self) -> SlTarget {
        match self {
            SlTargetYaml::Scalar(v) => SlTarget {
                overall: Some(v),
                fr_vector: None,
            },
            SlTargetYaml::Vector { overall, fr_vector } => SlTarget { overall, fr_vector },
        }
    }
}

impl PortsYaml {
    fn into_portset(self) -> Result<PortSet, PolicyError> {
        match self {
            PortsYaml::Keyword(k) if k.eq_ignore_ascii_case("any") => Ok(PortSet::Any),
            PortsYaml::Keyword(k) => Err(invalid("ports", &k)),
            PortsYaml::List(entries) => {
                let pairs = entries
                    .into_iter()
                    .map(PortEntry::into_pair)
                    .collect::<Result<Vec<_>, _>>()?;
                // from_pairs validates lo<=hi and returns the DI-020 canonical form.
                PortSet::from_pairs(&pairs)
                    .map_err(|_| invalid("ports", "inverted range (lo > hi)"))
            }
        }
    }
}

impl PortEntry {
    fn into_pair(self) -> Result<(u16, u16), PolicyError> {
        match self {
            PortEntry::Num(p) => Ok((p, p)),
            PortEntry::Token(t) => parse_range_token(&t),
        }
    }
}

// ── token parsers ────────────────────────────────────────────────────────────

fn parse_purdue(s: &str) -> Result<PurdueLevel, PolicyError> {
    Ok(match s {
        "L0" => PurdueLevel::L0,
        "L1" => PurdueLevel::L1,
        "L2" => PurdueLevel::L2,
        "L3" => PurdueLevel::L3,
        "IDMZ" => PurdueLevel::Idmz,
        "L4" => PurdueLevel::L4,
        "L5" => PurdueLevel::L5,
        other => return Err(invalid("purdue_level", other)),
    })
}

fn parse_direction(s: &str) -> Result<Direction, PolicyError> {
    Ok(match s {
        "forward" | "unidirectional" => Direction::Forward, // unidirectional is an alias
        "bidirectional" => Direction::Bidirectional,
        other => return Err(invalid("direction", other)),
    })
}

fn parse_proto(s: &str) -> Result<Proto, PolicyError> {
    Ok(match s {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        other => match other.strip_prefix("other:") {
            Some(n) => Proto::Other(n.parse().map_err(|_| invalid("proto", other))?),
            None => return Err(invalid("proto", other)),
        },
    })
}

fn parse_matcher(s: &str) -> Result<AssetMatcher, PolicyError> {
    match s.split_once('/') {
        Some((addr, prefix)) => {
            let ip: IpAddr = addr.parse().map_err(|_| invalid("members", s))?;
            let prefix_len: u8 = prefix.parse().map_err(|_| invalid("members", s))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if prefix_len > max {
                return Err(invalid("members", s));
            }
            Ok(AssetMatcher::Cidr {
                addr: ip,
                prefix_len,
            })
        }
        None => Ok(AssetMatcher::Ip(
            s.parse().map_err(|_| invalid("members", s))?,
        )),
    }
}

fn parse_range_token(t: &str) -> Result<(u16, u16), PolicyError> {
    match t.split_once('-') {
        Some((lo, hi)) => {
            let lo: u16 = lo.trim().parse().map_err(|_| invalid("ports", t))?;
            let hi: u16 = hi.trim().parse().map_err(|_| invalid("ports", t))?;
            Ok((lo, hi))
        }
        None => {
            let p: u16 = t.trim().parse().map_err(|_| invalid("ports", t))?;
            Ok((p, p))
        }
    }
}

fn invalid(field: &str, value: &str) -> PolicyError {
    PolicyError::InvalidToken {
        field: field.to_string(),
        value: value.to_string(),
    }
}

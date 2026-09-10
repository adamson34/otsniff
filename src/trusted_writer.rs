//! Operator-declared trusted-writer allowlist (P1-12, [ADR-0015](../docs/adr/0015-operator-declared-trusted-writers.md)).
//!
//! `--trusted-writer SRC=DST:PROTO` lets an operator name a known-good
//! engineering-command pair (e.g. an EWS writing to a PLC rack) so repeat
//! captures don't flag the same expected pair High/Critical forever. This
//! is an **unverified assertion**, not authentication: IPs are spoofable
//! and otsniff is a passive PCAP tool. See `docs/specs/trusted-writer-allowlist.md`
//! for the full design (D1-D4) — in particular D2 (partition, never
//! downgrade a whole finding) and D4 (audit log records a digest, not the
//! declared addresses).

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::audit::sha256_hex;

/// Protocol token in a `--trusted-writer` declaration (D1a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterProto {
    Modbus,
    Cip,
    S7,
    Dnp3,
    /// Matches any of the four protocols above.
    Any,
}

impl WriterProto {
    fn token(self) -> &'static str {
        match self {
            Self::Modbus => "modbus",
            Self::Cip => "cip",
            Self::S7 => "s7",
            Self::Dnp3 => "dnp3",
            Self::Any => "any",
        }
    }
}

impl FromStr for WriterProto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "modbus" => Ok(Self::Modbus),
            "cip" => Ok(Self::Cip),
            "s7" => Ok(Self::S7),
            "dnp3" => Ok(Self::Dnp3),
            "any" => Ok(Self::Any),
            other => Err(format!(
                "unknown protocol '{other}' (expected modbus, cip, s7, dnp3, or any)"
            )),
        }
    }
}

/// One parsed `--trusted-writer SRC=DST:PROTO` declaration. SRC/DST may be a
/// bare address (treated as a /32 or /128) or a CIDR (D1a).
#[derive(Debug, Clone)]
pub struct TrustedWriterRule {
    pub src: IpNet,
    pub dst: IpNet,
    pub proto: WriterProto,
}

impl TrustedWriterRule {
    pub fn matches(&self, src: IpAddr, dst: IpAddr, proto: WriterProto) -> bool {
        self.src.contains(&src)
            && self.dst.contains(&dst)
            && (self.proto == WriterProto::Any || self.proto == proto)
    }

    /// Normalized text used for the digest and for stderr warnings — CIDR
    /// form even for a bare-address declaration, so two textually
    /// different but semantically identical declarations digest the same.
    fn canonical(&self) -> String {
        format!("{}={}:{}", self.src, self.dst, self.proto.token())
    }
}

impl FromStr for TrustedWriterRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lhs, proto_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("'{s}' is missing ':PROTO' (expected SRC=DST:PROTO)"))?;
        let (src_str, dst_str) = lhs
            .split_once('=')
            .ok_or_else(|| format!("'{s}' is missing '=' (expected SRC=DST:PROTO)"))?;
        if src_str.is_empty() || dst_str.is_empty() {
            return Err(format!(
                "'{s}': SRC and DST must not be empty (expected SRC=DST:PROTO)"
            ));
        }
        let src = parse_ip_or_cidr(src_str).map_err(|e| format!("'{s}': invalid SRC — {e}"))?;
        let dst = parse_ip_or_cidr(dst_str).map_err(|e| format!("'{s}': invalid DST — {e}"))?;
        let proto = proto_str
            .parse::<WriterProto>()
            .map_err(|e| format!("'{s}': {e}"))?;
        Ok(TrustedWriterRule { src, dst, proto })
    }
}

fn parse_ip_or_cidr(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Ok(IpNet::V4(
            Ipv4Net::new(v4, 32).expect("32 is a valid IPv4 prefix length"),
        )),
        Ok(IpAddr::V6(v6)) => Ok(IpNet::V6(
            Ipv6Net::new(v6, 128).expect("128 is a valid IPv6 prefix length"),
        )),
        Err(_) => Err(format!("'{s}' is not a valid IP address or CIDR")),
    }
}

/// 1-based index of the first declared rule that matches `(src, dst, proto)`,
/// or `None` if no rule covers it. Declaration order is significant: this is
/// the index the `ics.trusted_writer_activity` evidence references (D3)
/// instead of echoing the raw declaration text.
pub fn classify(
    rules: &[TrustedWriterRule],
    src: IpAddr,
    dst: IpAddr,
    proto: WriterProto,
) -> Option<usize> {
    rules
        .iter()
        .position(|r| r.matches(src, dst, proto))
        .map(|i| i + 1)
}

/// SHA-256 (lowercase hex) over the sorted, de-duplicated canonical text of
/// every declared rule (D4). Recorded in the audit log instead of the raw
/// CIDRs/addresses so two runs can be compared for "was the same allowlist
/// in force?" without the compliance artifact carrying host identifiers.
pub fn digest(rules: &[TrustedWriterRule]) -> String {
    let mut canon: Vec<String> = rules.iter().map(TrustedWriterRule::canonical).collect();
    canon.sort();
    canon.dedup();
    sha256_hex(&canon.join("\n"))
}

/// Declared rules whose 1-based index is absent from `matched`. Callers
/// print each entry's canonical text on stderr — "a run with
/// `--trusted-writer` that matches nothing emits a warning naming the
/// unmatched declarations" (spec, Behaviour on the report).
pub fn unmatched<'a>(
    rules: &'a [TrustedWriterRule],
    matched: &std::collections::BTreeSet<usize>,
) -> Vec<&'a TrustedWriterRule> {
    rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched.contains(&(i + 1)))
        .map(|(_, r)| r)
        .collect()
}

impl std::fmt::Display for TrustedWriterRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_bare_ip_pair() {
        let r: TrustedWriterRule = "10.20.0.5=10.20.0.10:modbus".parse().unwrap();
        assert!(r.matches(ip("10.20.0.5"), ip("10.20.0.10"), WriterProto::Modbus));
        assert!(!r.matches(ip("10.20.0.6"), ip("10.20.0.10"), WriterProto::Modbus));
    }

    #[test]
    fn parses_cidr_dst() {
        let r: TrustedWriterRule = "10.20.0.5=10.20.0.0/24:modbus".parse().unwrap();
        assert!(r.matches(ip("10.20.0.5"), ip("10.20.0.250"), WriterProto::Modbus));
        assert!(!r.matches(ip("10.20.0.5"), ip("10.20.1.1"), WriterProto::Modbus));
    }

    #[test]
    fn parses_ipv6() {
        let r: TrustedWriterRule = "fe80::1=fe80::2:s7".parse().unwrap();
        assert!(r.matches(ip("fe80::1"), ip("fe80::2"), WriterProto::S7));
    }

    #[test]
    fn any_matches_every_protocol() {
        let r: TrustedWriterRule = "10.20.0.5=10.20.0.10:any".parse().unwrap();
        for p in [
            WriterProto::Modbus,
            WriterProto::Cip,
            WriterProto::S7,
            WriterProto::Dnp3,
        ] {
            assert!(r.matches(ip("10.20.0.5"), ip("10.20.0.10"), p));
        }
    }

    #[test]
    fn rule_for_one_protocol_does_not_match_another() {
        let r: TrustedWriterRule = "10.20.0.5=10.20.0.10:modbus".parse().unwrap();
        assert!(!r.matches(ip("10.20.0.5"), ip("10.20.0.10"), WriterProto::S7));
    }

    #[test]
    fn rejects_missing_equals() {
        let err = "10.20.0.5-10.20.0.10:modbus"
            .parse::<TrustedWriterRule>()
            .unwrap_err();
        assert!(err.contains('='));
    }

    #[test]
    fn rejects_missing_proto() {
        let err = "10.20.0.5=10.20.0.10"
            .parse::<TrustedWriterRule>()
            .unwrap_err();
        assert!(err.contains("PROTO"));
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!("10.20.0.5=not-an-ip:modbus"
            .parse::<TrustedWriterRule>()
            .is_err());
    }

    #[test]
    fn rejects_unknown_proto() {
        assert!("10.20.0.5=10.20.0.10:bogus"
            .parse::<TrustedWriterRule>()
            .is_err());
    }

    #[test]
    fn rejects_empty_src_or_dst() {
        assert!("=10.20.0.10:modbus".parse::<TrustedWriterRule>().is_err());
        assert!("10.20.0.5=:modbus".parse::<TrustedWriterRule>().is_err());
    }

    #[test]
    fn classify_returns_one_based_first_match() {
        let rules: Vec<TrustedWriterRule> = vec![
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
            "10.20.0.5=10.20.0.11:s7".parse().unwrap(),
        ];
        assert_eq!(
            classify(&rules, ip("10.20.0.5"), ip("10.20.0.11"), WriterProto::S7),
            Some(2)
        );
        assert_eq!(
            classify(&rules, ip("9.9.9.9"), ip("10.20.0.11"), WriterProto::S7),
            None
        );
    }

    #[test]
    fn digest_is_stable_and_order_independent() {
        let a: Vec<TrustedWriterRule> = vec![
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
            "10.20.0.5=10.20.0.11:s7".parse().unwrap(),
        ];
        let b: Vec<TrustedWriterRule> = vec![
            "10.20.0.5=10.20.0.11:s7".parse().unwrap(),
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
        ];
        assert_eq!(digest(&a), digest(&b));
        assert_eq!(digest(&a).len(), 64, "sha-256 hex digest");
    }

    #[test]
    fn digest_normalizes_bare_ip_vs_explicit_prefix() {
        let a: Vec<TrustedWriterRule> = vec!["10.20.0.5=10.20.0.10:modbus".parse().unwrap()];
        let b: Vec<TrustedWriterRule> = vec!["10.20.0.5/32=10.20.0.10/32:modbus".parse().unwrap()];
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn unmatched_reports_declarations_with_no_hits() {
        let rules: Vec<TrustedWriterRule> = vec![
            "10.20.0.5=10.20.0.10:modbus".parse().unwrap(),
            "10.20.0.5=10.20.0.11:s7".parse().unwrap(),
        ];
        let matched = std::collections::BTreeSet::from([1]);
        let stale = unmatched(&rules, &matched);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].proto, WriterProto::S7);
    }
}

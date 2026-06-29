//! Minimal LLMNR parser stub (S-8.01).
//!
//! Extracts A-record (hostname, IPv4) pairs from LLMNR (UDP/5355) response
//! payloads. See BC-1.02.012 and story S-8.01 AC-003 for the behavioral
//! contract.
//!
//! Implementation: LLMNR shares the RFC 1035 DNS wire format. Check QR=1
//! (response) at bit 15 of the flags field (bytes 2–3); iterate Answer section
//! for RRTYPE=A (0x0001) RRCLASS=IN (0x0001) records; strip trailing dot from
//! owner names; reject messages containing DNS compression pointers (0xC0 byte).

use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmnrHostname {
    pub name: String,
    pub ip: Ipv4Addr,
}

/// Parse an LLMNR payload, returning all A-record (hostname, IPv4) pairs found
/// in the Answer section of response messages (QR=1). Returns an empty `Vec`
/// for queries (QR=0), malformed input, or any other unrecognized payload;
/// never panics.
pub fn parse(_payload: &[u8]) -> Vec<LlmnrHostname> {
    todo!()
}

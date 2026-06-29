//! Minimal mDNS parser stub (S-8.01).
//!
//! Extracts A-record (hostname, IPv4) pairs from mDNS (UDP/5353) payloads.
//! See BC-1.02.010 and story S-8.01 AC-001 for the behavioral contract.
//!
//! Implementation: parse DNS message format; iterate the Answer section for
//! RRTYPE=A (0x0001) RRCLASS=IN (0x0001) records; strip `.local` suffix from
//! owner names; reject messages containing DNS compression pointers (0xC0 byte).

use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsHostname {
    pub name: String,
    pub ip: Ipv4Addr,
}

/// Parse an mDNS payload, returning all A-record (hostname, IPv4) pairs found
/// in the Answer section after normalization. Returns an empty `Vec` for any
/// malformed, truncated, or unrecognized payload; never panics.
pub fn parse(_payload: &[u8]) -> Vec<MdnsHostname> {
    todo!()
}

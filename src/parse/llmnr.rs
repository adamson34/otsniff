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
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── byte-fixture helpers ──────────────────────────────────────────────────

    /// Build a 12-byte LLMNR message header.
    ///
    /// `qr_response` sets bit 15 of the flags field (`true` → response, `false`
    /// → query). All other flags bits are zero.
    fn llmnr_header(qr_response: bool, ancount: u16) -> Vec<u8> {
        let flags_hi = if qr_response { 0x80u8 } else { 0x00u8 };
        vec![
            0x00, 0x00,                                    // TxID
            flags_hi, 0x00,                                // Flags
            0x00, 0x00,                                    // QDCOUNT = 0
            (ancount >> 8) as u8, (ancount & 0xFF) as u8, // ANCOUNT
            0x00, 0x00,                                    // NSCOUNT = 0
            0x00, 0x00,                                    // ARCOUNT = 0
        ]
    }

    /// Encode DNS labels into RFC 1035 wire format (ends with 0x00).
    fn dns_name(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for &label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0x00);
        out
    }

    /// Build a DNS A-record answer wire encoding.
    fn a_record(name: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&[0x00, 0x01]); // RRTYPE = A
        out.extend_from_slice(&[0x00, 0x01]); // RRCLASS = IN
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120 s
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        out.extend_from_slice(&ip);
        out
    }

    // ── BC-1.02.012 postcondition tests ──────────────────────────────────────

    /// BC-1.02.012 postcondition: LLMNR response (QR=1) with an A record for
    /// "ENG-WS-01" resolving to 10.0.1.20 → `LlmnrHostname { name:
    /// "ENG-WS-01", ip: 10.0.1.20 }`.
    #[test]
    fn test_bc_1_02_012_response_extracts_a_record() {
        let name = dns_name(&[b"ENG-WS-01"]);
        let ans = a_record(&name, [10, 0, 1, 20]);
        let mut msg = llmnr_header(true, 1); // QR=1 (response)
        msg.extend_from_slice(&ans);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "BC-1.02.012: LLMNR response with one A record must yield one LlmnrHostname"
        );
        assert_eq!(
            results[0].name, "ENG-WS-01",
            "BC-1.02.012: owner name must be returned with trailing dot stripped"
        );
        assert_eq!(
            results[0].ip,
            Ipv4Addr::new(10, 0, 1, 20),
            "BC-1.02.012: RDATA IPv4 must match the A record RDATA"
        );
    }

    // ── BC-1.02.012 precondition / rejection tests ────────────────────────────

    /// BC-1.02.012 precondition / EC-006: LLMNR query (QR=0) → empty Vec; only
    /// responses carry A-record answers.
    #[test]
    fn test_bc_1_02_012_query_returns_empty() {
        let name = dns_name(&[b"ENG-WS-01"]);
        let ans = a_record(&name, [10, 0, 1, 20]);
        let mut msg = llmnr_header(false, 1); // QR=0 (query)
        msg.extend_from_slice(&ans);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "BC-1.02.012 EC-006: LLMNR query (QR=0) must return empty Vec"
        );
    }

    /// BC-1.02.012 precondition / EC-001: compression pointer (0xC0 byte) in
    /// the answer owner name → entire message rejected → empty Vec.
    #[test]
    fn test_bc_1_02_012_rejects_compression_pointer() {
        let mut msg = llmnr_header(true, 1);
        msg.extend_from_slice(&[
            0xC0, 0x0C, // DNS compression pointer to offset 12
            0x00, 0x01, // RRTYPE = A
            0x00, 0x01, // RRCLASS = IN
            0x00, 0x00, 0x00, 0x78, // TTL
            0x00, 0x04, // RDLENGTH
            0x0A, 0x00, 0x01, 0x14, // RDATA: 10.0.1.20
        ]);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "BC-1.02.012 EC-001: compression pointer must cause parse() to return empty Vec"
        );
    }

    /// BC-1.02.012: payload shorter than the 12-byte DNS header → empty Vec.
    #[test]
    fn test_bc_1_02_012_rejects_short_payload() {
        assert!(
            parse(&[0u8; 11]).is_empty(),
            "BC-1.02.012: 11-byte payload must return empty Vec"
        );
        assert!(
            parse(&[]).is_empty(),
            "BC-1.02.012: empty payload must return empty Vec"
        );
    }

    /// Panic policy: parse() must return safely for any input.
    #[test]
    fn test_bc_1_02_012_malformed_payload_never_panics() {
        let _ = parse(&[]);
        let _ = parse(&[0xFFu8; 65535]);
    }
}

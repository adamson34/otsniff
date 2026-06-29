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
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── byte-fixture helpers ──────────────────────────────────────────────────

    /// Build a 12-byte mDNS message header with the given ANCOUNT.
    /// Sets QR=1, AA=1 in the flags (standard mDNS announce response);
    /// QDCOUNT, NSCOUNT, ARCOUNT are all zero.
    fn dns_header(ancount: u16) -> Vec<u8> {
        vec![
            0x00, 0x00,                                   // TxID
            0x84, 0x00,                                   // Flags: QR=1, AA=1
            0x00, 0x00,                                   // QDCOUNT = 0
            (ancount >> 8) as u8, (ancount & 0xFF) as u8, // ANCOUNT
            0x00, 0x00,                                   // NSCOUNT = 0
            0x00, 0x00,                                   // ARCOUNT = 0
        ]
    }

    /// Encode a sequence of labels into RFC 1035 wire format (ends with 0x00).
    fn dns_name(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for &label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0x00); // end-of-name root label
        out
    }

    /// Build a DNS A-record wire encoding: name + TYPE=A + CLASS=IN + TTL + RDLENGTH + RDATA.
    fn a_record(name: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&[0x00, 0x01]); // RRTYPE = A (1)
        out.extend_from_slice(&[0x00, 0x01]); // RRCLASS = IN (1)
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120 s
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        out.extend_from_slice(&ip); // RDATA (IPv4)
        out
    }

    /// Assemble a full mDNS message from pre-built answer byte blobs.
    /// ANCOUNT is set automatically from `answers.len()`.
    fn build_mdns(answers: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = dns_header(answers.len() as u16);
        for a in answers {
            msg.extend_from_slice(a);
        }
        msg
    }

    // ── BC-1.02.010 postcondition tests ──────────────────────────────────────

    /// BC-1.02.010 postcondition: A record for `HMI-LINE-3.local.` resolving to
    /// `10.0.0.5` → name field is `"HMI-LINE-3"` (`.local.` suffix stripped),
    /// ip field is `10.0.0.5`.
    #[test]
    fn test_bc_1_02_010_extracts_a_record_local_dot_suffix() {
        let name = dns_name(&[b"HMI-LINE-3", b"local"]);
        let ans = a_record(&name, [10, 0, 0, 5]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "BC-1.02.010: single A record must yield exactly one MdnsHostname, got: {:?}",
            results
        );
        assert_eq!(
            results[0].name, "HMI-LINE-3",
            "BC-1.02.010: .local. suffix must be stripped from the owner name"
        );
        assert_eq!(
            results[0].ip,
            Ipv4Addr::new(10, 0, 0, 5),
            "BC-1.02.010: RDATA IPv4 must be returned verbatim"
        );
    }

    /// BC-1.02.010 / EC-005: A record with no `.local` suffix — only the
    /// trailing dot is stripped; the name is preserved as-is.
    #[test]
    fn test_bc_1_02_010_preserves_name_without_local_suffix() {
        let name = dns_name(&[b"DEVICE-01"]);
        let ans = a_record(&name, [10, 0, 0, 6]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "BC-1.02.010 EC-005: non-.local A record must still be returned (trailing dot stripped)"
        );
        assert_eq!(
            results[0].name, "DEVICE-01",
            "BC-1.02.010 EC-005: name without .local suffix must be preserved"
        );
        assert_eq!(results[0].ip, Ipv4Addr::new(10, 0, 0, 6));
    }

    /// BC-1.02.010 / EC-009: multiple A records in one mDNS message — every
    /// valid record must be returned.
    #[test]
    fn test_bc_1_02_010_multiple_a_records_extracted() {
        let name1 = dns_name(&[b"HMI-LINE-3", b"local"]);
        let name2 = dns_name(&[b"PLC-SOUTH", b"local"]);
        let ans1 = a_record(&name1, [10, 0, 0, 5]);
        let ans2 = a_record(&name2, [10, 0, 0, 7]);
        let msg = build_mdns(&[ans1, ans2]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            2,
            "BC-1.02.010 EC-009: two A records must yield two MdnsHostname entries"
        );
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(
            names.contains(&"HMI-LINE-3"),
            "must contain HMI-LINE-3; got {:?}",
            names
        );
        assert!(
            names.contains(&"PLC-SOUTH"),
            "must contain PLC-SOUTH; got {:?}",
            names
        );
    }

    // ── BC-1.02.010 precondition / rejection tests ────────────────────────────

    /// BC-1.02.010 precondition / EC-001: compression pointer (0xC0) in owner
    /// name → the entire message is rejected; returns empty Vec.
    #[test]
    fn test_bc_1_02_010_rejects_compression_pointer() {
        // Header with ANCOUNT=1, immediately followed by a compression pointer
        // at the answer name position (byte 12).
        let mut msg = dns_header(1);
        msg.extend_from_slice(&[
            0xC0, 0x0C, // DNS compression pointer to offset 12 (self-referential)
            0x00, 0x01, // RRTYPE = A
            0x00, 0x01, // RRCLASS = IN
            0x00, 0x00, 0x00, 0x78, // TTL
            0x00, 0x04, // RDLENGTH
            0x0A, 0x00, 0x00, 0x05, // RDATA: 10.0.0.5
        ]);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "BC-1.02.010 EC-001: compression pointer must cause parse() to return empty Vec"
        );
    }

    /// BC-1.02.010: payload shorter than the 12-byte DNS header → empty Vec.
    #[test]
    fn test_bc_1_02_010_rejects_short_payload() {
        assert!(
            parse(&[0u8; 11]).is_empty(),
            "BC-1.02.010: 11-byte payload (< 12-byte DNS header) must return empty Vec"
        );
    }

    /// BC-1.02.010: ANCOUNT = 0 → no answer records to iterate → empty Vec.
    #[test]
    fn test_bc_1_02_010_ancount_zero_returns_empty() {
        let msg = dns_header(0); // 12-byte header, ANCOUNT = 0
        assert!(
            parse(&msg).is_empty(),
            "BC-1.02.010: ANCOUNT=0 must return empty Vec"
        );
    }

    /// BC-1.02.010 / EC-007: owner name that normalizes to an empty string
    /// (root zone label → "." → "" after stripping trailing dot) must be
    /// discarded rather than inserted.
    #[test]
    fn test_bc_1_02_010_discards_empty_name_after_normalization() {
        // Root-zone name in DNS wire format is a single zero byte.
        // Parsed: "." → strip trailing dot → "" → discard.
        let name = vec![0x00u8];
        let ans = a_record(&name, [10, 0, 0, 9]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "BC-1.02.010 EC-007: root-zone name normalizes to empty string and must be discarded"
        );
    }

    /// Panic policy: parse() must return safely for any input — no panics.
    #[test]
    fn test_bc_1_02_010_malformed_payload_never_panics() {
        let _ = parse(&[]);
        let _ = parse(&[0xFFu8; 1500]);
    }
}

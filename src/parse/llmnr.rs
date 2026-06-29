//! Minimal LLMNR parser (S-8.01).
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
pub fn parse(payload: &[u8]) -> Vec<LlmnrHostname> {
    // DNS/LLMNR header is 12 bytes minimum.
    if payload.len() < 12 {
        return Vec::new();
    }

    // Flags at bytes 2–3 (big-endian u16).  Bit 15 is the QR bit.
    // EC-006: queries (QR=0) carry no A-record answers — return empty Vec.
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if (flags >> 15) & 1 == 0 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut pos = 12usize;

    // Skip the question section.  Each question record is:
    //   QNAME (variable) + QTYPE (2) + QCLASS (2)
    for _ in 0..qdcount {
        pos = match skip_name(payload, pos) {
            Some(p) => p,
            None => return Vec::new(),
        };
        if pos + 4 > payload.len() {
            return Vec::new();
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse the answer section.  Each resource record is:
    //   NAME (variable) + RRTYPE (2) + RRCLASS (2) + TTL (4) + RDLENGTH (2) + RDATA
    let mut results = Vec::new();
    for _ in 0..ancount {
        let (name, new_pos) = match read_name(payload, pos) {
            Some(v) => v,
            None => return Vec::new(), // compression pointer → reject whole message
        };
        pos = new_pos;

        // Need 10 bytes for the fixed RR fields.
        if pos + 10 > payload.len() {
            return Vec::new();
        }

        let rrtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rrclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
        let rdlength = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > payload.len() {
            return Vec::new();
        }

        if rrtype == 0x0001 && rrclass == 0x0001 && rdlength == 4 {
            let ip = Ipv4Addr::from([
                payload[pos],
                payload[pos + 1],
                payload[pos + 2],
                payload[pos + 3],
            ]);
            // BC-1.02.013 precondition: strip trailing dot only.
            let normalized = name.trim_end_matches('.');
            if !normalized.is_empty() {
                results.push(LlmnrHostname {
                    name: normalized.to_string(),
                    ip,
                });
            }
        }

        pos += rdlength;
    }

    results
}

/// Walk a DNS name starting at `pos`, returning the new position after the
/// name on success.  Returns `None` if a compression pointer (byte >= 0xC0)
/// is encountered or if the payload is truncated.
fn skip_name(payload: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= payload.len() {
            return None;
        }
        let len_byte = payload[pos];
        if len_byte == 0 {
            return Some(pos + 1);
        }
        if len_byte & 0xC0 == 0xC0 {
            // DNS compression pointer — BC-1.02.012 precondition: reject message.
            return None;
        }
        let label_len = (len_byte & 0x3F) as usize;
        pos = pos.checked_add(1 + label_len)?;
        if pos > payload.len() {
            return None;
        }
    }
}

/// Read a DNS name starting at `pos`, building a dotted-label string.
/// Returns `(name, new_pos)` on success or `None` if a compression pointer
/// or truncation is encountered.
fn read_name(payload: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut total_name_len = 0usize;

    loop {
        if pos >= payload.len() {
            return None;
        }
        let len_byte = payload[pos];
        if len_byte == 0 {
            return Some((labels.join("."), pos + 1));
        }
        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer — reject.
            return None;
        }
        let label_len = (len_byte & 0x3F) as usize;
        pos += 1;
        if pos + label_len > payload.len() {
            return None;
        }
        // EC-008: guard against names > 253 characters (DNS limit).
        total_name_len = total_name_len.saturating_add(label_len + 1);
        if total_name_len > 255 {
            return None;
        }
        let label = String::from_utf8_lossy(&payload[pos..pos + label_len]).into_owned();
        labels.push(label);
        pos += label_len;
    }
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
            0x00, 0x00, // TxID
            flags_hi, 0x00, // Flags
            0x00, 0x00, // QDCOUNT = 0
            (ancount >> 8) as u8, (ancount & 0xFF) as u8, // ANCOUNT
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
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

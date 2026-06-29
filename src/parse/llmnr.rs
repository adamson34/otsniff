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
            // F-101: sanitize to printable ASCII FIRST, then normalize.
            // Running sanitization after normalization allowed a crafted control
            // byte after the trailing dot to defeat dot trimming.
            let sanitized: String = name
                .bytes()
                .filter(|&b| (0x20..0x7F).contains(&b))
                .map(|b| b as char)
                .collect();
            // BC-1.02.013 precondition: strip trailing dot only.
            let normalized = sanitized.trim_end_matches('.');
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
            0x00,
            0x00, // TxID
            flags_hi,
            0x00, // Flags
            0x00,
            0x00, // QDCOUNT = 0
            (ancount >> 8) as u8,
            (ancount & 0xFF) as u8, // ANCOUNT
            0x00,
            0x00, // NSCOUNT = 0
            0x00,
            0x00, // ARCOUNT = 0
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

    // ── F-001: hostname sanitization (printable ASCII filter) ─────────────────

    /// F-001 / BC-1.02.012: an LLMNR A-record owner name containing a control
    /// byte (0x07, bell) must have that byte stripped; the remaining printable
    /// chars must be returned.
    ///
    /// Fixture: label "ENG\x07-WS-01" → after filter → "ENG-WS-01".
    #[test]
    fn test_f001_sanitize_strips_control_byte() {
        let label: &[u8] = b"ENG\x07-WS-01";
        let name = dns_name(&[label]);
        let ans = a_record(&name, [10, 0, 1, 30]);
        let mut msg = llmnr_header(true, 1);
        msg.extend_from_slice(&ans);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-001 LLMNR: name with control byte must yield one record after sanitization"
        );
        assert_eq!(
            results[0].name, "ENG-WS-01",
            "F-001 LLMNR: control byte (0x07) must be stripped; remaining chars preserved"
        );
    }

    /// F-001 / BC-1.02.012: a name consisting entirely of control bytes must
    /// be discarded (sanitizes to empty string → no record pushed).
    #[test]
    fn test_f001_sanitize_discards_all_control_byte_name() {
        let label: &[u8] = &[0x01, 0x0A, 0x1F]; // SOH, LF, US — all below 0x20
        let name = dns_name(&[label]);
        let ans = a_record(&name, [10, 0, 1, 31]);
        let mut msg = llmnr_header(true, 1);
        msg.extend_from_slice(&ans);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "F-001 LLMNR: name consisting entirely of control bytes must be discarded"
        );
    }

    // ── F-101: sanitize BEFORE normalize ─────────────────────────────────────

    /// F-101 / BC-1.02.012: a control byte that follows the trailing dot
    /// defeats dot-trimming when sanitisation runs AFTER normalisation.
    /// Labels `["DEVICE", "\x07"]` join to `"DEVICE.\x07"`.  With the wrong
    /// order, `trim_end_matches('.')` sees `\x07` as the last char so no dot is
    /// removed; sanitise then strips the control byte, leaving `"DEVICE."` in
    /// the output.  With the correct order (sanitise first), `"DEVICE.\x07"` →
    /// `"DEVICE."` → trim trailing dot → `"DEVICE"`.
    #[test]
    fn test_f101_sanitize_before_normalize_llmnr() {
        // Second label is a single BEL byte (0x07, control char below 0x20).
        let name = dns_name(&[b"DEVICE", b"\x07"]);
        let ans = a_record(&name, [10, 0, 1, 40]);
        let mut msg = llmnr_header(true, 1);
        msg.extend_from_slice(&ans);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-101 LLMNR: 'DEVICE.\\x07' must yield one record after sanitize-first normalization"
        );
        assert_eq!(
            results[0].name, "DEVICE",
            "F-101 LLMNR: control byte after trailing dot must not defeat dot trimming"
        );
    }

    // ── F-003: question-section skip path ────────────────────────────────────

    /// Build a 12-byte LLMNR header with explicit QDCOUNT and ANCOUNT.
    fn llmnr_header_qd(qr_response: bool, qdcount: u16, ancount: u16) -> Vec<u8> {
        let flags_hi = if qr_response { 0x80u8 } else { 0x00u8 };
        vec![
            0x00,
            0x00, // TxID
            flags_hi,
            0x00, // Flags
            (qdcount >> 8) as u8,
            (qdcount & 0xFF) as u8, // QDCOUNT
            (ancount >> 8) as u8,
            (ancount & 0xFF) as u8, // ANCOUNT
            0x00,
            0x00, // NSCOUNT = 0
            0x00,
            0x00, // ARCOUNT = 0
        ]
    }

    /// Build a DNS question record wire encoding (QNAME + QTYPE + QCLASS).
    fn question_record(name: &[u8]) -> Vec<u8> {
        let mut out = name.to_vec();
        out.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        out.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        out
    }

    /// F-003 / BC-1.02.012: real LLMNR responses echo the question section
    /// (QDCOUNT=1).  The question-skip loop (skip_name + 4 bytes) must advance
    /// past the question before reading the answer section.
    ///
    /// All previous fixtures used QDCOUNT=0, leaving this code path untested.
    #[test]
    fn test_f003_question_section_skipped_qdcount_1() {
        let q_name = dns_name(&[b"ENG-WS-01"]);
        let a_name = dns_name(&[b"ENG-WS-01"]);
        let question = question_record(&q_name);
        let answer = a_record(&a_name, [10, 0, 1, 20]);
        let mut msg = llmnr_header_qd(true, 1, 1);
        msg.extend_from_slice(&question);
        msg.extend_from_slice(&answer);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-003 LLMNR: QDCOUNT=1 — question section must be skipped; A record must still be extracted"
        );
        assert_eq!(
            results[0].name, "ENG-WS-01",
            "F-003 LLMNR: owner name must be correctly extracted after skipping the question section"
        );
        assert_eq!(
            results[0].ip,
            std::net::Ipv4Addr::new(10, 0, 1, 20),
            "F-003 LLMNR: RDATA IPv4 must be correct after skipping question section"
        );
    }
}

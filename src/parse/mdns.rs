//! Minimal mDNS parser (S-8.01).
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
pub fn parse(payload: &[u8]) -> Vec<MdnsHostname> {
    // DNS header is 12 bytes minimum.
    if payload.len() < 12 {
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

        // Need 10 bytes for the fixed RR fields that follow the name.
        if pos + 10 > payload.len() {
            return Vec::new();
        }

        let rrtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        // Mask off the mDNS cache-flush bit (top bit of the class field).
        let rrclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) & 0x7FFF;
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
            // BC-1.02.013 precondition: strip `.local` suffix (case-insensitive),
            // then any trailing dot.
            const LOCAL_SUFFIX: &str = ".local";
            let stripped = if name.to_ascii_lowercase().ends_with(LOCAL_SUFFIX) {
                &name[..name.len() - LOCAL_SUFFIX.len()]
            } else {
                &name
            };
            let normalized = stripped.trim_end_matches('.');
            // F-001: sanitize to printable ASCII (mirror dhcp.rs) before the
            // empty-check, so control bytes / NULs do not survive into reports.
            let sanitized: String = normalized
                .bytes()
                .filter(|&b| (0x20..0x7F).contains(&b))
                .map(|b| b as char)
                .collect();
            if !sanitized.is_empty() {
                results.push(MdnsHostname {
                    name: sanitized,
                    ip,
                });
            }
        }

        pos += rdlength;
    }

    results
}

/// Walk a DNS name starting at `pos`, returning the new position after the
/// name on success.  Returns `None` if a compression pointer (top 2 bits ==
/// 0b11, i.e. byte >= 0xC0) is encountered or if the payload is truncated.
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
            // DNS compression pointer — BC-1.02.010 precondition: reject message.
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
/// or truncation is encountered.  The root label (0x00) terminates the name
/// without contributing a label; labels are joined with `.`.
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

    /// Build a 12-byte mDNS message header with the given ANCOUNT.
    /// Sets QR=1, AA=1 in the flags (standard mDNS announce response);
    /// QDCOUNT, NSCOUNT, ARCOUNT are all zero.
    fn dns_header(ancount: u16) -> Vec<u8> {
        vec![
            0x00,
            0x00, // TxID
            0x84,
            0x00, // Flags: QR=1, AA=1
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

    // ── F-003: question-section skip path ────────────────────────────────────

    /// Build a 12-byte mDNS header with explicit QDCOUNT and ANCOUNT.
    fn dns_header_qd(qdcount: u16, ancount: u16) -> Vec<u8> {
        vec![
            0x00,
            0x00, // TxID
            0x84,
            0x00, // Flags: QR=1, AA=1
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

    /// F-003 / BC-1.02.010: when QDCOUNT=1, the question record (QNAME +
    /// QTYPE + QCLASS) must be skipped before parsing the answer section.
    ///
    /// The question-skip loop (skip_name + 4 bytes) in mdns.rs was untested
    /// because all existing fixtures use QDCOUNT=0.  Real mDNS query/response
    /// messages may echo a question section.
    #[test]
    fn test_f003_question_section_skipped_qdcount_1() {
        let q_name = dns_name(&[b"HMI-LINE-3", b"local"]);
        let a_name = dns_name(&[b"HMI-LINE-3", b"local"]);
        let question = question_record(&q_name);
        let answer = a_record(&a_name, [10, 0, 0, 5]);
        let mut msg = dns_header_qd(1, 1);
        msg.extend_from_slice(&question);
        msg.extend_from_slice(&answer);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-003 mDNS: QDCOUNT=1 — question section must be skipped; A record must still be extracted"
        );
        assert_eq!(
            results[0].name, "HMI-LINE-3",
            "F-003 mDNS: owner name must be correctly extracted after skipping the question section"
        );
        assert_eq!(
            results[0].ip,
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            "F-003 mDNS: RDATA IPv4 must be correct after skipping question section"
        );
    }

    // ── F-002: mDNS cache-flush bit (RRCLASS & 0x7FFF) ───────────────────────

    /// F-002 / BC-1.02.010 / mdns.rs:62: the cache-flush bit (bit 15 of the
    /// class field) must be masked off before comparing to IN (0x0001).
    ///
    /// A real mDNS A record announcing on the local network uses RRCLASS=0x8001
    /// (cache-flush bit set + class IN).  Without the `& 0x7FFF` mask the class
    /// comparison fails and the record is silently dropped.
    ///
    /// This test adds no code — it guards the existing mask against regression.
    #[test]
    fn test_f002_cache_flush_bit_masked_off() {
        // Build a fixture whose RRCLASS bytes are 0x80, 0x01 (cache-flush set).
        let name = dns_name(&[b"PLCSOUTH", b"local"]);
        let mut ans = name.clone();
        ans.extend_from_slice(&[0x00, 0x01]); // RRTYPE = A
        ans.extend_from_slice(&[0x80, 0x01]); // RRCLASS = 0x8001 (cache-flush + IN)
        ans.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL = 120 s
        ans.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        ans.extend_from_slice(&[10, 0, 0, 7]); // RDATA
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-002: RRCLASS=0x8001 (cache-flush bit set) must still be treated as IN; record must be extracted"
        );
        assert_eq!(
            results[0].name, "PLCSOUTH",
            "F-002: owner name must be extracted when cache-flush bit is present"
        );
        assert_eq!(
            results[0].ip,
            std::net::Ipv4Addr::new(10, 0, 0, 7),
            "F-002: RDATA IPv4 must match the record RDATA"
        );
    }

    // ── F-006: case-insensitive .local strip ─────────────────────────────────

    /// F-006 / BC-1.02.010: `.local` suffix stripping must be case-insensitive.
    ///
    /// A name "FOO.LOCAL" must be normalized to "FOO", not returned verbatim.
    #[test]
    fn test_f006_case_insensitive_local_strip() {
        // Build dns_name with uppercase "LOCAL" label.
        let name = dns_name(&[b"FOO", b"LOCAL"]);
        let ans = a_record(&name, [10, 0, 0, 30]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-006: 'FOO.LOCAL' must yield one record after case-insensitive .local strip"
        );
        assert_eq!(
            results[0].name, "FOO",
            "F-006: '.LOCAL' suffix must be stripped case-insensitively; expected 'FOO'"
        );
    }

    // ── F-001: hostname sanitization (printable ASCII filter) ─────────────────

    /// F-001 / BC-1.02.010: a label containing an embedded NUL byte (0x00)
    /// must have that byte stripped.  The remaining printable chars must be
    /// returned; the name must not contain 0x00.
    ///
    /// Fixture: single-label "HMI\x00-3" → after filter → "HMI-3".
    #[test]
    fn test_f001_sanitize_strips_embedded_nul() {
        // Encode the label bytes directly — note dns_name uses the slice len as
        // the length prefix, so the NUL is part of the label payload.
        let label: &[u8] = b"HMI\x00-3";
        let name = dns_name(&[label]);
        let ans = a_record(&name, [10, 0, 0, 20]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert_eq!(
            results.len(),
            1,
            "F-001 mDNS: name with embedded NUL must yield one record after sanitization"
        );
        assert_eq!(
            results[0].name, "HMI-3",
            "F-001 mDNS: embedded NUL (0x00) must be stripped; remaining chars preserved"
        );
    }

    /// F-001 / BC-1.02.010: a name consisting entirely of control bytes must be
    /// discarded (sanitizes to empty string).
    ///
    /// Fixture: label is [0x01, 0x07, 0x1F] (all below 0x20) → sanitized to "" → discarded.
    #[test]
    fn test_f001_sanitize_discards_all_control_byte_name() {
        let label: &[u8] = &[0x01, 0x07, 0x1F];
        let name = dns_name(&[label]);
        let ans = a_record(&name, [10, 0, 0, 21]);
        let msg = build_mdns(&[ans]);
        let results = parse(&msg);
        assert!(
            results.is_empty(),
            "F-001 mDNS: name consisting entirely of control bytes must be discarded (sanitizes to empty)"
        );
    }
}

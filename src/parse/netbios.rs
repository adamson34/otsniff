//! Minimal NetBIOS Name Service parser stub (S-8.01).
//!
//! Extracts the workstation name from NBNS Registration Requests (UDP/137).
//! See BC-1.02.011 and story S-8.01 AC-002 for the behavioral contract.
//!
//! Implementation: check QR=0 and OPCODE=5 (Name Registration) in the 16-bit
//! flags field at bytes 2–3; read the 32-byte first-level-encoded QNAME label
//! starting at byte 12; decode via ((H-'A')<<4)|(L-'A'); trim trailing 0x20
//! bytes and drop the 16th (suffix) byte.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetBiosHostname {
    pub name: String,
}

/// Parse a NetBIOS-NS payload as an NBNS Registration Request and return the
/// decoded workstation name. Returns `None` for any non-registration payload,
/// malformed input, or empty decoded name; never panics.
pub fn parse_registration(_payload: &[u8]) -> Option<NetBiosHostname> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── byte-fixture helpers ──────────────────────────────────────────────────

    /// First-level encode 16 decoded bytes into the 32-byte NBNS wire encoding.
    /// For each byte b: out[2i] = (b >> 4) + 'A', out[2i+1] = (b & 0xF) + 'A'.
    fn nbns_encode(decoded: &[u8; 16]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &b) in decoded.iter().enumerate() {
            out[2 * i]     = ((b >> 4) & 0xF) + b'A';
            out[2 * i + 1] = (b & 0xF)        + b'A';
        }
        out
    }

    /// Build a minimal NBNS Registration Request packet.
    ///
    /// `flags_hi` / `flags_lo` are bytes 2–3 of the packet (the flags field).
    /// `label_len` is the QNAME first-byte label length (must be 32 for a valid
    /// first-level encoded name).
    /// `encoded` is the raw bytes placed after the label length byte; the caller
    /// controls the length so tests can inject truncated or wrong-size payloads.
    fn make_nbns_reg(flags_hi: u8, flags_lo: u8, label_len: u8, encoded: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]); // TxID
        buf.push(flags_hi);
        buf.push(flags_lo);
        buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        buf.push(label_len);                  // QNAME label length (byte 12)
        buf.extend_from_slice(encoded);        // encoded name bytes
        buf.push(0x00);                        // end of QNAME
        buf.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]); // QTYPE=NB, QCLASS=IN
        buf
    }

    /// Produce the NBNS flags for QR=0 (query), OPCODE=5 (Name Registration).
    /// Binary: 0_0101_000_0000_0000 = 0x2800 big-endian.
    fn reg_flags() -> (u8, u8) {
        (0x28, 0x00)
    }

    // ── BC-1.02.011 postcondition tests ──────────────────────────────────────

    /// BC-1.02.011 postcondition: valid NBNS Registration Request for
    /// "PLC-LINE3" → `Some(NetBiosHostname { name: "PLC-LINE3" })`.
    ///
    /// Wire name: "PLC-LINE3" padded with spaces (0x20) to 15 bytes, suffix byte 0x00;
    /// first-level encoded to 32 bytes; embedded at QNAME byte 12.
    #[test]
    fn test_bc_1_02_011_valid_registration_returns_hostname() {
        // Decoded 16-byte name: "PLC-LINE3" + six 0x20 spaces + 0x00 suffix.
        let mut decoded = [0x20u8; 16];
        decoded[15] = 0x00; // suffix byte (dropped, not part of name)
        decoded[..9].copy_from_slice(b"PLC-LINE3");

        let encoded = nbns_encode(&decoded);
        let (fh, fl) = reg_flags();
        let pkt = make_nbns_reg(fh, fl, 32, &encoded);
        let result = parse_registration(&pkt);
        assert!(
            result.is_some(),
            "BC-1.02.011: valid NBNS registration must return Some(NetBiosHostname)"
        );
        assert_eq!(
            result.unwrap().name,
            "PLC-LINE3",
            "BC-1.02.011: decoded name must have trailing spaces trimmed and suffix byte dropped"
        );
    }

    // ── BC-1.02.011 precondition / rejection tests ────────────────────────────

    /// BC-1.02.011 / EC-003: decoded name consists entirely of 0x20 (space)
    /// bytes → all 15 name bytes are spaces → empty after trim → None.
    #[test]
    fn test_bc_1_02_011_all_spaces_name_returns_none() {
        let decoded = [0x20u8; 16]; // all spaces (including suffix position)
        let encoded = nbns_encode(&decoded);
        let (fh, fl) = reg_flags();
        let pkt = make_nbns_reg(fh, fl, 32, &encoded);
        let result = parse_registration(&pkt);
        assert!(
            result.is_none(),
            "BC-1.02.011 EC-003: all-spaces decoded name must return None"
        );
    }

    /// BC-1.02.011 precondition: QR=0 is required, but OPCODE must be 5
    /// (Name Registration). OPCODE=0 (Name Query) → None.
    #[test]
    fn test_bc_1_02_011_wrong_opcode_returns_none() {
        let mut decoded = [0x20u8; 16];
        decoded[15] = 0x00;
        decoded[..6].copy_from_slice(b"ENG-WS");
        let encoded = nbns_encode(&decoded);
        // Flags: QR=0, OPCODE=0 (Name Query) → flags = 0x0000
        let pkt = make_nbns_reg(0x00, 0x00, 32, &encoded);
        let result = parse_registration(&pkt);
        assert!(
            result.is_none(),
            "BC-1.02.011: OPCODE=0 (Name Query) must return None; only OPCODE=5 is accepted"
        );
    }

    /// BC-1.02.011 precondition: minimum payload is 13 bytes (12-byte header +
    /// 1-byte label length). A 12-byte payload is too short → None.
    #[test]
    fn test_bc_1_02_011_truncated_payload_returns_none() {
        assert!(
            parse_registration(&[0u8; 12]).is_none(),
            "BC-1.02.011: 12-byte payload (< 13-byte minimum) must return None"
        );
        assert!(
            parse_registration(&[]).is_none(),
            "BC-1.02.011: empty payload must return None"
        );
    }

    /// BC-1.02.011 / EC-004: any encoding byte outside the A–P alphabet
    /// (0x41–0x50) → None.
    #[test]
    fn test_bc_1_02_011_invalid_encoding_byte_returns_none() {
        let decoded = [0x20u8; 16]; // spaces, produces valid 'C','A' pairs
        let mut encoded = nbns_encode(&decoded);
        // Corrupt the very first encoded byte to 0x51 = 'Q' (one past 'P' = 0x50).
        encoded[0] = 0x51;
        let (fh, fl) = reg_flags();
        let pkt = make_nbns_reg(fh, fl, 32, &encoded);
        let result = parse_registration(&pkt);
        assert!(
            result.is_none(),
            "BC-1.02.011 EC-004: encoded byte 0x51 ('Q') is outside A–P and must return None"
        );
    }

    /// BC-1.02.011 / EC-002: QNAME label length ≠ 32 (not first-level encoded)
    /// → None.
    #[test]
    fn test_bc_1_02_011_wrong_label_length_returns_none() {
        // Produce a packet whose QNAME label byte (byte 12) is 16, not 32.
        let encoded_half = [b'A'; 16]; // 16 valid bytes — length is wrong
        let (fh, fl) = reg_flags();
        let pkt = make_nbns_reg(fh, fl, 16, &encoded_half);
        let result = parse_registration(&pkt);
        assert!(
            result.is_none(),
            "BC-1.02.011 EC-002: label length 16 (not 32) must return None"
        );
    }

    /// Panic policy: parse_registration() must return safely for any input.
    #[test]
    fn test_bc_1_02_011_malformed_payload_never_panics() {
        let _ = parse_registration(&[]);
        let _ = parse_registration(&[0xFFu8; 1500]);
    }
}

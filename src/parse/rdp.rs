//! S-2.08: Minimal RDP connection-confirm recognizer.
//!
//! Recognises the X.224 Connection Confirm PDU (TPKT version 3, X.224 PDU
//! type 0xD0) on tcp/3389 so the `rdp_legacy` finding can flag connections
//! negotiated without Network Level Authentication (NLA).
//!
//! The `RDP_NEG_RSP` block (if present) is decoded to read `selectedProtocol`.
//! When `selectedProtocol & 0x01 == 0` the connection uses raw RDP (no SSL /
//! HYBRID / HYBRID_EX) — see S-2.08 AC-002 (BC-3.04.006).

/// The standard RDP port. The recogniser only fires on this port; the caller
/// (observe.rs) decides whether to invoke recognition.
pub const PORT: u16 = 3389;

/// Result of recognising an X.224 Connection Confirm PDU with an `RDP_NEG_RSP`
/// extension block.
///
/// `selected_protocol` contains the value of the `selectedProtocol` field from
/// the `RDP_NEG_RSP` block:
/// - `0x00000000` — PROTOCOL_RDP (no NLA, no SSL)
/// - `0x00000001` — PROTOCOL_SSL (TLS)
/// - `0x00000002` — PROTOCOL_HYBRID (CredSSP/NLA)
/// - `0x00000004` — PROTOCOL_HYBRID_EX (CredSSP + early user auth)
///
/// When `selected_protocol & 0x01 == 0` the connection was negotiated without
/// any TLS or NLA hardening — see EC-001 for the failure-response case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpNegRecognized {
    pub selected_protocol: u32,
}

/// Attempt to recognise an X.224 Connection Confirm PDU in a raw TCP payload.
///
/// Returns `Some(RdpNegRecognized)` when:
/// - The payload starts with a valid TPKT header (version 3, length matches
///   the actual payload length — EC-002).
/// - The X.224 PDU type byte is `0xD0` (Connection Confirm).
/// - An `RDP_NEG_RSP` block (type `0x02`) follows the X.224 header and can
///   be decoded to yield a 4-byte `selectedProtocol` value.
///
/// Returns `None` for:
/// - Any payload that is not a recognisable X.224 Connection Confirm
/// - TPKT length mismatch (EC-002)
/// - Missing or non-`RDP_NEG_RSP` negotiation block (EC-001 — failure response
///   has type `0x03`; treat as inconclusive, do not fire)
/// - Payload shorter than the minimum required structure
pub fn recognize_connection_confirm(payload: &[u8]) -> Option<RdpNegRecognized> {
    // Minimum: TPKT(4) + X.224 CC(7) + RDP_NEG_RSP(8) = 19 bytes.
    if payload.len() < 19 {
        return None;
    }

    // TPKT header: version must be 3, reserved must be 0.
    if payload[0] != 0x03 || payload[1] != 0x00 {
        return None;
    }

    // EC-002: TPKT declared length must match actual payload length.
    let tpkt_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if tpkt_len != payload.len() {
        return None;
    }

    // X.224 PDU type at offset 5: upper nibble must be 0xD (Connection Confirm).
    // Lower nibble is CDT (credit); accept any value.
    if payload[5] & 0xF0 != 0xD0 {
        return None;
    }

    // RDP_NEG_RSP type at offset 11 must be 0x02 (TYPE_RDP_NEG_RSP).
    // Type 0x03 is RDP_NEG_FAILURE — treat as inconclusive (EC-001).
    if payload[11] != 0x02 {
        return None;
    }

    // selectedProtocol is a little-endian u32 at offset 15.
    let sp = u32::from_le_bytes([payload[15], payload[16], payload[17], payload[18]]);

    Some(RdpNegRecognized {
        selected_protocol: sp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Helper: build a minimal TPKT + X.224 Connection Confirm + RDP_NEG_RSP.
    //
    // Layout (from the story spec):
    //   [0]     TPKT version = 3
    //   [1]     reserved = 0
    //   [2..4]  TPKT length (big-endian u16; total packet byte count)
    //   [4]     X.224 LI = length of X.224 header *after* this byte
    //   [5]     X.224 PDU type = 0xD0 (Connection Confirm; upper nibble 0xD)
    //   [6..8]  DST-REF (2 bytes, big-endian)
    //   [8..10] SRC-REF (2 bytes, big-endian)
    //   [10]    class/options = 0x00
    //   [11]    RDP_NEG_RSP type = 0x02
    //   [12]    RDP_NEG_RSP flags (any)
    //   [13..15] RDP_NEG_RSP length (little-endian u16; value 8)
    //   [15..19] selectedProtocol (little-endian u32)
    //
    // Total: 19 bytes.
    // -------------------------------------------------------------------------

    /// Build a complete TPKT/X.224 CC + RDP_NEG_RSP byte vector with the given
    /// `selected_protocol` value.
    fn build_x224_cc(selected_protocol: u32) -> Vec<u8> {
        let total_len: u16 = 19;
        // X.224 LI: number of bytes after the LI byte itself, up to and
        // including the class/options byte = 6 (PDU type + dst_ref[2] +
        // src_ref[2] + class). The RDP_NEG_RSP is not counted in LI.
        let x224_li: u8 = 6;
        let mut buf = vec![
            // TPKT header (4 bytes)
            0x03, // version
            0x00, // reserved
            (total_len >> 8) as u8,
            (total_len & 0xFF) as u8,
            // X.224 Connection Confirm (7 bytes: LI + PDU + DST_REF + SRC_REF + class)
            x224_li,
            0xD0, // PDU type: Connection Confirm
            0x00,
            0x00, // DST-REF
            0x00,
            0x01, // SRC-REF
            0x00, // class/options
        ];
        // RDP_NEG_RSP (8 bytes at offset 11)
        buf.push(0x02); // type = TYPE_RDP_NEG_RSP
        buf.push(0x00); // flags
        buf.push(0x08); // length lo (LE u16 = 8)
        buf.push(0x00); // length hi
                        // selectedProtocol (4 bytes, little-endian)
        buf.extend_from_slice(&selected_protocol.to_le_bytes());
        buf
    }

    /// Build a TPKT/X.224 CC *without* any negotiation block (EC-001).
    fn build_x224_cc_no_neg_rsp() -> Vec<u8> {
        // 11 bytes: TPKT(4) + X.224(7)
        let total_len: u16 = 11;
        vec![
            0x03,
            0x00,
            (total_len >> 8) as u8,
            (total_len & 0xFF) as u8,
            6,    // LI
            0xD0, // Connection Confirm
            0x00,
            0x00, // DST-REF
            0x00,
            0x01, // SRC-REF
            0x00, // class/options
        ]
    }

    // -------------------------------------------------------------------------
    // BC-1.04.004: recognizes X.224 CC with RDP_NEG_RSP — positive cases
    // -------------------------------------------------------------------------

    /// BC-1.04.004: PROTOCOL_RDP (selectedProtocol = 0x00000000) must parse to
    /// `Some(RdpNegRecognized { selected_protocol: 0 })`.
    #[test]
    fn test_bc_1_04_004_recognizes_x224_cc_with_neg_rsp_protocol_rdp() {
        let payload = build_x224_cc(0x00000000);
        let result = recognize_connection_confirm(&payload);
        assert_eq!(
            result,
            Some(RdpNegRecognized {
                selected_protocol: 0
            }),
            "PROTOCOL_RDP (0x00) must be recognised as selectedProtocol=0"
        );
    }

    /// BC-1.04.004: PROTOCOL_SSL (selectedProtocol = 0x00000001) must parse to
    /// `Some(RdpNegRecognized { selected_protocol: 1 })`.
    #[test]
    fn test_bc_1_04_004_recognizes_neg_rsp_protocol_ssl() {
        let payload = build_x224_cc(0x00000001);
        let result = recognize_connection_confirm(&payload);
        assert_eq!(
            result,
            Some(RdpNegRecognized {
                selected_protocol: 1
            }),
            "PROTOCOL_SSL (0x01) must be recognised as selectedProtocol=1"
        );
    }

    /// BC-1.04.004: PROTOCOL_HYBRID (selectedProtocol = 0x00000002, CredSSP/NLA)
    /// must parse to `Some(RdpNegRecognized { selected_protocol: 2 })`.
    #[test]
    fn test_bc_1_04_004_recognizes_neg_rsp_protocol_hybrid() {
        let payload = build_x224_cc(0x00000002);
        let result = recognize_connection_confirm(&payload);
        assert_eq!(
            result,
            Some(RdpNegRecognized {
                selected_protocol: 2
            }),
            "PROTOCOL_HYBRID (0x02) must be recognised as selectedProtocol=2"
        );
    }

    // -------------------------------------------------------------------------
    // BC-1.04.004 edge cases
    // -------------------------------------------------------------------------

    /// EC-001: X.224 CC without a RDP_NEG_RSP block must return `None`.
    /// The connection may have used a failure-response or a raw RDP handshake
    /// without negotiation; treat as inconclusive.
    #[test]
    fn test_bc_1_04_004_returns_none_without_neg_rsp() {
        let payload = build_x224_cc_no_neg_rsp();
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "EC-001: CC without RDP_NEG_RSP must return None (got {:?})",
            result
        );
    }

    /// EC-002: TPKT declared length larger than actual buffer must return `None`.
    #[test]
    fn test_bc_1_04_004_rejects_tpkt_length_mismatch() {
        let mut payload = build_x224_cc(0x00000000);
        // Lie: claim the packet is 100 bytes even though the buffer is only 19.
        payload[2] = 0x00;
        payload[3] = 0x64; // declared length = 100
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "EC-002: TPKT length mismatch must return None (got {:?})",
            result
        );
    }

    /// Non-CC PDU type (0xE0 = Connection Request) must return `None`.
    #[test]
    fn test_bc_1_04_004_rejects_non_cc_pdu() {
        let mut payload = build_x224_cc(0x00000000);
        // Replace the X.224 PDU type byte (offset 5) with Connection Request.
        payload[5] = 0xE0;
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "non-CC PDU type 0xE0 (Connection Request) must return None (got {:?})",
            result
        );
    }

    /// Arbitrary random bytes must return `None` (no panic).
    #[test]
    fn test_bc_1_04_004_rejects_random_bytes() {
        let garbage: &[u8] = &[0x00, 0xFF, 0xAB, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let result = recognize_connection_confirm(garbage);
        assert!(
            result.is_none(),
            "random bytes must return None (got {:?})",
            result
        );
    }

    // ── Group C: targeted mutant-killing tests ────────────────────────────────

    // ── Line 54: `payload[0] != 0x03 || payload[1] != 0x00` ─────────────────
    //
    // The condition rejects the payload when EITHER byte is wrong.
    // A `||` → `&&` mutant would only reject when BOTH bytes are wrong,
    // allowing payloads that have the wrong version (payload[0] != 0x03)
    // but the correct reserved byte, or vice versa.
    //
    // Test: valid reserved byte (0x00) but wrong TPKT version (not 0x03).
    // Original: || triggers → None.  Mutant (&&): one branch false → Some.

    /// TPKT version 0x04 with correct reserved byte 0x00 must return None.
    /// Kills the `||` → `&&` mutant on line 54.
    #[test]
    fn test_rdp_line54_wrong_version_correct_reserved_is_rejected() {
        let mut payload = build_x224_cc(0x00000000);
        payload[0] = 0x04; // wrong TPKT version; payload[1] stays 0x00
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "TPKT version 0x04 must be rejected even when reserved byte is correct (got {:?})",
            result
        );
    }

    /// Correct TPKT version 0x03 with wrong reserved byte 0x01 must return None.
    /// Kills the `||` → `&&` mutant on line 54 from the other branch.
    #[test]
    fn test_rdp_line54_correct_version_wrong_reserved_is_rejected() {
        let mut payload = build_x224_cc(0x00000000);
        // payload[0] stays 0x03 (correct version)
        payload[1] = 0x01; // reserved byte must be 0x00; 0x01 must be rejected
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "reserved byte 0x01 must be rejected even when version is correct (got {:?})",
            result
        );
    }

    // ── Line 66: `payload[5] & 0xF0 != 0xD0` ────────────────────────────────
    //
    // The upper nibble of payload[5] must be 0xD (Connection Confirm).
    // A `&` → `|` mutant would change the bitmask operation so that
    // bytes with the wrong upper nibble could still match.
    // A `&` → `^` mutant similarly.
    //
    // Strategy: use a PDU type byte whose upper nibble is NOT 0xD but whose
    // full byte OR or XOR with 0xF0 might still equal 0xD0.
    //
    // payload[5] = 0xE0: upper nibble = 0xE ≠ 0xD.
    //   0xE0 & 0xF0 = 0xE0 ≠ 0xD0 → None (correct).
    //   0xE0 | 0xF0 = 0xF0 ≠ 0xD0 → None (same result — doesn't distinguish).
    //   0xE0 ^ 0xF0 = 0x10 ≠ 0xD0 → None.
    //
    // payload[5] = 0xDF: upper nibble = 0xD, lower nibble = 0xF.
    //   0xDF & 0xF0 = 0xD0 == 0xD0 → Some (correct — CDT may be any value).
    //   0xDF | 0xF0 = 0xFF ≠ 0xD0 → None (wrong).
    //   0xDF ^ 0xF0 = 0x2F ≠ 0xD0 → None (wrong).
    //
    // The second case distinguishes `&` from `|` and `^`.

    /// PDU type 0xDF (upper nibble 0xD, lower nibble 0xF) must be accepted.
    /// Any lower-nibble (CDT) value is permitted; only the upper nibble matters.
    /// Kills `&` → `|` and `&` → `^` mutants on line 66.
    #[test]
    fn test_rdp_line66_connection_confirm_with_nonzero_cdt_is_accepted() {
        let mut payload = build_x224_cc(0x00000002);
        payload[5] = 0xDF; // upper nibble 0xD = CC; lower nibble 0xF = CDT field
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_some(),
            "PDU type 0xDF (CC with CDT=0xF) must be accepted by the & mask check (got {:?})",
            result
        );
        assert_eq!(
            result.unwrap().selected_protocol,
            2,
            "selectedProtocol must be decoded correctly even with CDT bits set"
        );
    }

    /// PDU type 0xC0 (upper nibble 0xC — not Connection Confirm) must be rejected.
    /// Kills `&` → `|` mutant: 0xC0 | 0xF0 = 0xF0 ≠ 0xD0, so still None.
    /// But 0xC0 & 0xF0 = 0xC0 ≠ 0xD0, original also None — this confirms
    /// the mask behaviour for a near-miss nibble.
    #[test]
    fn test_rdp_line66_wrong_upper_nibble_c_is_rejected() {
        let mut payload = build_x224_cc(0x00000000);
        payload[5] = 0xC0; // upper nibble 0xC — CR-like; not a CC
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "PDU type 0xC0 must be rejected (upper nibble is not 0xD) (got {:?})",
            result
        );
    }

    // ── Line 72: `payload[11] != 0x02` ───────────────────────────────────────
    //
    // Only RDP_NEG_RSP (type 0x02) is accepted. Type 0x03 is RDP_NEG_FAILURE.
    // A `!=` → `==` mutant would invert the check:
    //   Original: reject when type ≠ 0x02 (i.e., accept only 0x02).
    //   Mutant:   reject when type == 0x02 (i.e., accept everything EXCEPT 0x02).
    //
    // Two tests: one where type=0x02 is accepted, one where type=0x03 is rejected.

    /// RDP_NEG_RSP type 0x02 must be accepted.
    /// Kills `!=` → `==` mutant on line 72 (mutant would reject 0x02 → None).
    #[test]
    fn test_rdp_line72_neg_rsp_type_0x02_is_accepted() {
        let payload = build_x224_cc(0x00000001); // type byte at [11] is 0x02 by construction
        assert_eq!(payload[11], 0x02, "sanity: build_x224_cc must set type=0x02");
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_some(),
            "RDP_NEG_RSP type 0x02 must be accepted (got {:?})",
            result
        );
    }

    /// RDP_NEG_FAILURE type 0x03 must be rejected (treated as inconclusive).
    /// Also kills the `!=` → `==` mutant: mutant would accept 0x03 → Some.
    #[test]
    fn test_rdp_line72_neg_failure_type_0x03_is_rejected() {
        let mut payload = build_x224_cc(0x00000000);
        payload[11] = 0x03; // RDP_NEG_FAILURE — EC-001
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "RDP_NEG_FAILURE (type 0x03) must return None (got {:?})",
            result
        );
    }

    /// RDP_NEG_REQ type 0x01 (request, not response) must also be rejected.
    #[test]
    fn test_rdp_line72_neg_req_type_0x01_is_rejected() {
        let mut payload = build_x224_cc(0x00000000);
        payload[11] = 0x01; // RDP_NEG_REQ — not a response
        let result = recognize_connection_confirm(&payload);
        assert!(
            result.is_none(),
            "RDP_NEG_REQ (type 0x01) must return None (got {:?})",
            result
        );
    }

    // -------------------------------------------------------------------------
    // BC-1.04.004: observer-level integration (Observer::observe via Packet)
    // -------------------------------------------------------------------------

    /// BC-1.04.004: a TCP packet to dst_port 3389 carrying a valid X.224 CC +
    /// RDP_NEG_RSP (selectedProtocol=0) must produce exactly one RdpEvent with
    /// `selected_protocol == 0` and `dst_port == 3389`.
    #[test]
    fn test_bc_1_04_004_ingests_rdp_cc_on_port_3389() {
        use crate::observe::Observer;
        use crate::pcap::{Packet, Transport};
        use chrono::{TimeZone, Utc};

        let ts = Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap();
        let ot_subnet: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let mut observer = Observer::new(vec![ot_subnet]);

        let pkt = Packet {
            ts,
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port: 3389,
            payload: build_x224_cc(0x00000000),
        };

        observer.observe(&pkt);
        let obs = observer.observations();

        assert_eq!(
            obs.rdp_events.len(),
            1,
            "observer must append exactly one RdpEvent for tcp/3389 CC with RDP_NEG_RSP"
        );
        assert_eq!(
            obs.rdp_events[0].selected_protocol, 0,
            "RdpEvent.selected_protocol must be 0 (PROTOCOL_RDP)"
        );
        assert_eq!(
            obs.rdp_events[0].dst_port, 3389,
            "RdpEvent.dst_port must be 3389"
        );
    }

    /// EC-003: the same X.224 CC payload on dst_port 80 (not 3389) must NOT
    /// produce any RdpEvent.
    #[test]
    fn test_bc_1_04_004_ignores_rdp_on_wrong_port() {
        use crate::observe::Observer;
        use crate::pcap::{Packet, Transport};
        use chrono::{TimeZone, Utc};

        let ts = Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap();
        let ot_subnet: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let mut observer = Observer::new(vec![ot_subnet]);

        let pkt = Packet {
            ts,
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            transport: Transport::Tcp,
            src_port: 54321,
            dst_port: 80, // wrong port — must not fire
            payload: build_x224_cc(0x00000000),
        };

        observer.observe(&pkt);
        let obs = observer.observations();

        assert_eq!(
            obs.rdp_events.len(),
            0,
            "EC-003: X.224 CC payload on port 80 must not produce any RdpEvent"
        );
    }
}

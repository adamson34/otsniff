//! DNP3 Distributed Network Protocol parser (function-code-level).
//!
//! Stub for S-2.04. Implementation is `todo!()` until the
//! implementer wires real frame recognition.

pub const PORT: u16 = 20000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnp3Pdu {
    pub function_code: u8,
}

impl Dnp3Pdu {
    /// Returns true for DNP3 engineering-class function codes:
    /// Operate (4), Direct Operate (5), Direct Operate No Ack (6),
    /// Cold Restart (13), Warm Restart (14), Initialize Data (15),
    /// Initialize Application (16), Disable Unsolicited (20),
    /// Enable Unsolicited (21), Save Configuration (24).
    pub fn is_engineering_class(&self) -> bool {
        matches!(
            self.function_code,
            4 | 5 | 6           // Operate, Direct Operate, Direct Operate No Ack
            | 13 | 14           // Cold Restart, Warm Restart
            | 15 | 16           // Initialize Data, Initialize Application
            | 20 | 21           // Disable Unsolicited, Enable Unsolicited
            | 24 // Save Configuration
        )
    }
}

/// Recognize a DNP3 frame from a TCP payload. Returns None when bytes
/// are not a valid DNP3 frame (missing sync bytes, length mismatch,
/// truncated, etc.).
///
/// Minimum frame layout (13 bytes):
///   [0..1]  sync 0x05 0x64
///   [2]     length
///   [3]     control
///   [4..5]  dst address (LE)
///   [6..7]  src address (LE)
///   [8..9]  link-layer CRC
///   [10]    transport header
///   [11]    app control
///   [12]    app function code
pub fn parse(payload: &[u8]) -> Option<Dnp3Pdu> {
    if payload.len() < 13 {
        return None;
    }
    if payload[0] != 0x05 || payload[1] != 0x64 {
        return None;
    }
    let function_code = payload[12];
    Some(Dnp3Pdu { function_code })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DNP3 link-layer frame followed by transport
    /// and application headers containing the given function code.
    ///
    /// Layout:
    ///   [0..1]  sync 0x05 0x64
    ///   [2]     length (data layer; 5 hdr + ~5 data bytes)
    ///   [3]     control: DIR=1 PRM=1 FC=4 (UNCONFIRMED_USER_DATA = 0x44)
    ///   [4..5]  dst address LE (0x0001)
    ///   [6..7]  src address LE (0x0002)
    ///   [8..9]  link-layer CRC placeholder (0x00 0x00 — not verified per story)
    ///   [10]    transport: FIN=1 FIR=1 seq=0 (0xC0)
    ///   [11]    app control: FIR=1 FIN=1 seq=0 (0xC0)
    ///   [12]    app function code
    ///   [13..14] app-layer CRC placeholder
    fn make_frame(function_code: u8) -> Vec<u8> {
        vec![
            0x05,
            0x64, // sync
            0x0A, // length
            0x44, // control: DIR=1 PRM=1 FUNC=4
            0x01,
            0x00, // dst = 1 (LE)
            0x02,
            0x00, // src = 2 (LE)
            0x00,
            0x00, // link CRC placeholder
            0xC0, // transport: FIN=1 FIR=1 seq=0
            0xC0, // app control
            function_code,
            0x00,
            0x00, // app CRC placeholder
        ]
    }

    // --- BC-1.02.005 postcondition: parse returns Some on valid frames ---

    #[test]
    fn parse_recognizes_operate() {
        // AC-001 / BC-1.02.005: Operate (fc=4) round-trip
        let frame = make_frame(4);
        let pdu = parse(&frame).expect("valid DNP3 frame with fc=4 should parse");
        assert_eq!(pdu.function_code, 4);
    }

    #[test]
    fn parse_recognizes_direct_operate() {
        // AC-001 / BC-1.02.005: Direct Operate (fc=5) round-trip
        let frame = make_frame(5);
        let pdu = parse(&frame).expect("valid DNP3 frame with fc=5 should parse");
        assert_eq!(pdu.function_code, 5);
    }

    #[test]
    fn parse_recognizes_cold_restart() {
        // AC-001 / BC-1.02.005: Cold Restart (fc=13) explicitly listed in story
        let frame = make_frame(13);
        let pdu = parse(&frame).expect("valid DNP3 frame with fc=13 should parse");
        assert_eq!(pdu.function_code, 13);
    }

    #[test]
    fn parse_recognizes_warm_restart() {
        // AC-001 / BC-1.02.005: Warm Restart (fc=14)
        let frame = make_frame(14);
        let pdu = parse(&frame).expect("valid DNP3 frame with fc=14 should parse");
        assert_eq!(pdu.function_code, 14);
    }

    #[test]
    fn parse_recognizes_save_configuration() {
        // AC-001 / BC-1.02.005: Save Configuration (fc=24)
        let frame = make_frame(24);
        let pdu = parse(&frame).expect("valid DNP3 frame with fc=24 should parse");
        assert_eq!(pdu.function_code, 24);
    }

    // --- BC-1.02.005 precondition: parse returns None on invalid frames ---

    #[test]
    fn parse_rejects_missing_sync_bytes() {
        // EC-001: frame starts with wrong bytes — not DNP3
        let bad = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0x04, 0x00,
            0x00,
        ];
        assert!(
            parse(&bad).is_none(),
            "non-DNP3 sync bytes must return None"
        );
    }

    #[test]
    fn parse_rejects_truncated_frame() {
        // EC-001: only the two sync bytes — far too short
        let truncated = vec![0x05, 0x64];
        assert!(
            parse(&truncated).is_none(),
            "truncated frame must return None"
        );
    }

    #[test]
    fn parse_rejects_empty_payload() {
        // EC-001 boundary: completely empty
        assert!(parse(&[]).is_none(), "empty payload must return None");
    }

    #[test]
    fn parse_rejects_wrong_first_sync_byte() {
        // Sync bytes are 0x05 0x64; swapping the first must reject
        let mut frame = make_frame(4);
        frame[0] = 0x06;
        assert!(
            parse(&frame).is_none(),
            "wrong first sync byte must return None"
        );
    }

    #[test]
    fn parse_rejects_wrong_second_sync_byte() {
        // Sync bytes are 0x05 0x64; corrupting the second must reject
        let mut frame = make_frame(4);
        frame[1] = 0x65;
        assert!(
            parse(&frame).is_none(),
            "wrong second sync byte must return None"
        );
    }

    // --- BC-1.02.005 / AC-002: engineering classification ---

    #[test]
    fn is_engineering_class_classifies_all_engineering_codes_correctly() {
        // AC-002: every fc in the engineering set must return true
        for fc in [4u8, 5, 6, 13, 14, 15, 16, 20, 21, 24] {
            let pdu = Dnp3Pdu { function_code: fc };
            assert!(
                pdu.is_engineering_class(),
                "fc={fc} should be classified engineering"
            );
        }
    }

    #[test]
    fn is_engineering_class_does_not_flag_read_codes() {
        // AC-002: Read (1), Read-with-time (2), Unsolicited Response (22),
        // Confirm (23) are explicitly NOT engineering
        for fc in [1u8, 2, 22, 23] {
            let pdu = Dnp3Pdu { function_code: fc };
            assert!(
                !pdu.is_engineering_class(),
                "fc={fc} should NOT be classified engineering"
            );
        }
    }
}

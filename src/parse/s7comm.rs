//! Minimal S7Comm parser.
//!
//! Recognizes Siemens S7Comm over TPKT/COTP/TCP-102. v0.1 fidelity: just
//! enough to identify the function code so the engineering-commands
//! finding can flag writes, programming, and CPU control. No PDU-level
//! decoding (no variable values, no block contents).
//!
//! See `docs/specs/s7comm-parser.md`.

pub const PORT: u16 = 102;

const S7_PROTO_ID: u8 = 0x32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7Pdu {
    pub rosctr: u8,
    pub function_code: u8,
}

impl S7Pdu {
    pub fn label(&self) -> &'static str {
        match self.function_code {
            0x00 => "CPU services",
            0x04 => "Read Var",
            0x05 => "Write Var",
            0x1A => "Request download",
            0x1B => "Download block",
            0x1C => "Download ended",
            0x1D => "Start upload",
            0x1E => "Upload",
            0x1F => "End upload",
            0x28 => "PLC Control",
            0x29 => "PLC Stop",
            0xF0 => "Setup communication",
            _ => "Unknown",
        }
    }

    pub fn is_engineering_class(&self) -> bool {
        matches!(
            self.function_code,
            0x05      // Write Var
            | 0x1A    // Request download
            | 0x1B    // Download block
            | 0x1C    // Download ended
            | 0x1D    // Start upload
            | 0x1E    // Upload
            | 0x1F    // End upload
            | 0x28    // PLC Control
            | 0x29 // PLC Stop
        )
    }

    pub fn is_read_class(&self) -> bool {
        matches!(self.function_code, 0x04)
    }
}

/// Parse one S7Comm PDU from a TCP/102 payload.
///
/// Returns `None` if the payload doesn't look like TPKT+COTP+S7, if the
/// S7 header is incomplete, or if there are no parameters (no function
/// code byte to read).
pub fn parse(payload: &[u8]) -> Option<S7Pdu> {
    // TPKT: 0x03 0x00 length(2) — minimum 4 bytes.
    if payload.len() < 7 {
        return None;
    }
    if payload[0] != 0x03 || payload[1] != 0x00 {
        return None;
    }

    // COTP: first byte after TPKT is the COTP header length byte (the
    // count excludes itself).
    let cotp_len_byte = *payload.get(4)? as usize;
    let s7_offset = 5 + cotp_len_byte;
    if payload.len() < s7_offset + 10 {
        return None;
    }

    if payload[s7_offset] != S7_PROTO_ID {
        return None;
    }

    let rosctr = payload[s7_offset + 1];
    // S7 header: 10 bytes for Job (0x01) / UserData (0x07), 12 bytes for
    // Ack (0x02) / Ack_Data (0x03) which append error class + error code.
    let s7_header_len = match rosctr {
        0x02 | 0x03 => 12,
        _ => 10,
    };

    // Parameter length is at offset s7_offset + 6 (big-endian u16).
    let param_len = u16::from_be_bytes([payload[s7_offset + 6], payload[s7_offset + 7]]) as usize;
    if param_len == 0 {
        return None;
    }

    let param_offset = s7_offset + s7_header_len;
    if payload.len() <= param_offset {
        return None;
    }
    let function_code = payload[param_offset];

    Some(S7Pdu {
        rosctr,
        function_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic TPKT+COTP+S7 frame for tests. ROSCTR = Job (0x01),
    /// COTP DT (length=0x02, code=0xF0, sequence=0x80), 10-byte S7 header.
    fn job_with_function_code(fc: u8) -> Vec<u8> {
        // TPKT (4 bytes): 0x03 0x00 length_be
        // COTP (3 bytes): 0x02 0xF0 0x80
        // S7 hdr (10 bytes): 0x32 0x01 0x00 0x00 0x00 0x00 param_len_be data_len_be
        //   We set param_len=2, data_len=0.
        // S7 params (2 bytes): fc 0x00
        let total: u16 = 4 + 3 + 10 + 2;
        let mut out = vec![0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8];
        out.extend_from_slice(&[0x02, 0xF0, 0x80]); // COTP
        out.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00]); // S7 hdr
        out.extend_from_slice(&[fc, 0x00]); // params
        out
    }

    #[test]
    fn parses_setup_communication() {
        let pkt = job_with_function_code(0xF0);
        let pdu = parse(&pkt).expect("parses");
        assert_eq!(pdu.function_code, 0xF0);
        assert_eq!(pdu.label(), "Setup communication");
        assert!(!pdu.is_engineering_class());
    }

    #[test]
    fn write_var_is_engineering_class() {
        let pkt = job_with_function_code(0x05);
        let pdu = parse(&pkt).expect("parses");
        assert_eq!(pdu.label(), "Write Var");
        assert!(pdu.is_engineering_class());
    }

    #[test]
    fn read_var_is_not_engineering_class() {
        let pkt = job_with_function_code(0x04);
        let pdu = parse(&pkt).expect("parses");
        assert!(!pdu.is_engineering_class());
        assert!(pdu.is_read_class());
    }

    #[test]
    fn plc_stop_is_engineering_class() {
        let pkt = job_with_function_code(0x29);
        let pdu = parse(&pkt).expect("parses");
        assert_eq!(pdu.label(), "PLC Stop");
        assert!(pdu.is_engineering_class());
    }

    #[test]
    fn programming_function_codes_all_engineering_class() {
        for fc in [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F] {
            let pkt = job_with_function_code(fc);
            let pdu = parse(&pkt).expect("parses");
            assert!(
                pdu.is_engineering_class(),
                "fc=0x{:02X} should be engineering",
                fc
            );
        }
    }

    #[test]
    fn rejects_non_tpkt() {
        let bytes = [0xFF, 0x00, 0x00, 0x10, 0x02, 0xF0, 0x80, 0x32, 0x01];
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn rejects_short_payload() {
        let bytes = [0x03, 0x00, 0x00, 0x07];
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn rejects_zero_param_length() {
        // Same as a Job but with param_len=0 in the S7 header.
        let total: u16 = 4 + 3 + 10;
        let mut out = vec![0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8];
        out.extend_from_slice(&[0x02, 0xF0, 0x80]);
        out.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(parse(&out).is_none());
    }

    #[test]
    fn parses_ack_data_with_extra_header_bytes() {
        // ROSCTR = Ack_Data (0x03) → S7 header is 12 bytes (extra error
        // class + error code at the end). Build that and ensure we still
        // read the function code at the right offset.
        let total: u16 = 4 + 3 + 12 + 2;
        let mut out = vec![0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8];
        out.extend_from_slice(&[0x02, 0xF0, 0x80]);
        // S7 hdr (12 bytes for Ack_Data): proto rosctr res(2) ref(2) plen(2) dlen(2) errclass(1) errcode(1)
        out.extend_from_slice(&[
            0x32, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        out.extend_from_slice(&[0x05, 0x00]); // params: Write Var response
        let pdu = parse(&out).expect("parses");
        assert_eq!(pdu.function_code, 0x05);
    }
}

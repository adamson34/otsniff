//! Minimal Modbus/TCP parser.
//!
//! v0.1 only needs to recognize *which* function code was used so the
//! engineering-commands finding can flag writes and dangerous diagnostics.
//! No register-level decoding.

pub const PORT: u16 = 502;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusPdu {
    pub unit_id: u8,
    pub function_code: u8,
    /// First 2 bytes of the PDU payload (after function code) — useful for
    /// distinguishing diagnostic sub-functions in fc=0x08.
    pub sub: u16,
}

impl ModbusPdu {
    pub fn category(&self) -> Category {
        match self.function_code {
            0x01 | 0x02 | 0x03 | 0x04 | 0x07 | 0x0B | 0x0C | 0x11 | 0x14 | 0x18 | 0x2B => {
                Category::Read
            }
            0x05 | 0x06 | 0x0F | 0x10 | 0x15 | 0x16 => Category::Write,
            0x17 => Category::ReadWrite,
            0x08 => Category::Diagnostic,
            _ => Category::Other,
        }
    }

    pub fn label(&self) -> &'static str {
        match self.function_code {
            0x01 => "Read Coils",
            0x02 => "Read Discrete Inputs",
            0x03 => "Read Holding Registers",
            0x04 => "Read Input Registers",
            0x05 => "Write Single Coil",
            0x06 => "Write Single Register",
            0x07 => "Read Exception Status",
            0x08 => match self.sub {
                0x0001 => "Diagnostic: Restart Communications",
                0x0004 => "Diagnostic: Force Listen Only Mode",
                0x000A => "Diagnostic: Clear Counters",
                _ => "Diagnostic",
            },
            0x0F => "Write Multiple Coils",
            0x10 => "Write Multiple Registers",
            0x11 => "Report Server ID",
            0x14 => "Read File Record",
            0x15 => "Write File Record",
            0x16 => "Mask Write Register",
            0x17 => "Read/Write Multiple Registers",
            _ => "Unknown",
        }
    }

    /// Sub-set of writes/diagnostics treated as engineering-class for the
    /// findings layer. These are the calls that change plant state.
    pub fn is_engineering_class(&self) -> bool {
        matches!(self.category(), Category::Write | Category::ReadWrite)
            || matches!(
                (self.function_code, self.sub),
                (0x08, 0x0001) | (0x08, 0x0004) | (0x08, 0x000A)
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
    ReadWrite,
    Diagnostic,
    Other,
}

/// Parse one Modbus/TCP MBAP-framed PDU from a TCP payload.
///
/// Returns None if the payload is too short or the protocol-id field isn't
/// zero. Multiple PDUs in a single segment are not handled in v0.1.
pub fn parse(payload: &[u8]) -> Option<ModbusPdu> {
    if payload.len() < 8 {
        return None;
    }
    let proto_id = u16::from_be_bytes([payload[2], payload[3]]);
    if proto_id != 0 {
        return None;
    }
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < 2 || payload.len() < 6 + length {
        return None;
    }
    let unit_id = payload[6];
    let function_code = payload[7];
    let sub = if payload.len() >= 10 {
        u16::from_be_bytes([payload[8], payload[9]])
    } else {
        0
    };
    Some(ModbusPdu {
        unit_id,
        function_code,
        sub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_single_coil_is_engineering_class() {
        // MBAP: txn=0001 proto=0000 len=0006 unit=01 | fc=05 addr=0001 val=FF00
        let bytes = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xff, 0x00,
        ];
        let pdu = parse(&bytes).expect("parses");
        assert_eq!(pdu.function_code, 0x05);
        assert_eq!(pdu.category(), Category::Write);
        assert!(pdu.is_engineering_class());
    }

    #[test]
    fn read_holding_registers_not_engineering() {
        let bytes = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a,
        ];
        let pdu = parse(&bytes).expect("parses");
        assert!(!pdu.is_engineering_class());
        assert_eq!(pdu.label(), "Read Holding Registers");
    }

    #[test]
    fn force_listen_only_flagged() {
        let bytes = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00,
        ];
        let pdu = parse(&bytes).expect("parses");
        assert!(pdu.is_engineering_class());
        assert_eq!(pdu.label(), "Diagnostic: Force Listen Only Mode");
    }

    #[test]
    fn rejects_non_modbus() {
        // proto_id != 0
        let bytes = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01, 0x05, 0x00, 0x01, 0xff, 0x00,
        ];
        assert!(parse(&bytes).is_none());
    }
}

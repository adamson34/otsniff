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
        todo!("S-2.04: classify DNP3 function code")
    }
}

/// Recognize a DNP3 frame from a TCP payload. Returns None when bytes
/// are not a valid DNP3 frame (missing sync bytes, length mismatch,
/// truncated, etc.).
pub fn parse(_payload: &[u8]) -> Option<Dnp3Pdu> {
    todo!("S-2.04: DNP3 frame parser")
}

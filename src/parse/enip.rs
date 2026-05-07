//! Minimal EtherNet/IP encapsulation parser (Rockwell / ODVA family).
//!
//! v0.1 only needs to (a) confirm a flow is ENIP and (b) recognize when CIP
//! engineering-class services appear in the payload of SendRRData /
//! SendUnitData commands. We do *not* fully decode CPF or CIP — we look at
//! known offsets and bail otherwise.

pub const PORT: u16 = 44818;

const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnipHeader {
    pub command: u16,
    pub length: u16,
    pub session: u32,
}

impl EnipHeader {
    pub fn command_label(&self) -> &'static str {
        match self.command {
            0x0004 => "ListServices",
            0x0063 => "ListIdentity",
            0x0064 => "ListInterfaces",
            0x0065 => "RegisterSession",
            0x0066 => "UnRegisterSession",
            0x006F => "SendRRData",
            0x0070 => "SendUnitData",
            _ => "Unknown",
        }
    }
}

pub fn parse_header(payload: &[u8]) -> Option<EnipHeader> {
    if payload.len() < HEADER_LEN {
        return None;
    }
    let command = u16::from_le_bytes([payload[0], payload[1]]);
    let length = u16::from_le_bytes([payload[2], payload[3]]);
    let session = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some(EnipHeader {
        command,
        length,
        session,
    })
}

/// Heuristic: scan past the encapsulation header for a CIP service code in
/// SendRRData / SendUnitData payloads. CIP requests have the high bit clear;
/// the service code byte is at varying offsets depending on the CPF item
/// structure but commonly sits 6–10 bytes into the data portion. We sweep a
/// short window and return the first plausible engineering-class service.
pub fn engineering_class_cip(payload: &[u8]) -> Option<CipService> {
    let hdr = parse_header(payload)?;
    if !matches!(hdr.command, 0x006F | 0x0070) {
        return None;
    }
    let data = payload.get(HEADER_LEN..)?;
    // Skip the 4-byte interface handle + 2-byte timeout that precede CPF on
    // SendRRData. Then sweep offsets 6..=24 for an engineering-class service.
    let scan_from = if hdr.command == 0x006F { 6 } else { 0 };
    let end = (scan_from + 24).min(data.len());
    for byte in data.iter().take(end).skip(scan_from) {
        let svc = byte & 0x7f;
        if let Some(s) = CipService::from_code(svc) {
            if s.is_engineering_class() {
                return Some(s);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipService {
    GetAttributeAll,
    SetAttributeAll,
    Reset,
    Start,
    Stop,
    Create,
    Delete,
    GetAttributeSingle,
    SetAttributeSingle,
    ForwardClose,
    UnconnectedSend,
    ForwardOpen,
}

impl CipService {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x01 => Self::GetAttributeAll,
            0x02 => Self::SetAttributeAll,
            0x05 => Self::Reset,
            0x06 => Self::Start,
            0x07 => Self::Stop,
            0x08 => Self::Create,
            0x09 => Self::Delete,
            0x0E => Self::GetAttributeSingle,
            0x10 => Self::SetAttributeSingle,
            0x4E => Self::ForwardClose,
            0x52 => Self::UnconnectedSend,
            0x54 => Self::ForwardOpen,
            _ => return None,
        })
    }

    pub fn is_engineering_class(&self) -> bool {
        matches!(
            self,
            Self::SetAttributeAll
                | Self::SetAttributeSingle
                | Self::Reset
                | Self::Start
                | Self::Stop
                | Self::Create
                | Self::Delete
                | Self::ForwardOpen
                | Self::ForwardClose
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::GetAttributeAll => "Get Attribute All",
            Self::SetAttributeAll => "Set Attribute All",
            Self::Reset => "Reset",
            Self::Start => "Start",
            Self::Stop => "Stop",
            Self::Create => "Create",
            Self::Delete => "Delete",
            Self::GetAttributeSingle => "Get Attribute Single",
            Self::SetAttributeSingle => "Set Attribute Single",
            Self::ForwardClose => "Forward Close",
            Self::UnconnectedSend => "Unconnected Send",
            Self::ForwardOpen => "Forward Open",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_register_session() {
        // command=0x0065, length=0x0004, session=0
        let mut bytes = vec![0u8; HEADER_LEN + 4];
        bytes[0] = 0x65;
        bytes[1] = 0x00;
        bytes[2] = 0x04;
        bytes[3] = 0x00;
        let h = parse_header(&bytes).unwrap();
        assert_eq!(h.command, 0x0065);
        assert_eq!(h.command_label(), "RegisterSession");
    }

    #[test]
    fn cip_stop_is_engineering_class() {
        assert!(CipService::Stop.is_engineering_class());
        assert!(!CipService::GetAttributeSingle.is_engineering_class());
    }
}

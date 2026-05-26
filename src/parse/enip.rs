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

/// Heuristic: locate the CIP service code in SendRRData / SendUnitData
/// payloads by parsing the CPF (Common Packet Format) item structure.
///
/// **F-ADV-P4-007:** the previous implementation swept a 24-byte window
/// looking for any byte whose lower 7 bits matched an engineering-class
/// service code. With service codes 0x05–0x09 (Reset/Start/Stop/Create/
/// Delete) being extremely common byte values in any binary protocol
/// payload (item counts, sequence numbers, type-id low bytes), the
/// probability of a false positive per random 18-byte window was
/// `1 - (251/256)^18 ≈ 30%`. This version parses the CPF structure
/// properly: read item count, walk items reading `(type_id, length)`
/// pairs, inspect ONLY Connected (0x00B1) or Unconnected (0x00B2) data
/// items, and read the service code at the documented offset (byte 0 for
/// Unconnected, byte 2 after the 2-byte sequence count for Connected).
pub fn engineering_class_cip(payload: &[u8]) -> Option<CipService> {
    let hdr = parse_header(payload)?;
    if !matches!(hdr.command, 0x006F | 0x0070) {
        return None;
    }
    let data = payload.get(HEADER_LEN..)?;

    // SendRRData (0x006F): 4-byte interface handle + 2-byte timeout, then CPF.
    // SendUnitData (0x0070): same layout (interface handle + timeout = 0
    // in practice; CPF still starts at offset 6).
    let cpf_start = 6;
    let cpf = data.get(cpf_start..)?;
    // CPF: 2-byte item count, then `count` items of (2-byte type_id,
    // 2-byte length, length-byte data).
    if cpf.len() < 2 {
        return None;
    }
    let item_count = u16::from_le_bytes([cpf[0], cpf[1]]) as usize;
    let mut cursor = 2usize;
    // Bound the loop defensively — a malicious payload could claim a huge
    // item count.
    for _ in 0..item_count.min(16) {
        if cursor + 4 > cpf.len() {
            return None;
        }
        let type_id = u16::from_le_bytes([cpf[cursor], cpf[cursor + 1]]);
        let item_len = u16::from_le_bytes([cpf[cursor + 2], cpf[cursor + 3]]) as usize;
        let item_data_start = cursor + 4;
        let item_data_end = item_data_start.saturating_add(item_len);
        if item_data_end > cpf.len() {
            return None;
        }
        // Inspect only data items. Type IDs:
        //   0x00B1 — Connected Data Item (preceded by a 2-byte sequence count)
        //   0x00B2 — Unconnected Data Item (CIP message starts at offset 0)
        let svc_byte_offset = match type_id {
            0x00B2 => Some(0usize),
            0x00B1 => Some(2usize), // skip the 2-byte sequence count
            _ => None,
        };
        if let Some(off) = svc_byte_offset {
            if let Some(&byte) = cpf.get(item_data_start + off) {
                let svc = byte & 0x7f;
                if let Some(s) = CipService::from_code(svc) {
                    if s.is_engineering_class() {
                        return Some(s);
                    }
                }
            }
        }
        cursor = item_data_end;
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

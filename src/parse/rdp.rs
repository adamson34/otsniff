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
pub fn recognize_connection_confirm(_payload: &[u8]) -> Option<RdpNegRecognized> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_just_to_keep_mod_tree_alive() {}
}

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
    todo!()
}

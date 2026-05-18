//! Minimal LDAP parser stub.
//!
//! v0.1 only needs to recognise a BER-encoded `BindRequest` (tag 0x30 envelope
//! + ProtocolOp tag 0x60) on tcp/389 so the `ldap_creds` finding can flag
//! plaintext simple-bind traffic. No full ASN.1/BER walk is implemented here
//! yet — see S-2.05.

/// Primary port for unencrypted LDAP. The recogniser also accepts LDAP on
/// other ports (e.g., 3268 for the Global Catalog) — the caller decides
/// whether to invoke recognition; this constant is informational.
pub const PORT: u16 = 389;

/// Minimal description of an LDAP `BindRequest` extracted from the wire.
///
/// The implementer fills this struct from the BER walk (S-2.05 task 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapBindRecognized {
    /// LDAP version declared in the `BindRequest` (almost always 3).
    pub version: u8,
    /// `true` when the flow shows evidence of a successful STARTTLS exchange
    /// before this `BindRequest` (STARTTLS suppression — AC-003).
    pub used_starttls: bool,
    /// `true` when the bind is anonymous (empty DN + empty password).
    /// Anonymous binds do not constitute a credential leak — see EC-003.
    pub anonymous: bool,
}

/// Attempt to recognise an LDAP `BindRequest` in a raw TCP payload.
///
/// Returns `Some(LdapBindRecognized)` when the payload contains a valid
/// BER-encoded `LDAPMessage` whose `protocolOp` is a `BindRequest`
/// (tag 0x60) using `SimpleAuthentication` (context tag 0x80).
///
/// Returns `None` for any payload that is not a recognisable LDAP
/// `BindRequest` — too short, wrong tags, `SaslAuthentication`, etc.
///
/// The STARTTLS state (`used_starttls`) is flow-level context that the
/// caller (`observe.rs`) must supply after tracking the `ExtendedRequest`
/// / `ExtendedResponse` sequence for the same `(src, dst, src_port)` tuple.
/// This function is stateless; it inspects only the supplied bytes.
pub fn recognize_bind_request(_bytes: &[u8]) -> Option<LdapBindRecognized> {
    todo!("S-2.05: implement BER walk for LDAPMessage → ProtocolOp → BindRequest")
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_just_to_keep_mod_tree_alive() {}
}

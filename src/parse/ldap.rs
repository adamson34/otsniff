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
    use super::*;

    // -------------------------------------------------------------------------
    // Raw BER-encoded BindRequest fixtures.
    //
    // Layout (RFC 4511 §4.2):
    //   LDAPMessage  SEQUENCE (tag 0x30)
    //     messageID  INTEGER  (tag 0x02)
    //     BindRequest [APPLICATION 0] (tag 0x60)
    //       version  INTEGER  (tag 0x02)
    //       name     OctetString (tag 0x04)   — the Bind DN
    //       auth     AuthenticationChoice
    //         simple [0] IMPLICIT OctetString (tag 0x80) — password
    // -------------------------------------------------------------------------

    /// Construct a minimal BER-encoded LDAPMessage wrapping a BindRequest.
    ///
    /// version:  always 3 (LDAPv3)
    /// dn_bytes: raw octets for the Bind DN (OctetString value)
    /// pw_bytes: raw octets for the SimpleAuthentication password
    fn make_bind_request(dn_bytes: &[u8], pw_bytes: &[u8]) -> Vec<u8> {
        // Inner BindRequest body: version + name + simple-auth
        let version_tlv = vec![0x02, 0x01, 0x03]; // INTEGER 3
        let name_tlv = {
            let mut v = vec![0x04, dn_bytes.len() as u8];
            v.extend_from_slice(dn_bytes);
            v
        };
        let auth_tlv = {
            let mut v = vec![0x80, pw_bytes.len() as u8];
            v.extend_from_slice(pw_bytes);
            v
        };
        let bind_body: Vec<u8> = version_tlv
            .iter()
            .chain(name_tlv.iter())
            .chain(auth_tlv.iter())
            .copied()
            .collect();

        // BindRequest APPLICATION 0 (tag 0x60)
        let bind_req = {
            let mut v = vec![0x60, bind_body.len() as u8];
            v.extend_from_slice(&bind_body);
            v
        };

        // messageID INTEGER 1 (tag 0x02)
        let msg_id = vec![0x02, 0x01, 0x01];

        // LDAPMessage SEQUENCE (tag 0x30)
        let ldap_body: Vec<u8> = msg_id
            .iter()
            .chain(bind_req.iter())
            .copied()
            .collect();
        let mut msg = vec![0x30, ldap_body.len() as u8];
        msg.extend_from_slice(&ldap_body);
        msg
    }

    // AC-001 (BC-1.03.005): recogniser must return Some for a standard
    // LDAPv3 simple-bind with a non-empty DN and non-empty password.
    #[test]
    fn test_BC_1_03_005_recognizes_v3_simple_bind_with_password() {
        let dn = b"cn=admin,dc=example,dc=com";
        let pw = b"hunter2";
        let bytes = make_bind_request(dn, pw);
        let result = recognize_bind_request(&bytes);
        assert_eq!(
            result,
            Some(LdapBindRecognized {
                version: 3,
                used_starttls: false,
                anonymous: false,
            }),
            "AC-001: LDAPv3 simple-bind with credentials must be recognized"
        );
    }

    // AC-001 / EC-003 (BC-1.03.005): recogniser must surface anonymous flag
    // for empty DN + empty password; suppression is the finding layer's job.
    #[test]
    fn test_BC_1_03_005_recognizes_anonymous_bind_empty_password() {
        let bytes = make_bind_request(b"", b"");
        let result = recognize_bind_request(&bytes);
        assert_eq!(
            result,
            Some(LdapBindRecognized {
                version: 3,
                used_starttls: false,
                anonymous: true,
            }),
            "EC-003: anonymous bind (empty DN + empty password) must be recognized with anonymous=true"
        );
    }

    // Negative: random bytes that are not a valid LDAP BER envelope.
    #[test]
    fn test_BC_1_03_005_rejects_non_ldap_payload() {
        let bytes: &[u8] = &[0xff, 0x00, 0x01];
        assert_eq!(
            recognize_bind_request(bytes),
            None,
            "Non-LDAP payload must return None"
        );
    }

    // Negative: valid LDAPMessage outer envelope but ProtocolOp tag 0x42
    // (UnbindRequest) instead of BindRequest (0x60). RFC 4511 §4.3.
    #[test]
    fn test_BC_1_03_005_rejects_ldap_unbind() {
        // Build an LDAPMessage with an UnbindRequest (tag 0x42, NULL body)
        let msg_id = [0x02u8, 0x01, 0x02]; // messageID 2
        let unbind_req = [0x42u8, 0x00]; // UnbindRequest APPLICATION 2, empty
        let ldap_body: Vec<u8> = msg_id
            .iter()
            .chain(unbind_req.iter())
            .copied()
            .collect();
        let mut bytes = vec![0x30u8, ldap_body.len() as u8];
        bytes.extend_from_slice(&ldap_body);
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "UnbindRequest (tag 0x42) must return None — only BindRequest (0x60) is recognized"
        );
    }

    // Defensive: LDAPMessage with declared outer length > buffer length.
    // The parser must not panic and must return None.
    #[test]
    fn test_BC_1_03_005_rejects_oversized_length() {
        // Construct a real BindRequest but then lie about the outer SEQUENCE length.
        let inner = make_bind_request(b"cn=admin", b"pass");
        // Replace the outer length byte (index 1) with 0xff (255),
        // which is larger than the remaining buffer.
        let mut malformed = inner.clone();
        malformed[1] = 0xff;
        assert_eq!(
            recognize_bind_request(&malformed),
            None,
            "Oversized declared length must return None, not panic"
        );
    }
}

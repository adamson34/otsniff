//! Minimal LDAP parser.
//!
//! Recognises a BER-encoded `BindRequest` (tag 0x30 envelope + ProtocolOp tag
//! 0x60) on tcp/389 or tcp/3268 so the `ldap_creds` finding can flag plaintext
//! simple-bind traffic (S-2.05).

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
pub fn recognize_bind_request(bytes: &[u8]) -> Option<LdapBindRecognized> {
    let mut pos = 0;

    // RFC 4511 §5.1: LDAPMessage is a SEQUENCE (universal tag 0x30).
    let (_, seq_len) = read_tlv_header(bytes, &mut pos, 0x30)?;

    // Defensive: the declared SEQUENCE length must not exceed the buffer.
    if pos + seq_len > bytes.len() {
        return None;
    }

    // RFC 4511 §4.1.1: messageID INTEGER (tag 0x02). We do not need its
    // value — skip the TLV wholesale.
    skip_tlv(bytes, &mut pos, 0x02)?;

    // RFC 4511 §4.2: protocolOp must be BindRequest [APPLICATION 0] (tag 0x60).
    // Any other APPLICATION tag (e.g. 0x42 UnbindRequest) is rejected.
    let (_, bind_len) = read_tlv_header(bytes, &mut pos, 0x60)?;
    if pos + bind_len > bytes.len() {
        return None;
    }

    // RFC 4511 §4.2: version INTEGER (tag 0x02), value 1 byte.
    let (_, ver_len) = read_tlv_header(bytes, &mut pos, 0x02)?;
    if ver_len == 0 || pos + ver_len > bytes.len() {
        return None;
    }
    let version = bytes[pos];
    pos += ver_len;

    // RFC 4511 §4.2: name LDAPDN OctetString (tag 0x04) — the Bind DN.
    // We read the length but don't need the DN value; skip the content.
    let (_, dn_len) = read_tlv_header(bytes, &mut pos, 0x04)?;
    if pos + dn_len > bytes.len() {
        return None;
    }
    pos += dn_len;

    // RFC 4511 §4.2: AuthenticationChoice. Tag 0x80 = simple (context 0,
    // IMPLICIT OctetString). Anything else (SASL is tag 0xa3) is not
    // a simple-bind and we return None.
    let (_, pw_len) = read_tlv_header(bytes, &mut pos, 0x80)?;
    if pos + pw_len > bytes.len() {
        return None;
    }

    // EC-003: anonymous bind has an empty password (pw_len == 0).
    let anonymous = pw_len == 0;

    // STARTTLS state is tracked per-flow in the observer; this function
    // is stateless and always returns false for used_starttls.
    Some(LdapBindRecognized {
        version,
        used_starttls: false,
        anonymous,
    })
}

/// Read a BER TLV header (tag byte + short-form length) at `pos`, advancing
/// `pos` past the header. Returns `(tag, content_length)` on success.
///
/// Only short-form lengths (< 128) are accepted. This is sufficient for the
/// BindRequest PDUs we encounter in practice (RFC 4511 DN length is bounded
/// by 255 octets; most real bind messages fit in a single TCP segment).
fn read_tlv_header(buf: &[u8], pos: &mut usize, expected_tag: u8) -> Option<(u8, usize)> {
    if *pos + 2 > buf.len() {
        return None;
    }
    let tag = buf[*pos];
    if tag != expected_tag {
        return None;
    }
    *pos += 1;
    let len_byte = buf[*pos] as usize;
    // Long-form length (bit 7 set) is not supported.
    if len_byte & 0x80 != 0 {
        return None;
    }
    *pos += 1;
    Some((tag, len_byte))
}

/// Skip a TLV at `pos` (tag byte + length + content), advancing `pos` past
/// the entire element. Used to skip the messageID we don't care about.
fn skip_tlv(buf: &[u8], pos: &mut usize, expected_tag: u8) -> Option<()> {
    let (_, len) = read_tlv_header(buf, pos, expected_tag)?;
    if *pos + len > buf.len() {
        return None;
    }
    *pos += len;
    Some(())
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
        let version_tlv: &[u8] = &[0x02, 0x01, 0x03]; // INTEGER 3
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
        let msg_id: &[u8] = &[0x02, 0x01, 0x01];

        // LDAPMessage SEQUENCE (tag 0x30)
        let ldap_body: Vec<u8> = msg_id.iter().chain(bind_req.iter()).copied().collect();
        let mut msg = vec![0x30, ldap_body.len() as u8];
        msg.extend_from_slice(&ldap_body);
        msg
    }

    // AC-001 (BC-1.03.005): recogniser must return Some for a standard
    // LDAPv3 simple-bind with a non-empty DN and non-empty password.
    #[test]
    fn test_bc_1_03_005_recognizes_v3_simple_bind_with_password() {
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
    fn test_bc_1_03_005_recognizes_anonymous_bind_empty_password() {
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
    fn test_bc_1_03_005_rejects_non_ldap_payload() {
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
    fn test_bc_1_03_005_rejects_ldap_unbind() {
        // Build an LDAPMessage with an UnbindRequest (tag 0x42, NULL body)
        let msg_id = [0x02u8, 0x01, 0x02]; // messageID 2
        let unbind_req = [0x42u8, 0x00]; // UnbindRequest APPLICATION 2, empty
        let ldap_body: Vec<u8> = msg_id.iter().chain(unbind_req.iter()).copied().collect();
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
    fn test_bc_1_03_005_rejects_oversized_length() {
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

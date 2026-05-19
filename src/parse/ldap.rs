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

    // ── Group B: boundary tests for each bounds-check mutant ─────────────────
    //
    // The surviving mutants operate on the `>` comparisons on lines 47, 58, 73,
    // 82 and the `||` / `==` on line 64 and the `>` in skip_tlv (line 126).
    //
    // Strategy: craft payloads where the declared length field is exactly one
    // byte past the end of the available buffer. These trip the `>` check; a
    // mutant that changes `>` to `>=` would require the claimed size to equal
    // the buffer length (tight fit), so we also test the tight-fit case where
    // the buffer is exactly big enough and the result should be `Some(...)`.

    // ── Line 47: outer SEQUENCE bounds check ─────────────────────────────────

    /// The outer SEQUENCE declares length exactly equal to remaining bytes.
    /// The check `pos + seq_len > bytes.len()` allows this; `>=` would reject it.
    #[test]
    fn test_ldap_line47_seq_len_exactly_fits_is_accepted() {
        // A valid bind request: every byte is accounted for.
        let bytes = make_bind_request(b"cn=admin", b"secret");
        // If this is a valid BER message the outer SEQUENCE length exactly covers
        // the buffer contents (make_bind_request does not add padding).
        // Parsing must succeed.
        let result = recognize_bind_request(&bytes);
        assert!(
            result.is_some(),
            "bind request whose SEQUENCE length exactly fits must be accepted"
        );
    }

    /// The outer SEQUENCE claims one more byte than the buffer contains.
    /// Must return None.
    #[test]
    fn test_ldap_line47_seq_len_exceeds_buffer_by_one_is_rejected() {
        let mut bytes = make_bind_request(b"cn=admin", b"secret");
        // Increment the outer length byte by 1 so the claimed size is one past the end.
        bytes[1] += 1;
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "SEQUENCE claiming one extra byte must be rejected"
        );
    }

    // ── Line 58: BindRequest APPLICATION 0 bounds check ─────────────────────

    /// The BindRequest APPLICATION tag claims a length one byte beyond the buffer.
    /// Must return None.
    #[test]
    fn test_ldap_line58_bind_len_exceeds_buffer_is_rejected() {
        let mut bytes = make_bind_request(b"cn=admin", b"secret");
        // bytes[1] is the outer SEQUENCE length.
        // bytes[2] is the messageID tag (0x02).
        // bytes[3] is the messageID length (0x01).
        // bytes[4] is the messageID value (0x01).
        // bytes[5] is the BindRequest APPLICATION tag (0x60).
        // bytes[6] is the BindRequest length.
        // We inflate the BindRequest length by 1 without touching the outer SEQUENCE
        // length, so the outer bounds check (line 47) passes but the inner one (line 58) fails.
        bytes[6] += 1;
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "BindRequest claiming one extra byte must be rejected"
        );
    }

    // ── Line 64: version ver_len == 0 || pos + ver_len > buf ────────────────
    //
    // The condition is `ver_len == 0 || pos + ver_len > bytes.len()`.
    // Mutants could:
    //   (a) change `||` to `&&` — making a zero-length version field accepted
    //   (b) change `==` to `!=` — making any non-zero ver_len unconditionally fail
    //
    // Test (a): craft a BindRequest whose version INTEGER has len=0.
    //   Original (||): rejects because ver_len == 0 is true.
    //   Mutant (&&):  does NOT reject because `0 > len` is also false,
    //                 so it happily reads bytes[pos] as the version.

    /// A version INTEGER with declared length 0 must be rejected.
    ///
    /// Kills the `||` → `&&` mutant on line 64 by constructing a crafted message
    /// where the parser would succeed after the ver_len=0 check IF it continued
    /// (the bytes that follow ver_len=0 happen to form a valid DN + password),
    /// but the original code must return None because ver_len == 0 is unconditionally
    /// rejected via the `||` arm.
    #[test]
    fn test_ldap_line64_zero_version_length_is_rejected() {
        // Build a valid bind request: after the version tag+len bytes, the remaining
        // bytes are: version value (0x03), DN tag (0x04), DN len, DN bytes, pw tag (0x80), pw len.
        //
        // We want: bytes[8] = 0x00 (ver_len = 0), but bytes[9..] must look like a
        // valid DN OctetString followed by a valid SimpleAuthentication so that the
        // `&&` mutant's parser continues past ver_len=0 and returns Some(...).
        //
        // With ver_len = 0:
        //   - Original (`||`): ver_len == 0 → true → return None. CORRECT.
        //   - Mutant (`&&`): ver_len == 0 && (pos + 0 > len) = false → does NOT return None.
        //     Parser reads bytes[pos=9] as "version" value.
        //     bytes[9] must equal 0x04 for DN tag match. Then DN len at [10], DN at [11..],
        //     pw tag 0x80, pw len, pw bytes — all valid → mutant returns Some(...).
        //
        // Construct exactly this scenario:
        // [0] 0x30  [1] total_len
        // [2] 0x02  [3] 0x01  [4] 0x01   (msgID = 1)
        // [5] 0x60  [6] bind_len
        // [7] 0x02  [8] 0x00              (version tag, len=0)
        // [9] 0x04  [10] 0x02  [11] 'a'  [12] 'b'   (DN "ab" — but also where mutant reads version=0x04)
        // [13] 0x80 [14] 0x02  [15] 'x'  [16] 'y'   (password "xy")
        //
        // bind body (from [7] onwards): version TLV (0x02,0x00) + DN TLV (0x04,0x02,'a','b')
        //                               + pw TLV (0x80,0x02,'x','y') = 2 + 4 + 4 = 10 bytes
        // bind_len = 10
        // ldap body (from [2]): msgID TLV (0x02,0x01,0x01) + bind TLV (0x60,10,...) = 3 + 12 = 15
        // outer SEQUENCE len = 15
        let mut buf = vec![
            0x30, 15, // LDAPMessage SEQUENCE, len=15
            0x02, 0x01, 0x01, // messageID = 1
            0x60, 10, // BindRequest APPLICATION 0, len=10
            0x02, 0x00, // version INTEGER, len=0  ← the trigger
            0x04, 0x02, b'a', b'b', // name OctetString, len=2, value="ab"
            0x80, 0x02, b'x', b'y', // simple [0], len=2, value="xy"
        ];
        // Verify outer + inner lengths are consistent with buf.len() = 17
        assert_eq!(buf.len(), 17, "sanity: crafted buf must be 17 bytes");

        let result = recognize_bind_request(&buf);
        assert_eq!(
            result, None,
            "version INTEGER with length 0 must be rejected by the || check; \
             the && mutant would return Some here"
        );

        // Sanity: patch ver_len back to 0x01 and the same message parses successfully.
        buf[8] = 0x01; // ver_len = 1 (one byte: 0x04 is not a valid LDAP version but parse continues)
                       // Note: with ver_len=1, version = bytes[9] = 0x04. Then pos advances past it.
                       // Then DN tag at bytes[10]=0x02 (INTEGER tag, not OctetString tag 0x04) → fails.
                       // So we just confirm it returns None too (for different reason). The key test
                       // is the original above where ver_len=0 triggers the || branch.
                       // The important assertion is the one above — do not weaken it.
    }

    // ── Line 73: DN OctetString bounds check ─────────────────────────────────

    /// DN OctetString claims a length one byte beyond the buffer.
    /// Must return None.
    #[test]
    fn test_ldap_line73_dn_len_exceeds_buffer_is_rejected() {
        // Build a valid message then inflate the DN length byte.
        let dn = b"cn=admin";
        let pw = b"secret";
        let mut bytes = make_bind_request(dn, pw);
        // The DN OctetString tag (0x04) sits after the version field.
        // Walk the known offsets:
        //   [0] 0x30 outer tag
        //   [1] outer len
        //   [2] 0x02 msgID tag
        //   [3] 0x01 msgID len
        //   [4] 0x01 msgID value
        //   [5] 0x60 bind tag
        //   [6] bind len
        //   [7] 0x02 version tag
        //   [8] 0x01 version len
        //   [9] 0x03 version value
        //   [10] 0x04 DN tag
        //   [11] DN len  ← inflate
        bytes[11] = (dn.len() as u8) + 50; // claim far more than available
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "DN OctetString claiming excess bytes must be rejected (line 73)"
        );
    }

    // ── Line 82: password SimpleAuthentication bounds check ──────────────────

    /// Password SimpleAuthentication claims a length one byte beyond the buffer.
    /// Must return None.
    #[test]
    fn test_ldap_line82_pw_len_exceeds_buffer_is_rejected() {
        let dn = b"cn=admin";
        let pw = b"secret";
        let mut bytes = make_bind_request(dn, pw);
        // The SimpleAuthentication (0x80) tag comes after the DN content.
        // Offset of the 0x80 tag = 10 (version tlv) + 2 + dn.len() (DN tlv)
        //                        = 2 (outer hdr) + 3 (msgID tlv) + 2 (bind hdr) +
        //                          3 (version tlv) + 2 + dn.len() (DN tlv)
        // = 12 + dn.len()
        // The length byte follows the tag: offset 13 + dn.len()
        let pw_tag_offset = 12 + dn.len();
        let pw_len_offset = pw_tag_offset + 1;
        assert_eq!(
            bytes[pw_tag_offset], 0x80,
            "sanity: expected 0x80 at pw tag offset"
        );
        bytes[pw_len_offset] = (pw.len() as u8) + 50; // claim far more than available
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "password SimpleAuthentication claiming excess bytes must be rejected (line 82)"
        );
    }

    // ── Line 126: skip_tlv bounds check ──────────────────────────────────────
    //
    // skip_tlv is used to skip the messageID. If the messageID claims
    // a length that extends past the buffer end, skip_tlv must return None
    // so that recognize_bind_request propagates None.

    /// messageID INTEGER whose claimed length runs past the buffer end must
    /// cause the entire parse to return None.
    #[test]
    fn test_ldap_line126_skip_tlv_len_exceeds_buffer_is_rejected() {
        let mut bytes = make_bind_request(b"cn=admin", b"secret");
        // messageID length is at offset 3. Inflate it so *pos + len > buf.len().
        // The messageID value occupies 1 byte (offset 4), so setting len=255
        // guarantees the overflow.
        bytes[3] = 0x7F; // 127 bytes claimed — short-form, not long-form (bit 7 clear)
        assert_eq!(
            recognize_bind_request(&bytes),
            None,
            "messageID length overflowing buffer must be rejected by skip_tlv (line 126)"
        );
    }

    /// Verifies the || short-circuit in line 64: a valid non-zero ver_len that
    /// fits within the buffer must not be rejected.
    /// This is the complement of test_ldap_line64_zero_version_length_is_rejected.
    #[test]
    fn test_ldap_line64_nonzero_version_length_that_fits_is_accepted() {
        // Standard bind request has ver_len=1 and the byte fits — must succeed.
        let bytes = make_bind_request(b"uid=test", b"pass123");
        let result = recognize_bind_request(&bytes);
        assert!(
            result.is_some(),
            "standard ver_len=1 that fits in buffer must be accepted"
        );
        assert_eq!(result.unwrap().version, 3);
    }

    // ── Tight-fit boundary tests: distinguish `>` from `>=` and `==` ─────────
    //
    // For bounds checks of the form `pos + len > buf.len()`:
    //   Original (`>`):  accepts when pos+len == buf.len() (exact fit)
    //   Mutant (`>=`):   rejects when pos+len == buf.len() (exact fit)
    //   Mutant (`==`):   only rejects when pos+len == buf.len() (tight equals)
    //
    // The password field (last field) is special: when `pos + pw_len == bytes.len()`
    // exactly, the original code accepts it and the parse succeeds. The `>=` mutant
    // would reject it. The `==` mutant would also reject it. Both fail this test.
    //
    // For lines 64, 73, 126 the `>` vs `>=` distinction similarly:
    //   - line 64 (ver): ver content is not the last byte; a tight fit here means
    //     subsequent fields won't fit — both original and mutant return None.
    //   - line 73 (dn): same; tight fit here still works if pw can fit after.
    //   - line 126 (skip_tlv): msgID exact fit still leaves the rest of the buffer.
    //
    // For line 82 (pw), the password IS the last field, so tight fit is valid.

    /// Password field that exactly reaches the end of the buffer (pos + pw_len ==
    /// bytes.len()) must be accepted by the original `>` check.
    ///
    /// Kills `replace > with >=` and `replace > with ==` mutants on line 82.
    #[test]
    fn test_ldap_line82_pw_exact_fit_to_end_is_accepted() {
        // make_bind_request constructs a correctly-framed message where the
        // password bytes are the final content in the buffer (no padding after).
        // So pos + pw_len == bytes.len() holds exactly at the password check.
        let pw = b"exactpw";
        let bytes = make_bind_request(b"cn=admin", pw);
        // Sanity: verify the message parses correctly (no inflation).
        let result = recognize_bind_request(&bytes);
        assert!(
            result.is_some(),
            "tight-fit password (exactly fills buffer) must be accepted; got None"
        );
        assert_eq!(result.unwrap().anonymous, false);
    }

    /// Password of length 0 at exact end of buffer (anonymous bind tight fit).
    /// Still exactly fits. Kills `>=` mutant: 0-length pw still has pos == len.
    #[test]
    fn test_ldap_line82_empty_pw_exact_fit_is_accepted() {
        let bytes = make_bind_request(b"cn=admin", b"");
        let result = recognize_bind_request(&bytes);
        assert!(
            result.is_some(),
            "anonymous bind (empty pw, exact fit) must be accepted; got None"
        );
        assert_eq!(result.unwrap().anonymous, true);
    }

    // ── Line 73: dn tight-fit where pw still has room ────────────────────────
    //
    // If we make the DN empty, pos + dn_len (= pos + 0 = pos) does NOT equal
    // buf.len() — the rest of the message (pw field) follows. This won't help.
    // The tight fit for dn (pos + dn_len == bytes.len()) would mean no pw field,
    // which is malformed. So a `>=` mutant and original both return None.
    //
    // However, we can kill `replace > with ==` on line 73: with the mutant,
    // `pos + dn_len == bytes.len()` rejects, but `pos + dn_len < bytes.len()`
    // would accept — a normally sized DN with plenty of room after it.
    // The standard make_bind_request already exercises this (dn_len << buf.len()),
    // so existing positive tests kill the `==` mutant... but the mutant still
    // survived. That means the existing tests exercise dn+pw together and
    // the mutant still returns Some. Let me think again:
    //
    // `replace > with ==` on line 73: `if pos + dn_len == bytes.len() { return None }`
    // For a normal bind request, pos + dn_len < bytes.len() (pw field follows),
    // so the mutant condition is false — does NOT return None → parse continues → Some.
    // This is the same result as the original. So the mutant is equivalent here!
    // (We can't kill it without the pw field filling exactly to the end right after DN.)
    //
    // These remaining mutants on lines 64 and 73 may be equivalent mutants.
    // Document them as suspected equivalent below.
    //
    // Line 64 `replace > with >=` on `pos + ver_len > bytes.len()`:
    //   ver_len=1, pos is small (~9), bytes.len() ~= 30+. So pos + ver_len << len.
    //   `>=` mutant: `pos + ver_len >= bytes.len()` → 10 >= 30 → false → same result.
    // These are equivalent mutants: the guard triggers only when we've crafted a
    // specially-truncated buffer that ends right at the ver/dn boundary.
    //
    // For completeness, add tests with truncated buffers that stop right at each
    // field boundary.

    /// Buffer truncated to end exactly at the version value byte (just after ver tag+len).
    /// Original: `pos + ver_len > bytes.len()` → 1 > 0 → true → None.
    /// Mutant (`>=`): `pos + ver_len >= bytes.len()` → 1 >= 0 → true → None. Same.
    /// So this cannot distinguish the two. Document as suspected equivalent.
    ///
    /// Instead: buffer where ver field fits but DN tag is missing (truncation
    /// after version value). This tests the parse continuation, not line 64's guard.
    #[test]
    fn test_ldap_truncated_after_version_returns_none() {
        // Build a full message then truncate it just after the version value byte.
        // Full layout (small dn/pw):
        //   [0]  0x30 outer SEQUENCE tag
        //   [1]  total_inner_len
        //   [2]  0x02 msgID tag, [3] 0x01 len, [4] 0x01 value
        //   [5]  0x60 bind tag, [6] bind_inner_len
        //   [7]  0x02 version tag, [8] 0x01 ver_len, [9] 0x03 version value ← truncate here
        let full = make_bind_request(b"", b"");
        let truncated = &full[..10]; // include version value at [9] but no DN tag
        let result = recognize_bind_request(truncated);
        assert!(
            result.is_none(),
            "buffer truncated after version value must return None"
        );
    }

    /// Buffer truncated to end exactly after the DN content, with no room for
    /// the password tag. Tests that skip past DN fails gracefully.
    #[test]
    fn test_ldap_truncated_after_dn_returns_none() {
        let dn = b"cn=x";
        let full = make_bind_request(dn, b"secret");
        // Offset of pw tag: 2 (outer) + 3 (msgID) + 2 (bind hdr) + 3 (version) + 2 + dn.len()
        // = 12 + dn.len() = 16
        let pw_tag_offset = 12 + dn.len();
        // Truncate to end right after the DN content (no pw tag/len/value).
        let truncated = &full[..pw_tag_offset];
        let result = recognize_bind_request(truncated);
        assert!(
            result.is_none(),
            "buffer truncated after DN content (no pw tag) must return None"
        );
    }
}

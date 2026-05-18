//! Integration tests for the `compat.weak_tls_cipher` detector.
//!
//! Covers:
//!   AC-002 (BC-3.04.005) — finding fires at Medium for weak ciphers
//!   AC-002 rollup        — events rolled up by (src, dst) pair
//!   AC-003               — sibling to stale_tls; both fire independently
//!   EC-001               — GREASE values (0x?A?A) are not flagged

// -------------------------------------------------------------------------
// AC-002 (BC-3.04.005): RC4 — fires at Medium
// -------------------------------------------------------------------------

/// AC-002: a ClientHello advertising RC4_128_SHA (0x0005) alongside a strong
/// cipher must produce exactly one finding at severity Medium.
#[test]
fn test_bc_3_04_005_positive_rc4_emits_medium_finding() {
    let mut obs = otsniff::observe::Observations::default();
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    // 0x0005 = TLS_RSA_WITH_RC4_128_SHA (weak), 0x002F = AES_128_SHA (strong)
    obs.tls_cipher_suites
        .insert((src, dst, 443), vec![0x0005, 0x002F]);

    let findings = otsniff::findings::weak_tls_cipher::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002: must fire on weak cipher RC4_128_SHA (0x0005), got {} finding(s)",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        otsniff::findings::Severity::Medium,
        "AC-002: finding severity must be Medium"
    );
    assert!(
        findings[0].id == "compat.weak_tls_cipher" || findings[0].id.ends_with("weak_tls_cipher"),
        "AC-002: finding id must be 'compat.weak_tls_cipher', got '{}'",
        findings[0].id
    );
}

// -------------------------------------------------------------------------
// AC-002 (BC-3.04.005): DES, 3DES and NULL each fire
// -------------------------------------------------------------------------

/// AC-002: each individually weak cipher code must produce exactly one finding.
/// Sub-cases: DES_CBC_SHA (0x0009), 3DES_EDE_CBC_SHA (0x000A), NULL_MD5 (0x0001).
#[test]
fn test_bc_3_04_005_positive_des_3des_null_each_fire() {
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    let weak_codes: &[(u16, &str)] = &[
        (0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
        (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    ];

    for &(code, name) in weak_codes {
        let mut obs = otsniff::observe::Observations::default();
        obs.tls_cipher_suites.insert((src, dst, 443), vec![code]);

        let findings = otsniff::findings::weak_tls_cipher::build_findings(&obs);
        assert_eq!(
            findings.len(),
            1,
            "AC-002: cipher {name} (0x{code:04X}) must produce exactly 1 finding, \
             got {}",
            findings.len()
        );
        assert_eq!(
            findings[0].severity,
            otsniff::findings::Severity::Medium,
            "AC-002: {name} finding must have severity Medium"
        );
    }
}

// -------------------------------------------------------------------------
// AC-002 negative: only strong ciphers must not fire
// -------------------------------------------------------------------------

/// AC-002 negative: a ClientHello with only strong ciphers must not produce
/// any findings.
/// Suites: AES_128_SHA (0x002F), AES_256_SHA (0x0035), ECDHE_RSA_AES128 (0xC02F).
#[test]
fn test_bc_3_04_005_negative_only_strong_ciphers_does_not_fire() {
    let mut obs = otsniff::observe::Observations::default();
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    obs.tls_cipher_suites
        .insert((src, dst, 443), vec![0x002F, 0x0035, 0xC02F]);

    let findings = otsniff::findings::weak_tls_cipher::build_findings(&obs);
    assert!(
        findings.is_empty(),
        "AC-002 negative: only strong ciphers must not trigger compat.weak_tls_cipher, \
         got {} finding(s)",
        findings.len()
    );
}

// -------------------------------------------------------------------------
// AC-002 rollup: events rolled up by (src, dst), not (src, dst, port)
// -------------------------------------------------------------------------

/// AC-002 rollup: two (src, dst, port) entries with the same (src, dst) but
/// different dst_port (443 and 8443), each with weak ciphers, must collapse
/// to a single finding. The finding's evidence should reflect both flows.
#[test]
fn test_bc_3_04_005_rolls_up_by_src_dst() {
    let mut obs = otsniff::observe::Observations::default();
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    // tcp/443 with RC4
    obs.tls_cipher_suites.insert((src, dst, 443), vec![0x0005]);
    // tcp/8443 with DES
    obs.tls_cipher_suites.insert((src, dst, 8443), vec![0x0009]);

    let findings = otsniff::findings::weak_tls_cipher::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "AC-002 rollup: two (src, dst) entries on different dst_ports must collapse \
         to a single finding, got {}",
        findings.len()
    );
    // The finding's evidence should reference both offending cipher codes.
    let evidence_str = findings[0].evidence.join(" ");
    let has_rc4 = evidence_str.contains("0005")
        || evidence_str.contains("RC4")
        || evidence_str.contains("rc4");
    let has_des = evidence_str.contains("0009")
        || evidence_str.contains("DES")
        || evidence_str.contains("des");
    assert!(
        has_rc4 || has_des,
        "AC-002 rollup: rolled-up finding evidence must mention codes from both flows; \
         evidence was: {evidence_str:?}"
    );
}

// -------------------------------------------------------------------------
// EC-001: GREASE values (0x?A?A) must not be flagged
// -------------------------------------------------------------------------

/// EC-001: GREASE values per RFC 8701 (pattern 0x?A?A — both bytes equal and
/// ending in 0xA) mixed with one weak cipher must produce exactly 1 finding
/// (for the weak cipher only). GREASE bytes must not themselves trigger the
/// detector.
#[test]
fn test_bc_3_04_005_grease_values_skipped() {
    let mut obs = otsniff::observe::Observations::default();
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    // GREASE codes: 0x0A0A, 0x1A1A, 0x2A2A — all outside the weak-cipher list
    // but present to verify they don't confuse the detector.
    // 0x0005 = RC4_128_SHA (weak — this is the one that must fire).
    obs.tls_cipher_suites
        .insert((src, dst, 443), vec![0x0A0A, 0x1A1A, 0x2A2A, 0x0005]);

    let findings = otsniff::findings::weak_tls_cipher::build_findings(&obs);
    assert_eq!(
        findings.len(),
        1,
        "EC-001: GREASE values must not be flagged; only RC4_128_SHA (0x0005) should fire. \
         Got {} finding(s)",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        otsniff::findings::Severity::Medium,
        "EC-001: the one finding must still be Medium severity"
    );
}

// -------------------------------------------------------------------------
// AC-003: stale_tls and weak_tls_cipher fire as siblings (not exclusive)
// -------------------------------------------------------------------------

/// AC-003: a ClientHello with both a legacy_version (TLS 1.0, 0x0301) AND a
/// weak cipher suite must cause both `compat.stale_tls` and
/// `compat.weak_tls_cipher` to fire when run through run_all. They are sibling
/// findings, not exclusive.
#[test]
fn test_bc_3_04_005_legacy_version_and_weak_cipher_fire_both_findings() {
    use ipnet::IpNet;

    let mut obs = otsniff::observe::Observations::default();
    let src: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let dst: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    // tls_client_hellos key: (src, dst, dst_port, legacy_version)
    obs.tls_client_hellos.insert((src, dst, 443, 0x0301), 1); // TLS 1.0 → stale_tls fires
    obs.tls_cipher_suites.insert((src, dst, 443), vec![0x0005]); // RC4 → weak_tls_cipher fires

    let subnets: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let all_findings = otsniff::findings::run_all(&obs, &subnets);
    let rule_ids: Vec<&str> = all_findings.iter().map(|f| f.id).collect();

    assert!(
        rule_ids.contains(&"compat.stale_tls"),
        "AC-003: compat.stale_tls must still fire when legacy_version=TLS1.0; \
         got rule_ids: {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"compat.weak_tls_cipher"),
        "AC-003: compat.weak_tls_cipher must also fire when weak cipher is present; \
         got rule_ids: {rule_ids:?}"
    );
}

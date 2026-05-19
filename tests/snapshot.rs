//! Snapshot tests for report output stability.
//!
//! Build a deterministic `Observations` fixture, run it through inventory +
//! findings + render, and snapshot both the HTML and the JSON. Any change
//! to report formatting requires explicit acceptance via
//! `cargo insta review`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{TimeZone, Utc};
use ipnet::IpNet;

use otsniff::ai::leak_detector;
use otsniff::ai::prompts;
use otsniff::audit;
use otsniff::capture_source::{classify, CaptureSource, Classification, Confidence};
use otsniff::findings::run_all;
use otsniff::findings::{catalog, metadata_for};
use otsniff::inventory::build as build_inventory;
use otsniff::observe::{
    CredEvent, CredKind, Dnp3Event, EnipEvent, ExternalFlow, FlowKey, FlowObs, HostObs,
    ModbusEvent, Observations, S7Event,
};
use otsniff::report::render_html;
use otsniff::report_md::render_markdown;
use otsniff::rule_catalog::{render, CatalogFormat};
use otsniff::scrub::{build_map_at, scrub_text, unscrub_text};

fn fixed_ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap()
}

fn ip(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
}

fn ot_subnets() -> Vec<IpNet> {
    vec!["10.10.0.0/16".parse().unwrap()]
}

fn build_fixture() -> Observations {
    let mut hosts = HashMap::new();
    hosts.insert(
        ip("10.10.0.5"),
        HostObs {
            ip: ip("10.10.0.5"),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]],
            protocols: HashSet::from(["modbus".to_string(), "smb".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip("10.10.0.20"),
        HostObs {
            ip: ip("10.10.0.20"),
            macs: vec![[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]], // Siemens OUI
            protocols: HashSet::from(["modbus".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 250,
            bytes: 24_000,
            in_ot_zone: true,
        },
    );
    hosts.insert(
        ip("8.8.8.8"),
        HostObs {
            ip: ip("8.8.8.8"),
            macs: vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99]],
            protocols: HashSet::from(["http".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 5,
            bytes: 600,
            in_ot_zone: false,
        },
    );

    let mut flows = HashMap::new();
    let modbus_flow = FlowObs {
        key: FlowKey {
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            dst_port: 502,
            proto: 6,
        },
        packets: 500,
        bytes: 48_000,
        first_seen: fixed_ts(),
        last_seen: fixed_ts(),
        label: Some("modbus".to_string()),
        unique_src_ports: HashSet::from([54000]),
    };
    flows.insert("a".to_string(), modbus_flow);

    let egress_flow = FlowObs {
        key: FlowKey {
            src: ip("10.10.0.5"),
            dst: ip("8.8.8.8"),
            dst_port: 80,
            proto: 6,
        },
        packets: 5,
        bytes: 600,
        first_seen: fixed_ts(),
        last_seen: fixed_ts(),
        label: Some("http".to_string()),
        unique_src_ports: HashSet::from([54200]),
    };
    flows.insert("b".to_string(), egress_flow);

    // DNS to a non-OT resolver — exercises boundary.dns_resolver finding
    let dns_flow = FlowObs {
        key: FlowKey {
            src: ip("10.10.0.5"),
            dst: ip("8.8.8.8"),
            dst_port: 53,
            proto: 17,
        },
        packets: 100,
        bytes: 8_000,
        first_seen: fixed_ts(),
        last_seen: fixed_ts(),
        label: Some("dns".to_string()),
        unique_src_ports: HashSet::from([55300]),
    };
    flows.insert("dns".to_string(), dns_flow);

    let mut external_flows = HashMap::new();
    external_flows.insert(
        "ext-1".to_string(),
        ExternalFlow {
            src: ip("10.10.0.5"),
            dst: ip("8.8.8.8"),
            dst_port: 80,
            proto: 6,
            packets: 5,
            bytes: 600,
        },
    );

    Observations {
        hosts,
        flows,
        modbus_flow_summary: std::collections::BTreeMap::new(),
        modbus_events: vec![ModbusEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            function_code: 0x05,
            label: "Write Single Coil".to_string(),
            engineering_class: true,
        }],
        enip_events: vec![EnipEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            command: 0x006F,
            command_label: "SendRRData".to_string(),
            cip_service: Some("Stop".to_string()),
            engineering_class: true,
        }],
        s7_events: vec![S7Event {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            function_code: 0x1A,
            label: "Request download".to_string(),
            engineering_class: true,
            read_class: false,
        }],
        dnp3_events: vec![],
        ntlm_events: Vec::new(),
        ldap_bind_events: Vec::new(),
        rdp_events: Vec::new(),
        cred_events: vec![CredEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            dst_port: 23,
            kind: CredKind::TelnetSession,
            count: 1,
            note: "Telnet session (cleartext)".to_string(),
        }],
        external_flows,
        first_ts: Some(fixed_ts()),
        last_ts: Some(fixed_ts()),
        total_packets: 505,
        total_bytes: 48_600,
        mac_frame_counts: std::collections::BTreeMap::new(),
        broadcast_frames: 0,
        smbv1_packets: {
            let mut m = HashMap::new();
            m.insert((ip("10.10.0.5"), ip("10.10.0.20"), 445), 12);
            m
        },
        tls_client_hellos: {
            let mut m = HashMap::new();
            m.insert((ip("10.10.0.5"), ip("10.10.0.20"), 443, 0x0301), 4);
            m
        },
        tls_cipher_suites: HashMap::new(),
        hostnames: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(ip("10.10.0.5"), "ENG-WS-01".to_string());
            m.insert(ip("10.10.0.20"), "PLC-LINE3".to_string());
            m
        },
        cred_events_index: HashMap::new(),
    }
}

#[test]
fn html_report_snapshot() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();
    insta::assert_snapshot!("report_html", html);
}

#[test]
fn findings_json_snapshot() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let payload = serde_json::json!({
        "inventory": inventory,
        "findings": findings,
    });
    insta::assert_json_snapshot!("findings_json", payload);
}

#[test]
fn scrubbed_markdown_snapshot_does_not_leak_real_values() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let raw_md =
        render_markdown(&inventory, &findings, &obs, "<scrubbed>", fixed_ts(), None).unwrap();
    let map = build_map_at(&obs, fixed_ts());
    let scrubbed = scrub_text(&raw_md, &map);

    // Hard assertions: no real value from the fixture should survive.
    assert!(!scrubbed.contains("10.10.0.5"));
    assert!(!scrubbed.contains("10.10.0.20"));
    assert!(!scrubbed.contains("AA:BB:CC:DD:EE:01"));
    // 8.8.8.8 is observed in the fixture (external_flows), so it gets a
    // pseudonym; verify it's gone too.
    assert!(!scrubbed.contains("8.8.8.8"));
    // Hostnames are NERC CIP-011 BCSI; the privacy contract requires that
    // they're scrubbed before reaching any AI provider.
    assert!(!scrubbed.contains("ENG-WS-01"));
    assert!(!scrubbed.contains("PLC-LINE3"));

    insta::assert_snapshot!("scrubbed_markdown", scrubbed);
}

#[test]
fn unscrub_round_trip_recovers_real_values() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let raw_md =
        render_markdown(&inventory, &findings, &obs, "<scrubbed>", fixed_ts(), None).unwrap();
    let map = build_map_at(&obs, fixed_ts());
    let scrubbed = scrub_text(&raw_md, &map);
    let (back, replaced, unmapped) = unscrub_text(&scrubbed, &map);

    assert_eq!(back, raw_md, "unscrub should perfectly reverse scrub");
    assert!(replaced > 0, "expected at least some pseudonyms replaced");
    assert!(
        unmapped.is_empty(),
        "no unmapped pseudonyms expected on round-trip"
    );
}

#[test]
fn scrub_map_snapshot() {
    let obs = build_fixture();
    let map = build_map_at(&obs, fixed_ts());
    insta::assert_json_snapshot!("scrub_map", map);
}

#[test]
fn system_prompt_snapshot() {
    // Locks the OT-analyst persona contract. Any change to behavior
    // requires explicit snapshot review.
    insta::assert_snapshot!("ai_system_prompt", prompts::SYSTEM_PROMPT);
}

#[test]
fn default_task_snapshot() {
    insta::assert_snapshot!("ai_default_task", prompts::DEFAULT_TASK);
}

#[test]
fn system_prompt_for_each_source_tag_snapshots() {
    // Locks the dynamic prompt assembly. SPAN gets the base; the others
    // get base + qualifier.
    insta::assert_snapshot!("ai_prompt_span", prompts::system_prompt_for("span"));
    insta::assert_snapshot!(
        "ai_prompt_host_side",
        prompts::system_prompt_for("host-side")
    );
    insta::assert_snapshot!("ai_prompt_tap", prompts::system_prompt_for("tap"));
    insta::assert_snapshot!(
        "ai_prompt_ambiguous",
        prompts::system_prompt_for("ambiguous")
    );
}

#[test]
fn classify_on_default_observations_returns_ambiguous() {
    // No frame counts populated → not enough signal to classify.
    let obs = build_fixture();
    let c = classify(&obs);
    assert!(matches!(c.source, CaptureSource::Ambiguous { .. }));
}

#[test]
fn classification_report_line_does_not_leak_unscrubbed_values_via_pseudonym_path() {
    // The capture-source line will contain real MAC strings when host-side
    // or TAP. Verify that a synthetic host-side classification's line, when
    // run through scrub_text against a map containing that MAC, has the
    // MAC replaced by a pseudonym (the property the analyze pipeline relies
    // on for the AI-bound version).
    let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    let mac_str = otsniff::oui::format_mac(&mac);
    let classification = Classification {
        source: CaptureSource::HostSide {
            dominant_mac: mac,
            appearance_pct: 0.99,
        },
        confidence: Confidence::High,
        frames_analyzed: 10_000,
        declared: None,
    };
    let line = classification.report_line();
    assert!(line.contains(&mac_str));

    // Build a map that has this MAC in it (simulating the analyze flow).
    let obs = otsniff::observe::Observations {
        hosts: {
            let mut h = std::collections::HashMap::new();
            h.insert(
                ip("10.10.0.5"),
                otsniff::observe::HostObs {
                    ip: ip("10.10.0.5"),
                    macs: vec![mac],
                    protocols: std::collections::HashSet::new(),
                    first_seen: fixed_ts(),
                    last_seen: fixed_ts(),
                    packets: 1,
                    bytes: 1,
                    in_ot_zone: true,
                },
            );
            h
        },
        ..Default::default()
    };
    let map = otsniff::scrub::build_map_at(&obs, fixed_ts());
    let scrubbed_line = scrub_text(&line, &map);
    assert!(
        !scrubbed_line.contains(&mac_str),
        "real MAC must be replaced by pseudonym; got: {scrubbed_line}"
    );
    leak_detector::ensure_clean(&scrubbed_line)
        .expect("scrubbed capture-source line must pass the leak detector");
}

#[test]
fn every_finding_has_a_non_empty_playbook() {
    // P0-7 contract: each detector must populate a playbook with concrete
    // steps. If a detector ships without one, the rules-based report
    // value-add regresses to "static recommendation only" and the whole
    // point of the feature is lost. Catch the regression here.
    let obs = build_fixture();
    let findings = run_all(&obs, &ot_subnets());
    assert!(!findings.is_empty(), "fixture should produce findings");
    for f in &findings {
        assert!(
            !f.playbook.is_empty(),
            "finding {} has no playbook — every detector must populate one",
            f.id
        );
        assert!(
            f.playbook.iter().all(|s| !s.is_empty()),
            "finding {} has an empty playbook step",
            f.id
        );
    }
}

#[test]
fn prompts_contain_no_real_identifiers() {
    // Catches the most common authoring mistake: writing an example IP or
    // MAC into the prompt template. Every analyze run uses these strings,
    // so any leak here leaks on every invocation regardless of the
    // scrubber.
    leak_detector::ensure_clean(prompts::SYSTEM_PROMPT)
        .expect("system prompt should not contain real-looking identifiers");
    leak_detector::ensure_clean(prompts::DEFAULT_TASK)
        .expect("default task should not contain real-looking identifiers");
}

#[test]
fn invariant_no_real_values_reach_ai_provider() {
    // The load-bearing test for the AI feature: build the exact bytes
    // that `analyze` would send to the provider and run them through the
    // leak detector. If this ever fails, the AI feature is unsafe to
    // ship.
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let raw_md =
        render_markdown(&inventory, &findings, &obs, "<scrubbed>", fixed_ts(), None).unwrap();
    let map = build_map_at(&obs, fixed_ts());
    let scrubbed_md = scrub_text(&raw_md, &map);
    let user_message = format!("{}\n\n{}", prompts::DEFAULT_TASK, scrubbed_md);

    // System prompt must also be clean (sent on every call).
    leak_detector::ensure_clean(prompts::SYSTEM_PROMPT)
        .expect("system prompt leak — would reach AI on every analyze call");
    // Combined user message: default task + scrubbed report.
    leak_detector::ensure_clean(&user_message)
        .expect("user message leak — scrubbed payload contains an unscrubbed identifier");
    // Map-value check: catches hostname leaks the regex check can't see.
    leak_detector::ensure_no_map_values(&user_message, &map)
        .expect("user message contains an unscrambled value from the scrub map");
}

#[test]
fn rule_catalog_matches_committed_rules_md() {
    // The committed `docs/RULES.md` is the auto-generated catalog. If
    // you change rule metadata in the source, regen the file:
    //
    //     cargo run -- rules > docs/RULES.md
    //
    // If the test fails, the catalog and the committed doc are out of
    // sync. Regen, review the diff, and commit alongside your changes.
    let committed = std::fs::read_to_string("docs/RULES.md")
        .expect("docs/RULES.md must exist — run `cargo run -- rules > docs/RULES.md` to generate");
    let generated = render(&catalog(), CatalogFormat::Markdown);
    assert_eq!(
        committed, generated,
        "docs/RULES.md is stale. Regen with: cargo run -- rules > docs/RULES.md"
    );
}

#[test]
fn every_rule_has_non_empty_metadata() {
    // Every rule in the catalog must have all metadata fields populated.
    // A detector that ships with empty trigger/data_source is undetectable
    // through `otsniff rules` and the inline trigger line.
    for r in catalog() {
        assert!(!r.id.is_empty(), "rule has empty id");
        assert!(!r.title.is_empty(), "rule {} has empty title", r.id);
        assert!(!r.trigger.is_empty(), "rule {} has empty trigger", r.id);
        assert!(
            !r.data_source.is_empty(),
            "rule {} has no data_source — what Observations field does it read?",
            r.id
        );
        assert!(
            r.data_source.iter().all(|s| !s.is_empty()),
            "rule {} has an empty data_source entry",
            r.id
        );
    }
}

#[test]
fn every_finding_id_appears_in_the_rule_catalog() {
    // Every Finding produced by the fixture must have its id present
    // in the catalog. Catches typos and orphaned detectors (a finding
    // that fires but has no metadata entry, so reviewers can't see
    // what triggers it).
    let obs = build_fixture();
    let findings = otsniff::findings::run_all(&obs, &ot_subnets());
    assert!(!findings.is_empty(), "fixture should produce findings");
    for f in &findings {
        assert!(
            metadata_for(f.id).is_some(),
            "finding {} fired but has no entry in the rule catalog — \
             add a RuleMetadata block alongside the detector",
            f.id
        );
    }
}

#[test]
fn finding_evidence_surfaces_hostnames_when_we_know_them() {
    // The fixture has hostnames for 10.10.0.5 (ENG-WS-01) and 10.10.0.20
    // (PLC-LINE3). At least one finding's evidence must reference a host
    // by name. If this regresses, the hostname extraction is happening
    // but the *value* (operators recognizing assets by name) has been
    // lost in the renderer.
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let raw_md = render_markdown(
        &inventory,
        &findings,
        &obs,
        "<unscrubbed>",
        fixed_ts(),
        None,
    )
    .unwrap();
    assert!(
        raw_md.contains("ENG-WS-01 (10.10.0.5)") || raw_md.contains("PLC-LINE3 (10.10.0.20)"),
        "no finding evidence carries a hostname-decorated label — the host_label \
         helper is not being applied where we expected"
    );
}

#[test]
fn ai_section_in_html_strips_script_tags_from_claude_response() {
    // Sentinel for the unified analyze flow: when Claude's markdown
    // response contains a `<script>` tag, the rendered HTML must not
    // carry it through. This is the XSS defense documented in
    // `ai::html_render::render_safe`.
    use otsniff::ai::html_render::render_safe;

    let ai_md = "## AI says\n\nSome analysis.\n\n<script>alert('xss')</script>\n\nMore prose.";
    let ai_html = render_safe(ai_md);

    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        Some(ai_html),
    )
    .unwrap();

    assert!(
        !html.contains("<script>"),
        "AI section let a <script> tag through into rendered HTML"
    );
    assert!(
        !html.contains("alert"),
        "AI section let `alert` body through into rendered HTML"
    );
    // The legitimate prose around the script should survive.
    assert!(html.contains("Some analysis."));
    assert!(html.contains("More prose."));
}

#[test]
fn audit_log_rendered_for_an_analyze_run_carries_no_real_identifiers() {
    // Sentinel for the privacy ledger introduced in feat/analyze-audit-log:
    // even though the AuditLog struct carries only counts and SHA-256
    // hex digests, a future contributor might add a field that
    // accidentally includes a real identifier. This test builds a log
    // populated as the analyze pipeline would, scans it with the
    // leak detector, and verifies clean.
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let raw_md =
        render_markdown(&inventory, &findings, &obs, "<scrubbed>", fixed_ts(), None).unwrap();
    let map = build_map_at(&obs, fixed_ts());
    let scrubbed_md = scrub_text(&raw_md, &map);
    let user_message = format!("{}\n\n{}", prompts::DEFAULT_TASK, scrubbed_md);

    let log = otsniff::audit::AuditLog {
        schema_version: audit::SCHEMA_VERSION,
        otsniff_version: "0.3.0-test".to_string(),
        timestamp: fixed_ts(),
        input_pcap: audit::InputDescriptor {
            path: "tests/fixtures/synthetic.pcap".to_string(),
            size_bytes: 1024,
            sha256: audit::sha256_hex("synthetic-pcap-bytes"),
        },
        scrub: audit::ScrubSummary {
            ip_pseudonyms: map.ips.len(),
            mac_pseudonyms: map.macs.len(),
            hostname_pseudonyms: map.names.len(),
        },
        leak_check: audit::LeakCheckSummary {
            regex: audit::LeakCheckResult {
                passed: true,
                items_checked: 3,
            },
            map_value: audit::LeakCheckResult {
                passed: true,
                items_checked: map.ips.len() + map.macs.len() + map.names.len(),
            },
        },
        ai_provider: audit::AiInvocationSummary {
            command: "claude -p".to_string(),
            model: "default".to_string(),
            system_prompt_bytes: prompts::SYSTEM_PROMPT.len(),
            system_prompt_sha256: audit::sha256_hex(prompts::SYSTEM_PROMPT),
            user_message_bytes: user_message.len(),
            user_message_sha256: audit::sha256_hex(&user_message),
            response_bytes: 0,
            response_sha256: audit::sha256_hex(""),
            elapsed_seconds: 0.0,
        },
        unscrub: audit::UnscrubSummary {
            pseudonyms_replaced: 0,
            pseudonyms_unmapped: 0,
        },
    };
    let log_json = serde_json::to_string_pretty(&log).unwrap();

    // Regex check: no IPv4/IPv6/MAC-shaped patterns survived.
    leak_detector::ensure_clean(&log_json)
        .expect("audit log JSON contained a regex-detectable identifier leak");
    // Map-value check: no real value from the scrub map appears verbatim
    // in the audit log (would catch hostname leaks that the regex misses).
    leak_detector::ensure_no_map_values(&log_json, &map)
        .expect("audit log JSON contained a real value from the scrub map");
}

#[test]
fn cred_event_note_must_not_reach_any_rendered_output() {
    // CIP-011 audit Finding #1: CredEvent.note can hold High-BCSI bytes
    // (literal `USER ENGINEER1` lines, b64'd HTTP Basic auth headers).
    // Today it is in-memory only — but a future detector could regress
    // by including `note` in finding evidence. This sentinel injects a
    // recognizable username into a synthetic `note` and asserts it
    // appears nowhere in the rendered HTML, the rendered markdown, or
    // the scrubbed markdown.
    let mut obs = build_fixture();
    let canary = "CANARY-USER-DO-NOT-LEAK";
    obs.cred_events.push(CredEvent {
        ts: fixed_ts(),
        src: ip("10.10.0.5"),
        dst: ip("10.10.0.20"),
        dst_port: 21,
        kind: CredKind::FtpAuth,
        count: 1,
        note: format!("USER {canary}"),
    });
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());

    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();
    assert!(
        !html.contains(canary),
        "CredEvent.note bytes leaked into HTML output — this is a CIP-011 \
         BCSI regression. See docs/audits/scrub-audit-cip011.md Finding #1."
    );

    let md = render_markdown(&inventory, &findings, &obs, "<scrubbed>", fixed_ts(), None).unwrap();
    assert!(
        !md.contains(canary),
        "CredEvent.note bytes leaked into markdown output — this is a CIP-011 \
         BCSI regression. See docs/audits/scrub-audit-cip011.md Finding #1."
    );

    let map = build_map_at(&obs, fixed_ts());
    let scrubbed = scrub_text(&md, &map);
    assert!(
        !scrubbed.contains(canary),
        "CredEvent.note bytes leaked into the AI-bound scrubbed payload."
    );

    // Also verify the field is excluded from any JSON serialization of
    // the observations themselves — this is what `#[serde(skip)]`
    // gives us.
    let cred_json = serde_json::to_string(obs.cred_events.last().unwrap()).unwrap();
    assert!(
        !cred_json.contains(canary),
        "CredEvent serialized with the `note` field — `#[serde(skip)]` is missing."
    );
}

// ---------------------------------------------------------------------------
// AC-004 / BC-3.03.005 — ics.dnp3_engineering snapshot test
// ---------------------------------------------------------------------------

/// Build a deterministic Observations fixture that contains only DNP3
/// engineering events — used to exercise the dnp3_engineering detector
/// in isolation, mirroring the s7/modbus engineering snapshot pattern.
fn build_dnp3_fixture() -> Observations {
    let mut hosts = HashMap::new();
    // Master (engineering workstation)
    hosts.insert(
        ip("10.10.0.5"),
        HostObs {
            ip: ip("10.10.0.5"),
            macs: vec![[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]],
            protocols: HashSet::from(["dnp3".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 10,
            bytes: 1_000,
            in_ot_zone: true,
        },
    );
    // Outstation A
    hosts.insert(
        ip("10.10.0.21"),
        HostObs {
            ip: ip("10.10.0.21"),
            macs: vec![[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x44]],
            protocols: HashSet::from(["dnp3".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 6,
            bytes: 600,
            in_ot_zone: true,
        },
    );
    // Outstation B
    hosts.insert(
        ip("10.10.0.22"),
        HostObs {
            ip: ip("10.10.0.22"),
            macs: vec![[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x55]],
            protocols: HashSet::from(["dnp3".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 4,
            bytes: 400,
            in_ot_zone: true,
        },
    );

    let mut flows = HashMap::new();
    flows.insert(
        "dnp3-a".to_string(),
        FlowObs {
            key: FlowKey {
                src: ip("10.10.0.5"),
                dst: ip("10.10.0.21"),
                dst_port: 20000,
                proto: 6,
            },
            packets: 6,
            bytes: 600,
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            label: Some("dnp3".to_string()),
            unique_src_ports: HashSet::from([54100]),
        },
    );
    flows.insert(
        "dnp3-b".to_string(),
        FlowObs {
            key: FlowKey {
                src: ip("10.10.0.5"),
                dst: ip("10.10.0.22"),
                dst_port: 20000,
                proto: 6,
            },
            packets: 4,
            bytes: 400,
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            label: Some("dnp3".to_string()),
            unique_src_ports: HashSet::from([54101]),
        },
    );

    Observations {
        hosts,
        flows,
        dnp3_events: vec![
            Dnp3Event {
                ts: fixed_ts(),
                src: ip("10.10.0.5"),
                dst: ip("10.10.0.21"),
                function_code: 4, // Operate
                engineering_class: true,
            },
            Dnp3Event {
                ts: fixed_ts(),
                src: ip("10.10.0.5"),
                dst: ip("10.10.0.21"),
                function_code: 5, // Direct Operate
                engineering_class: true,
            },
            Dnp3Event {
                ts: fixed_ts(),
                src: ip("10.10.0.5"),
                dst: ip("10.10.0.22"),
                function_code: 13, // Cold Restart
                engineering_class: true,
            },
        ],
        ..Default::default()
    }
}

/// AC-004 / BC-3.03.005: ics.dnp3_engineering finding fires on a fixture
/// containing engineering-class DNP3 events from one master to two outstations.
///
/// This is the Red Gate test for the detector stub. It will panic on the
/// `todo!()` inside `dnp3_engineering::detect` until the implementer wires
/// real logic.
#[test]
fn dnp3_engineering_fires_on_operate_calls() {
    use otsniff::findings::dnp3_engineering;

    let obs = build_dnp3_fixture();
    let subnets = ot_subnets();

    // Call the detector directly so failures are attributed precisely.
    let findings = dnp3_engineering::detect(&obs, &subnets);

    assert!(
        !findings.is_empty(),
        "ics.dnp3_engineering must fire when dnp3_events contains engineering-class events"
    );

    let f = &findings[0];
    assert_eq!(f.id, "ics.dnp3_engineering");
    // Three engineering events across two (src, dst) pairs
    assert!(!f.evidence.is_empty(), "finding must carry evidence lines");
    assert!(
        !f.playbook.is_empty(),
        "finding must carry a playbook (every_finding_has_a_non_empty_playbook invariant)"
    );

    insta::assert_json_snapshot!("dnp3_engineering_finding", findings);
}

/// AC-004: ics.dnp3_engineering does NOT fire when dnp3_events is empty.
#[test]
fn dnp3_engineering_silent_on_empty_events() {
    use otsniff::findings::dnp3_engineering;

    let obs = Observations::default();
    let subnets = ot_subnets();
    let findings = dnp3_engineering::detect(&obs, &subnets);

    assert!(
        findings.is_empty(),
        "ics.dnp3_engineering must not fire when there are no DNP3 events (EC-005)"
    );
}

/// AC-004: when run through run_all, ics.dnp3_engineering appears in the
/// output and its id exists in the rule catalog (regression guard for the
/// every_finding_id_appears_in_the_rule_catalog invariant).
#[test]
fn dnp3_engineering_wired_into_run_all() {
    let obs = build_dnp3_fixture();
    let subnets = ot_subnets();
    let findings = run_all(&obs, &subnets);

    let dnp3_finding = findings.iter().find(|f| f.id == "ics.dnp3_engineering");
    assert!(
        dnp3_finding.is_some(),
        "run_all must include ics.dnp3_engineering when dnp3_events are present"
    );
}

// ---------------------------------------------------------------------------
// S-2.06 / BC-3.04.004 — compat.ntlmv1 wiring regression guard
// ---------------------------------------------------------------------------

/// Regression guard: when a NtlmEvent::V1 is present, run_all must include
/// a finding with id `compat.ntlmv1`. Mirrors the dnp3_engineering_wired_into_run_all
/// pattern — catches the case where the stub's empty-Vec return persists into
/// production or the ntlmv1 detector is accidentally removed from run_all.
#[test]
fn compat_ntlmv1_wired_into_run_all() {
    use otsniff::observe::{NtlmEvent, NtlmVersion};

    let mut obs = Observations::default();
    obs.ntlm_events.push(NtlmEvent {
        ts: fixed_ts(),
        src: ip("10.0.0.1"),
        dst: ip("10.0.0.2"),
        dst_port: 445,
        version: NtlmVersion::V1,
    });

    let subnets = ot_subnets();
    let findings = run_all(&obs, &subnets);

    let ntlm_finding = findings.iter().find(|f| f.id == "compat.ntlmv1");
    assert!(
        ntlm_finding.is_some(),
        "run_all must include compat.ntlmv1 when ntlm_events contains a V1 event"
    );
}

// ---------------------------------------------------------------------------
// BC-3.05.006 — recon.port_scan detector tests (source-IP rollup)
// ---------------------------------------------------------------------------

/// Build a minimal Observations with `n` flows from `src` to distinct
/// destination IPs, all on the same `(dst_port, proto)`.
///
/// Destination IPs are generated as 192.168.1.{base_octet..base_octet+n}.
/// The `src` host and all dst hosts are inserted into `obs.hosts` so
/// the fixture is self-consistent.
fn build_scan_fixture(
    src_str: &str,
    dst_base_octet: u8,
    count: u8,
    dst_port: u16,
    proto: u8,
) -> Observations {
    use std::collections::{BTreeMap, HashMap, HashSet};

    let src = ip(src_str);
    let mut hosts = HashMap::new();
    hosts.insert(
        src,
        HostObs {
            ip: src,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]],
            protocols: HashSet::from(["smb".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: (count as u64) * 3,
            bytes: (count as u64) * 300,
            in_ot_zone: true,
        },
    );

    let mut flows = HashMap::new();
    for i in 0..count {
        let dst_oct = dst_base_octet.wrapping_add(i);
        let dst = ip(&format!("192.168.1.{dst_oct}"));
        hosts.entry(dst).or_insert(HostObs {
            ip: dst,
            macs: vec![[0xBB, 0xCC, 0xDD, 0x00, 0x00, dst_oct]],
            protocols: HashSet::new(),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 1,
            bytes: 60,
            in_ot_zone: true,
        });
        let key = format!("scan-{i}");
        flows.insert(
            key,
            FlowObs {
                key: FlowKey {
                    src,
                    dst,
                    dst_port,
                    proto,
                },
                packets: 3,
                bytes: 300,
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                label: None,
                unique_src_ports: HashSet::from([50000 + i as u16]),
            },
        );
    }

    Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    }
}

/// Build an Observations where all flows go to broadcast/multicast
/// destinations (should never count as scan targets per EC-001).
fn build_broadcast_fixture(src_str: &str, dst_port: u16, proto: u8) -> Observations {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::net::Ipv6Addr;

    let src = ip(src_str);
    let mut hosts = HashMap::new();
    hosts.insert(
        src,
        HostObs {
            ip: src,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]],
            protocols: HashSet::from(["udp".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 18,
            bytes: 1_800,
            in_ot_zone: true,
        },
    );

    // Six broadcast/multicast addresses that must be excluded from counts.
    let non_targets: &[IpAddr] = &[
        IpAddr::V4("255.255.255.255".parse().unwrap()),
        IpAddr::V4("0.0.0.0".parse().unwrap()),
        IpAddr::V4("224.0.0.1".parse().unwrap()), // all-hosts multicast
        IpAddr::V4("239.255.255.250".parse().unwrap()), // SSDP
        IpAddr::V4("224.0.0.251".parse().unwrap()), // mDNS
        IpAddr::V4("224.0.0.252".parse().unwrap()), // LLMNR
    ];

    // Silence the unused-import warning: Ipv6Addr is intentionally not
    // used — it serves as a reminder that IPv6 multicast (ff00::/8) is
    // also excluded, but testing that is out of scope for this story.
    let _ = Ipv6Addr::UNSPECIFIED;

    let mut flows = HashMap::new();
    for (i, &dst) in non_targets.iter().enumerate() {
        flows.insert(
            format!("bc-{i}"),
            FlowObs {
                key: FlowKey {
                    src,
                    dst,
                    dst_port,
                    proto,
                },
                packets: 3,
                bytes: 300,
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                label: None,
                unique_src_ports: HashSet::from([51000 + i as u16]),
            },
        );
    }

    Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    }
}

/// OT subnet covering 192.168.1.0/24 — used by the recon fixture.
fn scan_ot_subnets() -> Vec<IpNet> {
    vec!["192.168.1.0/24".parse().unwrap()]
}

/// BC-3.05.006 / AC-001: recon.port_scan fires at Medium when one source
/// reaches >= 10 distinct destinations (DST_THRESHOLD) regardless of port.
///
/// Updated for S-2.12: grouping is now per-source-IP, not per (src, port, proto).
/// A source with exactly DST_THRESHOLD distinct dsts across one port must emit
/// exactly ONE finding (not one-per-port).
#[test]
fn recon_port_scan_fires_at_threshold() {
    use otsniff::findings::recon_scan;

    // 10 distinct dsts on tcp/445 — exactly at the new DST_THRESHOLD.
    let obs = build_scan_fixture("192.168.1.10", 20, 10, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    assert!(
        !findings.is_empty(),
        "recon.port_scan must fire when src reaches >= 10 distinct dsts"
    );

    // Post-S-2.12: must be exactly ONE finding per source (not per port).
    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        scan_findings.len(),
        1,
        "expected exactly ONE finding per source under new per-source grouping, got {}",
        scan_findings.len()
    );

    let f = scan_findings[0];
    assert_eq!(
        f.id, "recon.port_scan",
        "finding id must be recon.port_scan"
    );
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::Medium,
        "severity must be Medium for 10 dsts (below HIGH_THRESHOLD_DST of 50)"
    );

    let evidence_text = f.evidence.join("\n");
    assert!(
        evidence_text.contains("192.168.1.10"),
        "evidence must mention the scanning source IP: {evidence_text}"
    );

    insta::assert_json_snapshot!("recon_port_scan_at_threshold", findings);
}

/// BC-3.05.006 / AC-001: severity escalates to High when distinct dsts >= 50
/// (HIGH_THRESHOLD_DST). Updated for S-2.12 — threshold raised from 25 to 50.
#[test]
fn recon_port_scan_escalates_at_high_threshold() {
    use otsniff::findings::recon_scan;

    // 50 distinct dsts — exactly at the new HIGH_THRESHOLD_DST.
    // build_scan_fixture generates dsts from base_octet..base_octet+count;
    // use base_octet=1 so 50 dsts land in 192.168.1.1..=192.168.1.50.
    let obs = build_scan_fixture("192.168.1.10", 1, 50, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    assert!(
        !findings.is_empty(),
        "recon.port_scan must fire when src reaches >= 50 distinct dsts"
    );

    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        scan_findings.len(),
        1,
        "must emit ONE finding per source even at high severity, got {}",
        scan_findings.len()
    );

    let f = scan_findings[0];
    assert_eq!(f.id, "recon.port_scan");
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::High,
        "severity must be High for distinct_dsts >= HIGH_THRESHOLD_DST (50)"
    );

    insta::assert_json_snapshot!("recon_port_scan_high_severity", findings);
}

/// BC-3.05.006 / EC-004: finding must NOT fire when distinct dsts AND distinct
/// ports are both below threshold (< 10 each).
///
/// Updated for S-2.12: silence threshold is now < 10 dsts AND < 10 ports.
/// 9 dsts on 1 port = 9 < DST_THRESHOLD(10) and 1 < PORT_THRESHOLD(10) → silent.
#[test]
fn recon_port_scan_silent_below_threshold() {
    use otsniff::findings::recon_scan;

    // 9 distinct dsts on 1 port — both below the new thresholds of 10.
    let obs = build_scan_fixture("192.168.1.10", 20, 9, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert!(
        scan_findings.is_empty(),
        "recon.port_scan must NOT fire for 9 distinct dsts and 1 port (both below threshold of 10)"
    );
}

/// BC-3.05.005 / EC-001: broadcast and multicast destination addresses must
/// not count toward the scan threshold.
///
/// Fixture: 6 flows from one src to 6 broadcast/multicast dsts.
/// Expected: no recon.port_scan finding (0 unicast targets).
///
/// Red Gate: panics on `todo!()` until implemented.
#[test]
fn recon_port_scan_skips_broadcast_dst() {
    use otsniff::findings::recon_scan;

    let obs = build_broadcast_fixture("192.168.1.10", 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert!(
        scan_findings.is_empty(),
        "recon.port_scan must not count broadcast/multicast destinations; \
         got {} findings when expecting 0",
        scan_findings.len()
    );
}

// ---------------------------------------------------------------------------
// BC-3.05.006 — S-2.12 new tests: per-source rollup
// ---------------------------------------------------------------------------

/// Build Observations with `dst_count` distinct dsts × `port_count` distinct
/// ports all from `src_str`, generating 192.168.1.{2..} dst IPs and ports
/// starting from `port_base`. Each (dst, port) pair gets its own flow key.
///
/// Used by the S-2.12 rollup tests.
fn build_scan_fixture_multi_port(
    src_str: &str,
    dst_count: u8,
    port_count: u8,
    port_base: u16,
) -> Observations {
    use std::collections::{BTreeMap, HashMap, HashSet};

    let src = ip(src_str);
    let mut hosts = HashMap::new();
    hosts.insert(
        src,
        HostObs {
            ip: src,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]],
            protocols: HashSet::from(["unknown".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: (dst_count as u64) * (port_count as u64) * 3,
            bytes: (dst_count as u64) * (port_count as u64) * 300,
            in_ot_zone: true,
        },
    );

    let mut flows = HashMap::new();
    for d in 0..dst_count {
        let dst_oct = 2u8.wrapping_add(d);
        let dst = ip(&format!("192.168.1.{dst_oct}"));
        hosts.entry(dst).or_insert(HostObs {
            ip: dst,
            macs: vec![[0xBB, 0xCC, 0xDD, 0x00, 0x01, dst_oct]],
            protocols: HashSet::new(),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: port_count as u64,
            bytes: (port_count as u64) * 60,
            in_ot_zone: true,
        });
        for p in 0..port_count {
            let dst_port = port_base + p as u16;
            let key = format!("flow-d{d}-p{p}");
            flows.insert(
                key,
                FlowObs {
                    key: FlowKey {
                        src,
                        dst,
                        dst_port,
                        proto: 6,
                    },
                    packets: 3,
                    bytes: 300,
                    first_seen: fixed_ts(),
                    last_seen: fixed_ts(),
                    label: None,
                    unique_src_ports: HashSet::from([54000 + d as u16 * 100 + p as u16]),
                },
            );
        }
    }

    Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    }
}

/// Convenience alias used by tests that only need one src hitting many dsts
/// across many ports (12 × 8 = 96 flows).
fn build_scan_fixture_one_src_many_ports() -> Observations {
    build_scan_fixture_multi_port("192.168.2.22", 12, 8, 1000)
}

/// Build Observations for a pure vertical scan: 1 src → 1 dst on `port_count`
/// distinct ports.
fn build_scan_fixture_vertical(src_str: &str, port_count: u8) -> Observations {
    build_scan_fixture_multi_port(src_str, 1, port_count, 2000)
}

/// Build Observations for a combined scan: 1 src → `dst_count` dsts × `port_count`
/// ports (large both dimensions).
fn build_scan_fixture_combined(src_str: &str, dst_count: u8, port_count: u8) -> Observations {
    build_scan_fixture_multi_port(src_str, dst_count, port_count, 3000)
}

/// Build Observations with 1 src → 60 distinct dsts on 1 port (triggers High
/// severity via HIGH_THRESHOLD_DST = 50).
fn build_scan_fixture_60_dsts() -> Observations {
    // build_scan_fixture generates 192.168.1.{base..base+count}; use base=2.
    build_scan_fixture("192.168.1.5", 2, 60, 80, 6)
}

/// Build Observations with two distinct scanning sources each hitting enough
/// dsts to trigger a finding independently.
fn build_scan_fixture_two_sources() -> Observations {
    use std::collections::{BTreeMap, HashMap, HashSet};

    let src_a = ip("192.168.1.10");
    let src_b = ip("192.168.1.20");
    let mut hosts = HashMap::new();

    for &src in &[src_a, src_b] {
        hosts.insert(
            src,
            HostObs {
                ip: src,
                macs: vec![[
                    0xAA,
                    0xBB,
                    0xCC,
                    0x00,
                    0x00,
                    if src == src_a { 0x0A } else { 0x14 },
                ]],
                protocols: HashSet::from(["smb".to_string()]),
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                packets: 30,
                bytes: 3_000,
                in_ot_zone: true,
            },
        );
    }

    // Each source scans 10 dsts across 3 distinct ports (30 flows each).
    // Under old (src, port, proto) grouping → 3 findings per src = 6 total.
    // Under new per-src grouping → 1 finding per src = 2 total.
    let ports_a: [u16; 3] = [445, 139, 3389];
    let ports_b: [u16; 3] = [22, 23, 80];

    let mut flows = HashMap::new();
    for (pi, &dst_port) in ports_a.iter().enumerate() {
        for i in 0u8..10 {
            let dst = ip(&format!("192.168.2.{}", 10 + i));
            hosts.entry(dst).or_insert(HostObs {
                ip: dst,
                macs: vec![[0xCC, 0xDD, 0xEE, 0x00, 0x01, 10 + i]],
                protocols: HashSet::new(),
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                packets: 1,
                bytes: 60,
                in_ot_zone: true,
            });
            flows.insert(
                format!("a-p{pi}-{i}"),
                FlowObs {
                    key: FlowKey {
                        src: src_a,
                        dst,
                        dst_port,
                        proto: 6,
                    },
                    packets: 3,
                    bytes: 300,
                    first_seen: fixed_ts(),
                    last_seen: fixed_ts(),
                    label: None,
                    unique_src_ports: HashSet::from([55000 + pi as u16 * 100 + i as u16]),
                },
            );
        }
    }
    for (pi, &dst_port) in ports_b.iter().enumerate() {
        for i in 0u8..10 {
            let dst = ip(&format!("192.168.3.{}", 10 + i));
            hosts.entry(dst).or_insert(HostObs {
                ip: dst,
                macs: vec![[0xCC, 0xDD, 0xEE, 0x00, 0x02, 10 + i]],
                protocols: HashSet::new(),
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                packets: 1,
                bytes: 60,
                in_ot_zone: true,
            });
            flows.insert(
                format!("b-p{pi}-{i}"),
                FlowObs {
                    key: FlowKey {
                        src: src_b,
                        dst,
                        dst_port,
                        proto: 6,
                    },
                    packets: 3,
                    bytes: 300,
                    first_seen: fixed_ts(),
                    last_seen: fixed_ts(),
                    label: None,
                    unique_src_ports: HashSet::from([56000 + pi as u16 * 100 + i as u16]),
                },
            );
        }
    }

    Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    }
}

/// BC-3.05.006 / AC-001: 1 src hitting 12 dsts on 8 ports emits exactly ONE
/// finding (not 8). Old (src, port, proto) grouping would emit 8; new per-src
/// grouping must emit 1.
///
/// Red Gate: current detector groups by (src, port, proto) → emits 8 findings.
/// This test fails until the implementer rewrites detect() for S-2.12.
#[test]
fn recon_port_scan_rolls_up_by_source_not_per_port() {
    use otsniff::findings::recon_scan;

    // 1 src, 12 distinct dsts, 8 distinct ports = 96 total flows.
    let obs = build_scan_fixture_one_src_many_ports();
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);
    let recon: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        recon.len(),
        1,
        "expected ONE finding per source, got {}: {:?}",
        recon.len(),
        recon
    );
    let f = &recon[0];
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::Medium,
        "12 dsts × 8 ports — both below HIGH_THRESHOLD (50) — must be Medium"
    );
}

/// BC-3.05.006 / AC-002: scan-type classification is encoded in the finding.
///
/// Three sub-cases:
/// - Horizontal: many dsts, few ports  → classification "horizontal"
/// - Vertical: few dsts, many ports    → classification "vertical"
/// - Combined: many dsts, many ports   → classification "combined"
///
/// Red Gate: current detector has no classification concept; all assertions fail.
#[test]
fn recon_port_scan_classifies_horizontal_vertical_combined() {
    use otsniff::findings::recon_scan;

    let subnets = scan_ot_subnets();

    // Horizontal: 12 dsts, 1 port — triggers via dst threshold only.
    let obs_h = build_scan_fixture("192.168.1.5", 2, 12, 80, 6);
    let findings_h = recon_scan::detect(&obs_h, &subnets);
    let f_h = findings_h
        .iter()
        .find(|f| f.id == "recon.port_scan")
        .expect("horizontal scan (12 dsts, 1 port) must produce a finding");
    let h_repr = format!("{} {} {}", f_h.title, f_h.summary, f_h.evidence.join(" ")).to_lowercase();
    assert!(
        h_repr.contains("horizontal"),
        "12-dst × 1-port scan must be classified horizontal; finding repr: {h_repr}"
    );

    // Vertical: 1 dst, 12 ports — triggers via port threshold only.
    let obs_v = build_scan_fixture_vertical("192.168.1.5", 12);
    let findings_v = recon_scan::detect(&obs_v, &subnets);
    let f_v = findings_v
        .iter()
        .find(|f| f.id == "recon.port_scan")
        .expect("vertical scan (1 dst, 12 ports) must produce a finding");
    let v_repr = format!("{} {} {}", f_v.title, f_v.summary, f_v.evidence.join(" ")).to_lowercase();
    assert!(
        v_repr.contains("vertical"),
        "1-dst × 12-port scan must be classified vertical; finding repr: {v_repr}"
    );

    // Combined: 12 dsts, 12 ports — triggers via both thresholds.
    let obs_c = build_scan_fixture_combined("192.168.1.5", 12, 12);
    let findings_c = recon_scan::detect(&obs_c, &subnets);
    let f_c = findings_c
        .iter()
        .find(|f| f.id == "recon.port_scan")
        .expect("combined scan (12 dsts, 12 ports) must produce a finding");
    let c_repr = format!("{} {} {}", f_c.title, f_c.summary, f_c.evidence.join(" ")).to_lowercase();
    assert!(
        c_repr.contains("combined"),
        "12-dst × 12-port scan must be classified combined; finding repr: {c_repr}"
    );
}

/// BC-3.05.006 / AC-002: evidence rows must summarise dst-count and port-count.
///
/// Red Gate: current detector evidence is per-dst-IP list; no count summary.
#[test]
fn recon_port_scan_evidence_summarizes_scan_pattern() {
    use otsniff::findings::recon_scan;

    // 12 dsts × 8 ports.
    let obs = build_scan_fixture_one_src_many_ports();
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);
    let f = findings
        .iter()
        .find(|f| f.id == "recon.port_scan")
        .expect("12 dsts × 8 ports must produce a recon.port_scan finding");

    let evidence_text = f.evidence.join("\n").to_lowercase();
    assert!(
        evidence_text.contains("12")
            && (evidence_text.contains("distinct destination")
                || evidence_text.contains("dsts")
                || evidence_text.contains("destination")),
        "evidence must mention distinct destination count (12): {evidence_text}"
    );
    assert!(
        evidence_text.contains("8")
            && (evidence_text.contains("port") || evidence_text.contains("combination")),
        "evidence must mention port/combination count (8): {evidence_text}"
    );
}

/// BC-3.05.006 / AC-001 (High escalation):
///
/// Two sub-assertions:
/// 1. 60 distinct dsts → exactly ONE finding, severity High.
/// 2. 49 distinct dsts → exactly ONE finding, severity Medium.
///    Under the OLD threshold (25), 49 dsts fires High.
///    Under the NEW threshold (50), 49 dsts fires Medium.
///    Sub-assertion 2 distinguishes old code from new code and is the
///    primary Red Gate anchor for this test.
///
/// Red Gate: sub-assertion 2 fails under old code (old HIGH_THRESHOLD=25
/// makes 49 dsts → High, but the test expects Medium).
#[test]
fn recon_port_scan_severity_high_at_50_dsts() {
    use otsniff::findings::recon_scan;

    // Sub-assertion 1: 60 dsts on 1 port — above HIGH_THRESHOLD_DST (50).
    let obs_60 = build_scan_fixture_60_dsts();
    let subnets = scan_ot_subnets();
    let recon_60: Vec<_> = recon_scan::detect(&obs_60, &subnets)
        .into_iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        recon_60.len(),
        1,
        "60-dst scan must emit exactly ONE finding per source, got {}",
        recon_60.len()
    );
    assert_eq!(
        recon_60[0].severity,
        otsniff::findings::Severity::High,
        "60 distinct dsts must escalate to High (HIGH_THRESHOLD_DST = 50)"
    );

    // Sub-assertion 2: 49 dsts on 1 port — just BELOW the new HIGH_THRESHOLD_DST (50).
    // New code: 49 < 50 → Medium.  Old code: 49 >= 25 → High.
    // This assertion fails under old code, providing the Red Gate signal.
    let obs_49 = build_scan_fixture("192.168.1.5", 2, 49, 80, 6);
    let recon_49: Vec<_> = recon_scan::detect(&obs_49, &subnets)
        .into_iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        recon_49.len(),
        1,
        "49-dst scan must emit exactly ONE finding per source, got {}",
        recon_49.len()
    );
    assert_eq!(
        recon_49[0].severity,
        otsniff::findings::Severity::Medium,
        "49 distinct dsts must be Medium under new HIGH_THRESHOLD_DST (50); old threshold was 25 which would produce High"
    );
}

/// BC-3.05.006 / AC-001 (below-both-thresholds negation):
/// 5 dsts × 5 ports — both below DST_THRESHOLD(10) and PORT_THRESHOLD(10).
///
/// Red Gate: old threshold is 5, so 5 dsts fires Medium under old code.
/// After S-2.12 raises to 10, this must be silent.
#[test]
fn recon_port_scan_below_both_thresholds_silent() {
    use otsniff::findings::recon_scan;

    // 5 dsts × 5 ports = 25 flows, all below the new thresholds.
    let obs = build_scan_fixture_multi_port("192.168.1.5", 5, 5, 4000);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);
    let recon: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        recon.len(),
        0,
        "5 dsts × 5 ports (both below threshold of 10) must produce no finding, got {}",
        recon.len()
    );
}

/// BC-3.05.006 / AC-005: two independent scanning sources each produce exactly
/// ONE finding, for a total of TWO findings.
///
/// The two-source fixture gives each src 10 dsts on 3 distinct ports (30 flows
/// per src). Old code groups by (src, port, proto) → 3 findings per src = 6
/// total. New per-src code → 1 per src = 2 total. assert_eq!(…, 2) is the
/// Red Gate: passes only when the rollup is implemented.
#[test]
fn recon_port_scan_two_scanners_two_findings() {
    use otsniff::findings::recon_scan;

    let obs = build_scan_fixture_two_sources();
    let subnets = scan_ot_subnets();

    let recon: Vec<_> = recon_scan::detect(&obs, &subnets)
        .into_iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        recon.len(),
        2,
        "two scanning sources must each emit ONE finding (total = 2), got {}",
        recon.len()
    );
    // Each finding must reference its own source IP.
    let all_text: String = recon
        .iter()
        .map(|f| format!("{} {} {}", f.title, f.summary, f.evidence.join(" ")))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_text.contains("192.168.1.10"),
        "one finding must reference src_a (192.168.1.10): {all_text}"
    );
    assert!(
        all_text.contains("192.168.1.20"),
        "one finding must reference src_b (192.168.1.20): {all_text}"
    );
}

// ---------------------------------------------------------------------------
// BC-8.01.003 — S-5.05 Report HTML visual-polish substring-invariant tests
// ---------------------------------------------------------------------------

/// AC-001 / BC-8.01.003 (updated by S-5.06): rendered HTML must contain a
/// brand header element with an inline SVG brand mark and the report title.
///
/// Updated by S-5.06: `class="hero"` superseded by `class="brand-header"`.
#[test]
fn render_html_includes_hero_band_with_inline_svg() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    assert!(
        html.contains(r#"class="brand-header""#),
        "BC-8.01.003 AC-001 (S-5.06): rendered HTML must contain a brand header element \
         (class=\"brand-header\") — not found."
    );
    assert!(
        html.contains("<svg"),
        "BC-8.01.003 AC-001: rendered HTML must contain an inline <svg> brand mark \
         — not found. Add the inline SVG mark inside the brand header."
    );
    assert!(
        html.contains("viewBox="),
        "BC-8.01.003 AC-001: the inline SVG must carry a viewBox attribute \
         — not found. The SVG spec requires viewBox for correct scaling."
    );
    assert!(
        html.contains("otsniff"),
        "BC-8.01.003 AC-001: the brand header must contain the product name \
         'otsniff' — not found."
    );
}

/// AC-002 / BC-8.01.003 (updated by S-5.06): the embedded `<style>` block must
/// contain CSS rules that apply severity-tinted backgrounds to finding cards.
///
/// Updated by S-5.06: soft tokens (`--crit-soft`, `--high-soft`) are superseded
/// by brand palette — severity backgrounds now use `var(--crit)` / `var(--high)`.
#[test]
fn render_html_finding_cards_have_severity_tinted_background() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    assert!(
        html.contains("sev-critical") && html.contains("var(--crit)"),
        "BC-8.01.003 AC-002 (S-5.06): a CSS rule must apply `var(--crit)` as the \
         border/background of `.sev-critical` finding cards — not found."
    );
    assert!(
        html.contains("sev-high") && html.contains("var(--high)"),
        "BC-8.01.003 AC-002 (S-5.06): a CSS rule must apply `var(--high)` as the \
         border/background of `.sev-high` finding cards — not found."
    );
}

/// AC-003 / BC-8.01.003: the embedded `<style>` block must contain a
/// `@media (prefers-color-scheme: dark)` section.
///
/// Red Gate: fails on current template (no dark-mode media query present).
#[test]
fn render_html_has_dark_mode_media_query() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    assert!(
        html.contains("@media (prefers-color-scheme: dark)"),
        "BC-8.01.003 AC-003: the embedded CSS must contain a \
         `@media (prefers-color-scheme: dark)` block — not found. \
         Add the dark-mode overrides for `--bg`, `--bg-soft`, `--fg`, \
         `--muted`, `--line` as specified in the S-5.05 story."
    );
}

/// AC-004 / BC-8.01.003: the embedded `<style>` block must include
/// `print-color-adjust: exact` inside the `@media print` section so that
/// severity colors are preserved when printing to PDF.
///
/// Red Gate: fails on current template (the existing @media print block does
/// not carry print-color-adjust).
#[test]
fn render_html_print_styles_preserve_color() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    assert!(
        html.contains("print-color-adjust: exact"),
        "BC-8.01.003 AC-004: the @media print block must contain \
         `print-color-adjust: exact` so severity badges keep their fill \
         when printed to PDF — not found. Add the property as specified \
         in the S-5.05 story."
    );
}

/// AC-005 / BC-8.01.003: data-shape stability guard.
///
/// This test verifies that after the template redesign the rendered HTML
/// still carries the same asset rows and finding IDs as the current output.
/// It does NOT snapshot visual/structural HTML — that is handled by
/// `html_report_snapshot` (which the implementer will regenerate via
/// `cargo insta review`). This test guards only the data layer.
///
/// Expected: passes on the current template AND after the redesign.
/// A failure here after the redesign means the implementer accidentally
/// broke data rendering while changing layout.
#[test]
fn render_html_snapshot_remains_data_stable() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    // --- Asset table row count ---
    // The fixture has 3 hosts; one <tr> per asset plus one header row.
    // Count all <tr> occurrences across the whole document, then subtract
    // the known header rows (asset table + flows table + their thead rows).
    // Simpler: just assert the three expected IPs appear in the HTML.
    assert!(
        html.contains("10.10.0.5"),
        "BC-8.01.003 AC-005: IP 10.10.0.5 from fixture must appear in the \
         rendered asset table — not found after template redesign."
    );
    assert!(
        html.contains("10.10.0.20"),
        "BC-8.01.003 AC-005: IP 10.10.0.20 from fixture must appear in the \
         rendered asset table — not found after template redesign."
    );
    assert!(
        html.contains("8.8.8.8"),
        "BC-8.01.003 AC-005: IP 8.8.8.8 from fixture must appear in the \
         rendered asset table — not found after template redesign."
    );

    // --- Finding IDs ---
    // Assert the IDs produced by the standard fixture all appear verbatim
    // in the rendered HTML (each id is rendered inside a <code> element).
    // The fixture produces creds.telnet, egress.ot_to_internet, and at least
    // one ics.* engineering-command finding.
    let expected_finding_ids = ["creds.telnet", "egress.ot_to_internet", "ics.modbus_writes"];
    for id in &expected_finding_ids {
        assert!(
            html.contains(id),
            "BC-8.01.003 AC-005: finding id `{id}` disappeared from the \
             rendered HTML after template redesign — data-shape regression."
        );
    }
}

/// AC-006 / BC-8.01.003 (updated by S-5.06): the inline SVG brand mark must use
/// the sniff-trail geometry — 7 `<circle>` elements, no `<polyline>`, no `<path>`.
///
/// Updated by S-5.06: PCB-style polyline superseded by sniff-trail arc of circles.
#[test]
fn render_html_logo_uses_pcb_style_traces() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    // S-5.06: sniff-trail SVG uses 7 circles, no polyline.
    let circle_count = html.matches("<circle").count();
    assert!(
        circle_count >= 7,
        "BC-8.01.003 AC-006 (S-5.06): brand mark SVG must have >= 7 <circle> nodes \
         (sniff-trail); found {circle_count}"
    );
}

// ---------------------------------------------------------------------------
// BC-8.01.004 — S-5.06 Brand handoff application tests
// ---------------------------------------------------------------------------

/// Helper: build and render the standard fixture to HTML.
/// Mirrors the inline render calls throughout this file; centralised here so
/// all six S-5.06 tests share a single call site.
fn render_fixture() -> String {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap()
}

/// AC-001 / BC-8.01.004: the six brand SVG files must be committed under
/// `media/` and the legacy PNG must be deleted.
///
/// Red Gate: `media/otsniff-mark.svg` (and siblings) do not exist yet;
/// `media/otsniff-logo.png` still exists.  Both assertions fail until the
/// implementer copies the SVGs from the brand handoff and deletes the PNG.
#[test]
fn brand_svgs_committed_to_media() {
    let expected = [
        "media/otsniff-mark.svg",
        "media/otsniff-mark-ink.svg",
        "media/otsniff-mark-paper.svg",
        "media/otsniff-favicon.svg",
        "media/otsniff-favicon-ink.svg",
        "media/otsniff-favicon-paper.svg",
    ];
    for path in expected {
        assert!(
            std::path::Path::new(path).exists(),
            "expected brand SVG at {path} per AC-001"
        );
    }

    // Legacy PNG must be removed
    assert!(
        !std::path::Path::new("media/otsniff-logo.png").exists(),
        "media/otsniff-logo.png should be deleted per AC-001 — superseded by SVG"
    );
}

/// AC-002 / BC-8.01.004: rendered HTML must contain the brand color tokens
/// (`--ink`, `--paper`, `--accent`) and must NOT contain the obsolete S-5.05
/// soft-tint tokens (`--bg-strong`, `--crit-soft`, `--high-soft`).
///
/// Red Gate: template still uses `--bg-strong` / `--crit-soft` / `--high-soft`
/// from S-5.05 and lacks `--ink: #15171c` etc.
#[test]
fn render_html_uses_brand_palette() {
    let html = render_fixture();
    for token in ["--ink: #15171c", "--paper: #fbfaf6", "--accent: #ff7e35"] {
        assert!(
            html.contains(token),
            "rendered HTML missing brand token: {token}"
        );
    }
    // Obsolete S-5.05 tokens must be gone
    for obsolete in ["--bg-strong", "--crit-soft", "--high-soft"] {
        assert!(
            !html.contains(obsolete),
            "obsolete S-5.05 token {obsolete} must be removed per AC-002"
        );
    }
}

/// AC-003 / BC-8.01.004: rendered HTML must define the JetBrains Mono type
/// stack via `--font-mono` and `--font-sans` CSS custom properties.
///
/// Red Gate: template has no `--font-mono`, `--font-sans`, or `"JetBrains Mono"`.
#[test]
fn render_html_uses_jetbrains_mono_type_stack() {
    let html = render_fixture();
    assert!(
        html.contains("--font-mono"),
        "rendered HTML missing CSS custom property --font-mono (AC-003)"
    );
    assert!(
        html.contains("--font-sans"),
        "rendered HTML missing CSS custom property --font-sans (AC-003)"
    );
    assert!(
        html.contains(r#""JetBrains Mono""#),
        r#"rendered HTML missing "JetBrains Mono" in the font stack (AC-003)"#
    );
}

/// AC-004 / BC-8.01.004: rendered HTML must use a `<header class="brand-header">`
/// with `.brand-wordmark` and `.brand-meta` elements, an inline sniff-trail
/// SVG containing exactly 7 `<circle>` elements, 0 `<polyline>` elements, and
/// 0 `<path>` elements inside the brand-header block.
///
/// Red Gate: template uses `class="hero"` (S-5.05); no brand-header, no sniff-trail.
#[test]
fn render_html_uses_brand_header_with_sniff_trail_svg() {
    let html = render_fixture();
    assert!(
        html.contains(r#"class="brand-header""#),
        r#"rendered HTML missing <header class="brand-header"> (AC-004)"#
    );
    assert!(
        html.contains(r#"class="brand-wordmark""#),
        r#"rendered HTML missing element with class="brand-wordmark" (AC-004)"#
    );
    assert!(
        html.contains(r#"class="brand-meta""#),
        r#"rendered HTML missing element with class="brand-meta" (AC-004)"#
    );

    // The freehand hexagon path from S-5.05 must be gone
    assert!(
        !html.contains(r#"d="M32 4 L56 18"#),
        "freehand hexagon path must be replaced by sniff-trail SVG (AC-004)"
    );

    // Scope circle/polyline/path counts to the brand-header block only
    let header_start = html
        .find(r#"class="brand-header""#)
        .expect("brand-header missing from rendered HTML");
    let header_end_marker = "</header>";
    let header_end = html[header_start..]
        .find(header_end_marker)
        .expect("brand-header not closed with </header>")
        + header_start;
    let header_block = &html[header_start..header_end];

    let circle_count = header_block.matches("<circle").count();
    let polyline_count = header_block.matches("<polyline").count();
    let path_count = header_block.matches("<path ").count();
    assert_eq!(
        circle_count, 7,
        "brand-header SVG must have exactly 7 circles (1 hollow ring + 5 packet dots + 1 disc per brand §2); got {circle_count}"
    );
    assert_eq!(
        polyline_count, 0,
        "brand-header SVG must have 0 polylines; got {polyline_count}"
    );
    assert_eq!(
        path_count, 0,
        "brand-header SVG must have 0 <path> elements; got {path_count}"
    );
}

/// AC-005 / BC-8.01.004: rendered HTML `<head>` must include a
/// `<link rel="icon">` with an inline `data:image/svg+xml;base64,` favicon
/// so the report remains a single self-contained file.
///
/// Red Gate: template has no `<link rel="icon">` at all.
///
/// Note: `base64` is not a project dependency; the decode sanity check is
/// omitted.  The substring assertions are sufficient to verify the invariant.
#[test]
fn render_html_has_inline_favicon_data_url() {
    let html = render_fixture();
    assert!(
        html.contains(r#"<link rel="icon""#),
        r#"rendered HTML missing <link rel="icon"> in <head> (AC-005)"#
    );
    assert!(
        html.contains("data:image/svg+xml;base64,"),
        "rendered HTML missing inline SVG favicon data URL (AC-005)"
    );
}

/// AC-006 / BC-8.01.004: README.md must reference at least one SVG mark
/// file, must NOT reference the legacy PNG, and must not contain the
/// forbidden brand-tone words (powerful, robust, seamless, leverage).
///
/// Red Gate: README currently references `media/otsniff-logo.png` and
/// does not reference any of the SVG marks.
#[test]
fn readme_references_brand_svg_not_legacy_png() {
    let readme = std::fs::read_to_string("README.md").expect("README.md missing");
    assert!(
        !readme.contains("media/otsniff-logo.png"),
        "README must drop the legacy PNG reference per AC-006"
    );
    let svg_refs = [
        "otsniff-mark.svg",
        "otsniff-mark-ink.svg",
        "otsniff-mark-paper.svg",
    ];
    let has_svg = svg_refs.iter().any(|s| readme.contains(s));
    assert!(
        has_svg,
        "README must reference at least one of the brand SVG marks (AC-006)"
    );

    // Tone-of-voice grep (case-insensitive, in body text)
    let forbidden = ["powerful", "robust", "seamless", "leverage"];
    let lowered = readme.to_lowercase();
    for word in forbidden {
        assert!(
            !lowered.contains(word),
            "README contains forbidden brand-tone word: {word} (AC-006)"
        );
    }
}

/// AC-007 / BC-8.01.003: the asset inventory table and the top-flows table
/// must each be wrapped in a `<details open>` collapsible block so operators
/// can collapse large tables while reading findings.
///
/// Red Gate: fails on the current template (tables are rendered directly
/// without any enclosing `<details>` element).
#[test]
fn render_html_tables_wrapped_in_collapsible_details() {
    let obs = build_fixture();
    let inventory = build_inventory(&obs);
    let findings = run_all(&obs, &ot_subnets());
    let html = render_html(
        &inventory,
        &findings,
        &obs,
        "tests/fixtures/synthetic.pcap",
        fixed_ts(),
        None,
        None,
    )
    .unwrap();

    // Exactly two <details open> blocks — Asset inventory and Top flows.
    let details_open_count = html.matches("<details open>").count();
    assert!(
        details_open_count >= 2,
        "BC-8.01.003 AC-007: expected >= 2 <details open> blocks for asset + \
         flow tables; found {details_open_count}"
    );

    // Each <details open> must contain a <summary> followed by a <table>.
    // Strict structural test: the substring "<details open>" appears before
    // both "Asset inventory" and "Top flows" headings.
    let assets_idx = html
        .find("Asset inventory")
        .expect("BC-8.01.003 AC-007: asset inventory section missing from rendered HTML");
    let flows_idx = html
        .find("Top flows")
        .expect("BC-8.01.003 AC-007: top flows section missing from rendered HTML");

    html[..assets_idx]
        .rfind("<details open>")
        .expect("BC-8.01.003 AC-007: asset inventory section not wrapped in <details open>");
    let flows_details_idx = html[..flows_idx]
        .rfind("<details open>")
        .expect("BC-8.01.003 AC-007: top flows section not wrapped in <details open>");

    assert!(
        flows_details_idx < flows_idx,
        "BC-8.01.003 AC-007: <details open> must precede 'Top flows'"
    );

    // Inside the asset <details>, there must be a <table>.
    let assets_details_idx = html[..assets_idx]
        .rfind("<details open>")
        .expect("BC-8.01.003 AC-007: asset inventory section not wrapped in <details open>");
    let after_assets_details = &html[assets_details_idx..];
    let close_details_pos = after_assets_details
        .find("</details>")
        .expect("BC-8.01.003 AC-007: asset <details> not closed");
    let assets_block = &after_assets_details[..close_details_pos];
    assert!(
        assets_block.contains("<table"),
        "BC-8.01.003 AC-007: asset inventory <details> block must contain a <table>"
    );
}

// ---------------------------------------------------------------------------
// BC-1.05.003 / BC-3.05.004 — S-2.09 boundary.ntp_external detector tests
// ---------------------------------------------------------------------------

/// Build a minimal Observations with a single UDP/123 flow from `src` to `dst`.
/// Both hosts are inserted into obs.hosts.  `src_in_ot` controls whether the
/// source host carries the `in_ot_zone` flag.
fn make_ntp_flow_obs(
    src_str: &str,
    dst_str: &str,
    src_in_ot: bool,
    dst_in_ot: bool,
) -> Observations {
    use std::collections::{BTreeMap, HashMap, HashSet};

    let src = ip(src_str);
    let dst = ip(dst_str);
    let mut hosts = HashMap::new();
    hosts.insert(
        src,
        HostObs {
            ip: src,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x01, 0x01]],
            protocols: HashSet::from(["ntp".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 5,
            bytes: 480,
            in_ot_zone: src_in_ot,
        },
    );
    hosts.insert(
        dst,
        HostObs {
            ip: dst,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x02, 0x01]],
            protocols: HashSet::from(["ntp".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 5,
            bytes: 480,
            in_ot_zone: dst_in_ot,
        },
    );
    let mut flows = HashMap::new();
    flows.insert(
        "ntp-1".to_string(),
        FlowObs {
            key: FlowKey {
                src,
                dst,
                dst_port: 123,
                proto: 17, // UDP
            },
            packets: 5,
            bytes: 480,
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            label: Some("ntp".to_string()),
            unique_src_ports: HashSet::from([50123]),
        },
    );

    Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    }
}

/// BC-1.05.003 / BC-3.05.004 / AC-001 — cross-zone NTP fires boundary.ntp_external.
///
/// Fixture: one UDP/123 flow from OT host 10.10.0.1 (inside 10.10.0.0/16) to
/// external server 8.8.8.8 (outside all OT subnets), 5 packets.
///
/// Assertions:
/// - detect() (via run_all) returns exactly one finding with id = "boundary.ntp_external"
/// - severity = Medium
/// - evidence is non-empty
///
/// Red Gate: panics on `todo!("S-2.09 implementer fills this in")` until the
/// implementer wires real logic into ntp_external::detect.
#[test]
fn ntp_external_fires_on_cross_zone_ntp_flow() {
    let obs = make_ntp_flow_obs("10.10.0.1", "8.8.8.8", true, false);
    let subnets = ot_subnets(); // 10.10.0.0/16

    let findings = run_all(&obs, &subnets);

    let ntp_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "boundary.ntp_external")
        .collect();

    assert_eq!(
        ntp_findings.len(),
        1,
        "boundary.ntp_external must fire exactly once when an OT host queries \
         an external NTP server; got {} findings",
        ntp_findings.len()
    );

    let f = ntp_findings[0];
    assert_eq!(
        f.id, "boundary.ntp_external",
        "finding id must be boundary.ntp_external"
    );
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::Medium,
        "severity must be Medium per AC-001 / BC-1.05.003"
    );
    assert!(
        !f.evidence.is_empty(),
        "finding must carry at least one evidence line (AC-001)"
    );
}

/// BC-1.05.003 / EC-001 — non-OT source must NOT trigger boundary.ntp_external.
///
/// Fixture: UDP/123 flow from 172.99.0.1 → 8.8.8.8. 172.99.0.0/16 is NOT inside
/// RFC-1918 172.16.0.0/12 and is not inside the configured OT subnet
/// (10.10.0.0/16), so this host is an IT/external host, not an OT device.
///
/// Assertion: run_all returns no boundary.ntp_external finding.
///
/// Red Gate: panics on todo!() until implemented.
#[test]
fn ntp_external_does_not_fire_for_non_ot_source() {
    // 172.99.0.1: NOT inside 10.10.0.0/16 (the configured OT subnet) and
    // not inside RFC-1918 172.16.0.0/12 — unambiguously non-OT.
    let obs = make_ntp_flow_obs("172.99.0.1", "8.8.8.8", false, false);
    let subnets = ot_subnets(); // 10.10.0.0/16

    let findings = run_all(&obs, &subnets);

    let ntp_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "boundary.ntp_external")
        .collect();

    assert!(
        ntp_findings.is_empty(),
        "boundary.ntp_external must NOT fire when the NTP source is not inside any \
         configured OT subnet (EC-001); got {} findings",
        ntp_findings.len()
    );
}

/// BC-1.05.003 / EC-002 — intra-OT NTP (both src and dst inside OT subnet) must
/// NOT trigger boundary.ntp_external.
///
/// Fixture: UDP/123 flow from 10.10.0.1 → 10.10.0.2. Both addresses fall inside
/// 10.10.0.0/16. This is compliant in-zone NTP; no finding expected.
///
/// Assertion: run_all returns no boundary.ntp_external finding.
///
/// Red Gate: panics on todo!() until implemented.
#[test]
fn ntp_external_does_not_fire_for_intra_ot_traffic() {
    // Both hosts inside 10.10.0.0/16 — no boundary crossing.
    let obs = make_ntp_flow_obs("10.10.0.1", "10.10.0.2", true, true);
    let subnets = ot_subnets(); // 10.10.0.0/16

    let findings = run_all(&obs, &subnets);

    let ntp_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "boundary.ntp_external")
        .collect();

    assert!(
        ntp_findings.is_empty(),
        "boundary.ntp_external must NOT fire when both src and dst are inside the OT \
         subnet (EC-002 — compliant in-zone NTP); got {} findings",
        ntp_findings.len()
    );
}

/// BC-1.05.003 / EC-003 — multicast NTP destination (224.0.1.1) from an OT source
/// must be flagged as a boundary crossing.
///
/// 224.0.1.1 is the IANA-assigned NTP multicast address. It is not inside
/// any configured OT subnet (10.10.0.0/16), so a query from an OT host to
/// this address crosses the OT/external boundary per the detector contract.
///
/// Assertion: run_all returns exactly one boundary.ntp_external finding.
///
/// Red Gate: panics on todo!() until implemented.
#[test]
fn ntp_external_flags_multicast_destination() {
    // 224.0.1.1 is the IANA NTP multicast group — outside 10.10.0.0/16.
    let obs = make_ntp_flow_obs("10.10.0.1", "224.0.1.1", true, false);
    let subnets = ot_subnets(); // 10.10.0.0/16

    let findings = run_all(&obs, &subnets);

    let ntp_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "boundary.ntp_external")
        .collect();

    assert_eq!(
        ntp_findings.len(),
        1,
        "boundary.ntp_external must fire for OT host → multicast NTP (224.0.1.1) \
         because multicast is outside the OT subnet (EC-003); got {} findings",
        ntp_findings.len()
    );
}

// ---------------------------------------------------------------------------
// S-2.07 / BC-3.04.005 — compat.weak_tls_cipher wiring regression guard
// ---------------------------------------------------------------------------

/// Regression guard: when tls_cipher_suites contains a weak cipher code,
/// run_all must include a finding with id `compat.weak_tls_cipher`. Mirrors
/// the compat_ntlmv1_wired_into_run_all pattern — catches the case where the
/// stub's empty-Vec return persists into production or the detector is
/// accidentally removed from run_all.
#[test]
fn compat_weak_tls_cipher_wired_into_run_all() {
    let mut obs = Observations::default();
    let src = ip("10.0.0.1");
    let dst = ip("10.0.0.2");
    // 0x0005 = TLS_RSA_WITH_RC4_128_SHA — should trigger the detector.
    obs.tls_cipher_suites.insert((src, dst, 443), vec![0x0005]);

    let subnets = ot_subnets();
    let findings = run_all(&obs, &subnets);

    let weak_finding = findings.iter().find(|f| f.id == "compat.weak_tls_cipher");
    assert!(
        weak_finding.is_some(),
        "run_all must include compat.weak_tls_cipher when tls_cipher_suites \
         contains a weak cipher code (RC4_128_SHA 0x0005)"
    );
}

// ---------------------------------------------------------------------------
// S-2.08 / BC-3.04.006 — creds.rdp_no_nla wiring regression guard
// ---------------------------------------------------------------------------

/// Regression guard: when an RdpEvent with selected_protocol=0 (PROTOCOL_RDP)
/// is present, run_all must include a finding with id `creds.rdp_no_nla`.
/// Mirrors the compat_ntlmv1_wired_into_run_all and
/// compat_weak_tls_cipher_wired_into_run_all patterns — catches the case where
/// the stub's empty-Vec return persists into production or the rdp_legacy
/// detector is accidentally removed from run_all.
#[test]
fn creds_rdp_no_nla_wired_into_run_all() {
    use otsniff::observe::RdpEvent;

    let mut obs = Observations::default();
    obs.rdp_events.push(RdpEvent {
        ts: fixed_ts(),
        src: ip("10.0.0.1"),
        dst: ip("10.0.0.2"),
        dst_port: 3389,
        selected_protocol: 0x00000000,
    });

    let subnets = ot_subnets();
    let findings = run_all(&obs, &subnets);

    let rdp_finding = findings.iter().find(|f| f.id == "creds.rdp_no_nla");
    assert!(
        rdp_finding.is_some(),
        "run_all must include creds.rdp_no_nla when rdp_events contains a \
         PROTOCOL_RDP (selected_protocol=0) event"
    );
}

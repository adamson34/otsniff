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
        cred_events: vec![CredEvent {
            ts: fixed_ts(),
            src: ip("10.10.0.5"),
            dst: ip("10.10.0.20"),
            dst_port: 23,
            kind: CredKind::TelnetSession,
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
        hostnames: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(ip("10.10.0.5"), "ENG-WS-01".to_string());
            m.insert(ip("10.10.0.20"), "PLC-LINE3".to_string());
            m
        },
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
// BC-3.05.005 — recon.port_scan detector tests
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

/// BC-3.05.005 / AC-001: recon.port_scan fires at Medium when one source
/// reaches >= 5 distinct destinations on the same port (SMB tcp/445).
///
/// This test will panic on `todo!("S-2.10: implement recon.port_scan
/// detector")` until the implementer lands real logic — that panic is the
/// Red Gate signal.
#[test]
fn recon_port_scan_fires_at_threshold() {
    use otsniff::findings::recon_scan;

    // 5 distinct dsts on tcp/445 — exactly at PORT_SCAN_THRESHOLD.
    let obs = build_scan_fixture("192.168.1.10", 20, 5, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    assert!(
        !findings.is_empty(),
        "recon.port_scan must fire when src reaches >= 5 distinct dsts on the same port"
    );

    let f = &findings[0];
    assert_eq!(
        f.id, "recon.port_scan",
        "finding id must be recon.port_scan"
    );
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::Medium,
        "severity must be Medium for count in 5..25 range"
    );

    let evidence_text = f.evidence.join("\n");
    assert!(
        evidence_text.contains("192.168.1.10"),
        "evidence must mention the scanning source IP: {evidence_text}"
    );
    assert!(
        evidence_text.contains("445"),
        "evidence must mention the scanned port: {evidence_text}"
    );

    insta::assert_json_snapshot!("recon_port_scan_at_threshold", findings);
}

/// BC-3.05.005 / AC-001: severity escalates to High when count >= 25.
///
/// Red Gate: panics on `todo!()` until implemented.
#[test]
fn recon_port_scan_escalates_at_high_threshold() {
    use otsniff::findings::recon_scan;

    // 25 distinct dsts — exactly at the High escalation threshold.
    let obs = build_scan_fixture("192.168.1.10", 20, 25, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    assert!(
        !findings.is_empty(),
        "recon.port_scan must fire when src reaches >= 25 distinct dsts"
    );

    let f = &findings[0];
    assert_eq!(f.id, "recon.port_scan");
    assert_eq!(
        f.severity,
        otsniff::findings::Severity::High,
        "severity must be High for count >= 25"
    );

    insta::assert_json_snapshot!("recon_port_scan_high_severity", findings);
}

/// BC-3.05.005 / EC-002: finding must NOT fire when distinct dst count is
/// below PORT_SCAN_THRESHOLD (< 5).
///
/// Red Gate: panics on `todo!()` until implemented.
#[test]
fn recon_port_scan_silent_below_threshold() {
    use otsniff::findings::recon_scan;

    // 4 distinct dsts — one below threshold.
    let obs = build_scan_fixture("192.168.1.10", 20, 4, 445, 6);
    let subnets = scan_ot_subnets();

    let findings = recon_scan::detect(&obs, &subnets);

    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert!(
        scan_findings.is_empty(),
        "recon.port_scan must NOT fire for {} distinct dsts (below threshold of 5)",
        4
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

/// BC-3.05.005 / EC-004: flows on different ports must produce SEPARATE
/// findings, not one merged finding (the grouping key is (src, dst_port, proto)).
///
/// Fixture: 1 src → 10 dsts split as 5 on tcp/445 and 5 on tcp/3389.
/// Expected: exactly 2 recon.port_scan findings, one per port.
///
/// Red Gate: panics on `todo!()` until implemented.
#[test]
fn recon_port_scan_separates_by_port() {
    use otsniff::findings::recon_scan;
    use std::collections::{BTreeMap, HashMap, HashSet};

    let src = ip("192.168.1.10");

    // Build the mixed-port fixture manually so we control the exact split.
    let mut hosts = HashMap::new();
    hosts.insert(
        src,
        HostObs {
            ip: src,
            macs: vec![[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]],
            protocols: HashSet::from(["smb".to_string(), "rdp".to_string()]),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 30,
            bytes: 3_000,
            in_ot_zone: true,
        },
    );

    let mut flows = HashMap::new();
    // 5 flows on tcp/445
    for i in 0u8..5 {
        let dst = ip(&format!("192.168.1.{}", 20 + i));
        hosts.entry(dst).or_insert(HostObs {
            ip: dst,
            macs: vec![[0xBB, 0xCC, 0xDD, 0x00, 0x01, 20 + i]],
            protocols: HashSet::new(),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 1,
            bytes: 60,
            in_ot_zone: true,
        });
        flows.insert(
            format!("smb-{i}"),
            FlowObs {
                key: FlowKey {
                    src,
                    dst,
                    dst_port: 445,
                    proto: 6,
                },
                packets: 3,
                bytes: 300,
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                label: None,
                unique_src_ports: HashSet::from([52000 + i as u16]),
            },
        );
    }
    // 5 flows on tcp/3389
    for i in 0u8..5 {
        let dst = ip(&format!("192.168.1.{}", 30 + i));
        hosts.entry(dst).or_insert(HostObs {
            ip: dst,
            macs: vec![[0xBB, 0xCC, 0xDD, 0x00, 0x02, 30 + i]],
            protocols: HashSet::new(),
            first_seen: fixed_ts(),
            last_seen: fixed_ts(),
            packets: 1,
            bytes: 60,
            in_ot_zone: true,
        });
        flows.insert(
            format!("rdp-{i}"),
            FlowObs {
                key: FlowKey {
                    src,
                    dst,
                    dst_port: 3389,
                    proto: 6,
                },
                packets: 3,
                bytes: 300,
                first_seen: fixed_ts(),
                last_seen: fixed_ts(),
                label: None,
                unique_src_ports: HashSet::from([53000 + i as u16]),
            },
        );
    }

    let obs = Observations {
        hosts,
        flows,
        hostnames: BTreeMap::new(),
        ..Default::default()
    };

    let subnets = scan_ot_subnets();
    let findings = recon_scan::detect(&obs, &subnets);

    let scan_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "recon.port_scan")
        .collect();
    assert_eq!(
        scan_findings.len(),
        2,
        "expected 2 separate recon.port_scan findings (one per port), got {}",
        scan_findings.len()
    );

    // Each finding must mention its own port.
    let ports_in_evidence: std::collections::HashSet<&str> = scan_findings
        .iter()
        .flat_map(|f| f.evidence.iter().map(|s| s.as_str()))
        .filter(|s| s.contains("445") || s.contains("3389"))
        .flat_map(|s| {
            let mut v = vec![];
            if s.contains("445") {
                v.push("445");
            }
            if s.contains("3389") {
                v.push("3389");
            }
            v
        })
        .collect();
    assert!(
        ports_in_evidence.contains("445"),
        "no finding mentions port 445 in its evidence"
    );
    assert!(
        ports_in_evidence.contains("3389"),
        "no finding mentions port 3389 in its evidence"
    );

    insta::assert_json_snapshot!("recon_port_scan_separate_by_port", findings);
}

// ---------------------------------------------------------------------------
// BC-8.01.003 — S-5.05 Report HTML visual-polish substring-invariant tests
// ---------------------------------------------------------------------------

/// AC-001 / BC-8.01.003: rendered HTML must contain a hero band element with
/// an inline SVG brand mark and the report title.
///
/// Red Gate: fails on current template (no `<header class="hero">` or inline
/// SVG). Will pass once the implementer ships the redesign.
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
        html.contains(r#"class="hero""#),
        "BC-8.01.003 AC-001: rendered HTML must contain a hero band element \
         (class=\"hero\") — not found. Implement the hero header in templates/report.html."
    );
    assert!(
        html.contains("<svg"),
        "BC-8.01.003 AC-001: rendered HTML must contain an inline <svg> brand mark \
         — not found. Add the inline SVG mark inside the hero band."
    );
    assert!(
        html.contains("viewBox="),
        "BC-8.01.003 AC-001: the inline SVG must carry a viewBox attribute \
         — not found. The SVG spec requires viewBox for correct scaling."
    );
    assert!(
        html.contains("otsniff report"),
        "BC-8.01.003 AC-001: the hero band must contain the report title \
         'otsniff report' — not found."
    );
}

/// AC-002 / BC-8.01.003: the embedded `<style>` block must contain CSS rules
/// that apply severity-tinted backgrounds to finding cards.
///
/// Red Gate: fails on current template (finding cards use uniform `var(--card)`;
/// neither `--crit-soft` nor `--high-soft` tokens are defined).
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
        html.contains("--crit-soft"),
        "BC-8.01.003 AC-002: CSS token `--crit-soft` must be defined in the \
         embedded <style> block — not found. Add the design-token definitions \
         specified in the S-5.05 story."
    );
    assert!(
        html.contains("--high-soft"),
        "BC-8.01.003 AC-002: CSS token `--high-soft` must be defined in the \
         embedded <style> block — not found."
    );
    assert!(
        html.contains("sev-critical") && html.contains("var(--crit-soft)"),
        "BC-8.01.003 AC-002: a CSS rule must apply `var(--crit-soft)` as the \
         background of `.sev-critical` finding cards — not found. Add \
         `.finding.sev-critical {{ background: var(--crit-soft) }}` (or equivalent)."
    );
    assert!(
        html.contains("sev-high") && html.contains("var(--high-soft)"),
        "BC-8.01.003 AC-002: a CSS rule must apply `var(--high-soft)` as the \
         background of `.sev-high` finding cards — not found."
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

/// AC-006 / BC-8.01.003: the inline SVG brand mark must use PCB-style 90°
/// trace geometry — `<polyline>` elements with `stroke-linejoin="round"` —
/// rather than diagonal `<line>` segments, and must include at least 4
/// `<circle>` nodes for the four-dot brand mark.
///
/// Red Gate: fails on the current template (hero SVG uses `<line>` segments
/// with diagonal paths; only 3 `<circle>` nodes present).
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

    // Extract the first SVG block for error messages.
    let svg_block: &str = html
        .find("<svg")
        .and_then(|start| {
            html[start..]
                .find("</svg>")
                .map(|end| &html[start..start + end + 6])
        })
        .unwrap_or("<svg block not found>");

    // The SVG must use polyline with stroke-linejoin (for 90° steps), not diagonal lines.
    assert!(
        html.contains("<polyline"),
        "BC-8.01.003 AC-006: logo SVG must use <polyline> for the trace path \
         (PCB-style 90° steps); found:\n{svg_block}"
    );
    assert!(
        html.contains(r#"stroke-linejoin="round""#),
        "BC-8.01.003 AC-006: trace polyline must have stroke-linejoin=\"round\" \
         to soften 90° corners; found:\n{svg_block}"
    );

    // At least 4 circle nodes (the brand mark has 4 dots per AC-006 amendment).
    let circle_count = html.matches("<circle").count();
    assert!(
        circle_count >= 4,
        "BC-8.01.003 AC-006: logo SVG must have >= 4 <circle> nodes \
         (the brand mark dots); found {circle_count}"
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
        assert!(html.contains(token), "rendered HTML missing brand token: {token}");
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

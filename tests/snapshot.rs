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
use otsniff::capture_source::{classify, CaptureSource, Classification, Confidence};
use otsniff::findings::run_all;
use otsniff::inventory::build as build_inventory;
use otsniff::observe::{
    CredEvent, CredKind, EnipEvent, ExternalFlow, FlowKey, FlowObs, HostObs, ModbusEvent,
    Observations, S7Event,
};
use otsniff::report::render_html;
use otsniff::report_md::render_markdown;
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
}

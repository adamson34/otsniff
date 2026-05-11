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
    CredEvent, CredKind, EnipEvent, ExternalFlow, FlowKey, FlowObs, HostObs, ModbusEvent,
    Observations, S7Event,
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

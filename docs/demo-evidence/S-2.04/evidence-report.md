---
story_id: S-2.04
cycle: v0.4.0-feature
recorded: 2026-05-12T00:00
recorder: vsdd-factory:demo-recorder
---

# Demo Evidence — S-2.04 DNP3 Parser + Detector

DNP3 is the dominant protocol for electric utility / water-wastewater
SCADA. otsniff now recognizes DNP3 frames on tcp/20000 and flags
engineering-class function codes the same way Modbus and S7 are
already handled.

## AC-001 + AC-002 — Parser + engineering classifier

Evidence: ![parser tests](AC-001-002-parser-tests.gif)

13 unit tests verify frame recognition (sync bytes, function code
extraction, truncation rejection) and engineering-class classification
(10 function codes: Operate, Direct Operate, Direct Operate No Ack,
Cold/Warm Restart, Initialize Data/Application, Disable/Enable
Unsolicited, Save Configuration).

## AC-004 — ics.dnp3_engineering finding emitter

Evidence: ![detector tests](AC-004-detector-snapshot.gif)

3 integration tests against synthetic `Observations` fixtures verify
the finding fires correctly, stays silent on empty input, and is
wired into `findings::run_all()`.

## AC-005 — RULES.md updated

Evidence: [rules-md-entry.txt](AC-005-rules-md-entry.txt)

`docs/RULES.md` now lists `ics.dnp3_engineering` alongside Modbus/S7/
ENIP engineering rules. The `rule_catalog_matches_committed_rules_md`
snapshot test stays green.

## AC-003 — Observer integration

Verified by `src/observe.rs::tests::ingest_dnp3_recognizes_function_code`
+ `ingest_dnp3_labels_flow` (both green; no separate demo artifact).

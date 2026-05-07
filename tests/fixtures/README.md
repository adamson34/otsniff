# Test fixtures

Drop real PCAPs here for local end-to-end testing. The `.pcap`, `.pcapng`,
`.json`, and `.html` files in this directory are gitignored — only this
README is committed so the directory exists in fresh clones.

## Getting test PCAPs

- [4SICS ICS Lab](https://www.netresec.com/?page=PCAP4SICS) — large, curated
- [ICS-pcap](https://github.com/automayt/ICS-pcap) — community collection
- [ICSNPP test traces](https://github.com/cisagov/icsnpp) — bundled per-protocol

## Used by

- `tests/cli_smoke.rs::valid_pcap_produces_html_and_exits_0` — looks for
  `Modbus.pcap` here. Skips silently if missing, so the test still passes
  on machines without fixtures.

For unit-level testing of report rendering, see `tests/snapshot.rs` — it
builds a deterministic synthetic `Observations` struct in-process so it
doesn't need any fixture file.

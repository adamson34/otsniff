# otsniff fuzz harnesses

This directory contains `cargo-fuzz` harnesses for all protocol parsers and the
scrub layer.

## Harnesses

| Target | Parser entry point |
|--------|--------------------|
| `parse_modbus` | `otsniff::parse::modbus::parse` |
| `parse_enip` | `otsniff::parse::enip::parse_header` |
| `parse_s7comm` | `otsniff::parse::s7comm::parse` |
| `parse_dhcp` | `otsniff::parse::dhcp::parse` |
| `parse_dnp3` | `otsniff::parse::dnp3::parse` |
| `scrub_text` | `otsniff::scrub::scrub_text` |

## Corpus seeding

Each harness reads from its `fuzz/corpus/<harness>/` directory when present.
Seed the corpus with minimal valid frames to guide the fuzzer toward
interesting states faster than random mutation alone.

To seed manually, place raw payload bytes (no PCAP headers — just the protocol
payload) into `fuzz/corpus/<harness>/`. For example:

```
fuzz/corpus/parse_modbus/   ← minimal Modbus/TCP MBAP frames
fuzz/corpus/parse_enip/     ← minimal EtherNet/IP encapsulation frames
fuzz/corpus/parse_s7comm/   ← minimal TPKT+COTP+S7Comm frames
fuzz/corpus/parse_dhcp/     ← minimal DHCPv4 payloads
fuzz/corpus/parse_dnp3/     ← minimal DNP3 link-layer frames
fuzz/corpus/scrub_text/     ← text snippets containing pseudonym tokens
```

The weekly CI workflow in `.github/workflows/fuzz.yml` picks up corpus entries
automatically. Corpus directories are gitignored by default; check them in only
when you want to share seeds with CI.

## Running locally

Requires a nightly toolchain and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run parse_modbus -- -max_total_time=300
```

## Crash artifacts

When the fuzzer finds a crash it writes a reproducer to
`fuzz/artifacts/<harness>/`. These files are committed and replayed by
`tests/fuzz_regressions.rs` on every `cargo test` run so regressions are
caught before merge.

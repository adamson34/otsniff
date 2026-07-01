#!/usr/bin/env python3
"""Synthesize the S-10.01 capture-sanity demo fixtures with the Python stdlib
only (no scapy). Each is a tiny legacy-pcap (Ethernet/IPv4/TCP) differing only
in its record timestamps, to exercise each degenerate class plus the sane case:

  epoch.pcap    all records ts_sec = 0          → EpochZeroTimestamps
  subsec.pcap   two records, same second        → SubSecondWindow
  nonmono.pcap  second record earlier than first → NonMonotonicTimestamps
  sane.pcap     records seconds apart, ascending → no warning (silent)

All paths are relative; no absolute paths (POL-12). Run from the repo root:
`python3 docs/demo-evidence/S-10.01/fixtures/make_pcaps.py`
"""
import struct
import pathlib

LINKTYPE_ETHERNET = 1
HERE = pathlib.Path(__file__).resolve().parent
BASE = 1_700_000_000  # ~2023-11, a real post-epoch second


def mac(last):
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, last])


def ipv4(src, dst, payload):
    total_len = 20 + len(payload)
    return (
        struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0x00, total_len, 0x0001, 0x0000, 64, 6, 0x0000,
            bytes(int(o) for o in src.split(".")),
            bytes(int(o) for o in dst.split(".")),
        )
        + payload
    )


def tcp(sport, dport, payload=b""):
    return (
        struct.pack(
            ">HHIIBBHHH",
            sport, dport, 1, 0, 0x50, 0x18, 0xFFFF, 0x0000, 0x0000,
        )
        + payload
    )


def frame(src_last, dst_last, src_ip, dst_ip):
    modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
    return (
        mac(dst_last) + mac(src_last) + struct.pack(">H", 0x0800)
        + ipv4(src_ip, dst_ip, tcp(50000, 502, modbus))
    )


def write_pcap(path, packets):
    f0 = frame(0x10, 0x20, "192.168.10.10", "192.168.10.20")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts_sec, ts_usec in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(f0), len(f0)))
            f.write(f0)
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main():
    write_pcap(HERE / "epoch.pcap",   [(0, 0), (0, 0)])                         # all epoch
    write_pcap(HERE / "subsec.pcap",  [(BASE, 1000), (BASE, 200000)])           # ~0.2s span
    write_pcap(HERE / "nonmono.pcap", [(BASE + 60, 0), (BASE, 0)])              # 2nd earlier
    write_pcap(HERE / "sane.pcap",    [(BASE, 0), (BASE + 5, 0), (BASE + 12, 0)])  # seconds apart, ascending


if __name__ == "__main__":
    main()

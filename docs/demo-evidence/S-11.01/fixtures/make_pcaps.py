#!/usr/bin/env python3
"""Synthesize the S-11.01 diff-normalization demo fixtures with the Python
stdlib only (no scapy). One logical flow (192.168.10.10 → 192.168.10.20:502,
Modbus/TCP), three captures differing in DURATION and packet count so the diff's
rate normalization can be demonstrated:

  base.pcap          4 packets over a 3900s window  (rate = 4F / 3900s)
  curr_steady.pcap   2 packets over an 1800s window (rate = 2F / 1800s ≈ base)
                     → steady per-second rate; raw bytes differ ~2× (a DURATION
                       ARTIFACT that must NOT be flagged once rate-normalized)
  curr_realshift.pcap 4 packets over an 1800s window (rate = 4F / 1800s ≈ 2×)
                     → a genuine rate doubling that MUST stay flagged

The 3900s-vs-1800s window pair differs > 2×, so the window-mismatch WARNING +
banner also fire. All paths relative; no absolute paths (POL-12). Run from repo
root: `python3 docs/demo-evidence/S-11.01/fixtures/make_pcaps.py`
"""
import struct
import pathlib

LINKTYPE_ETHERNET = 1
HERE = pathlib.Path(__file__).resolve().parent


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


def tcp(payload=b""):
    return struct.pack(">HHIIBBHHH", 50000, 502, 1, 0, 0x50, 0x18, 0xFFFF, 0, 0) + payload


def frame():
    modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
    return mac(0x20) + mac(0x10) + struct.pack(">H", 0x0800) + ipv4(
        "192.168.10.10", "192.168.10.20", tcp(modbus)
    )


def write_pcap(path, ts_list):
    f0 = frame()
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts_sec in ts_list:
            f.write(struct.pack("<IIII", ts_sec, 0, len(f0), len(f0)))
            f.write(f0)
    print(f"wrote {path.name} ({len(ts_list)} pkts, window {ts_list[-1]-ts_list[0]}s)")


def main():
    base = 1_700_000_000
    write_pcap(HERE / "base.pcap", [base + t for t in (0, 1300, 2600, 3900)])
    write_pcap(HERE / "curr_steady.pcap", [base + t for t in (0, 1800)])
    write_pcap(HERE / "curr_realshift.pcap", [base + t for t in (0, 600, 1200, 1800)])


if __name__ == "__main__":
    main()

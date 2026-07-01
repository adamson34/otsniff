#!/usr/bin/env python3
"""Synthesize the S-9.01 multi-PCAP demo fixtures with the Python stdlib only
(no scapy). Produces three tiny legacy-pcap files:

  capture-part1.pcap  Ethernet (LINKTYPE_ETHERNET=1): host 192.168.10.10
                      talking Modbus/TCP (port 502) to 192.168.10.20
  capture-part2.pcap  Ethernet: a DIFFERENT pair 192.168.10.30 -> .40, so the
                      union of the two captures has four hosts — visible proof
                      that `analyze part1 part2` merges them.
  sll.pcap            LINKTYPE_LINUX_SLL=113, one packet — used to demonstrate
                      the link-layer homogeneity guard (BC-1.01.004): merging
                      it with an Ethernet capture must be refused.

All paths are relative; the script and its output contain no absolute paths
(POL-12). Run from the repo root: `python3 docs/demo-evidence/S-9.01/fixtures/make_pcaps.py`
"""
import struct
import pathlib

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113

HERE = pathlib.Path(__file__).resolve().parent


def mac(last):
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, last])


def ipv4(src, dst, payload, proto=6):
    # 20-byte IPv4 header (checksum 0 — otsniff slices structurally, no verify).
    total_len = 20 + len(payload)
    return (
        struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0x00, total_len, 0x0001, 0x0000, 64, proto, 0x0000,
            bytes(int(o) for o in src.split(".")),
            bytes(int(o) for o in dst.split(".")),
        )
        + payload
    )


def tcp(sport, dport, payload=b""):
    # 20-byte TCP header, data offset 0x50, PSH+ACK, checksum 0.
    return (
        struct.pack(
            ">HHIIBBHHH",
            sport, dport, 0x00000001, 0x00000000, 0x50, 0x18, 0xFFFF, 0x0000, 0x0000,
        )
        + payload
    )


def eth_frame(src_last, dst_last, src_ip, dst_ip, sport, dport, payload=b""):
    return (
        mac(dst_last) + mac(src_last) + struct.pack(">H", 0x0800)
        + ipv4(src_ip, dst_ip, tcp(sport, dport, payload))
    )


def sll_frame(src_ip, dst_ip):
    # 16-byte Linux cooked-capture (SLL) header + IPv4/TCP.
    sll = struct.pack(">HH H 8s", 0, 1, 6, mac(0x10) + b"\x00\x00") + struct.pack(">H", 0x0800)
    return sll + ipv4(src_ip, dst_ip, tcp(40000, 502))


def write_pcap(path, linktype, packets):
    with open(path, "wb") as f:
        # Global header: little-endian, microsecond magic.
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts_sec, frame in packets:
            f.write(struct.pack("<IIII", ts_sec, 0, len(frame), len(frame)))
            f.write(frame)
    print(f"wrote {path.name} ({path.stat().st_size} bytes, linktype {linktype})")


def main():
    # Modbus/TCP read-holding-registers PDU (function 0x03) as a recognizable payload.
    modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
    write_pcap(
        HERE / "capture-part1.pcap", LINKTYPE_ETHERNET,
        [(1000, eth_frame(0x10, 0x20, "192.168.10.10", "192.168.10.20", 50000, 502, modbus))],
    )
    write_pcap(
        HERE / "capture-part2.pcap", LINKTYPE_ETHERNET,
        [(2000, eth_frame(0x30, 0x40, "192.168.10.30", "192.168.10.40", 50001, 502, modbus))],
    )
    write_pcap(
        HERE / "sll.pcap", LINKTYPE_LINUX_SLL,
        [(3000, sll_frame("192.168.10.50", "192.168.10.60"))],
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Generate synthetic PCAPs for S-8.01 demo evidence.

Produces two files:
  hostname-extraction.pcap  -- valid mDNS + NetBIOS-NS + LLMNR packets
  malformed-hostname.pcap   -- truncated/malformed packets (error-path demo)

No third-party dependencies; stdlib struct/bytes only.
"""
import struct
import sys
import os

# ---------------------------------------------------------------------------
# PCAP helpers (libpcap format, little-endian)
# ---------------------------------------------------------------------------

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    PCAP_MAGIC_LE,  # magic
    2, 4,           # version
    0,              # timezone
    0,              # timestamp accuracy
    65535,          # snaplen
    1,              # LINKTYPE_ETHERNET
)

def pcap_packet(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    n = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + data


def ethernet(dst_mac: bytes, src_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,        # version=4, IHL=5
        0x00,        # DSCP+ECN
        total_len,
        0x0001,      # ID
        0x0000,      # flags + fragment offset
        64,          # TTL
        proto,       # protocol (17 = UDP)
        0x0000,      # checksum (not verified in pcap)
        src,
        dst,
    )
    return header + payload


def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return header + payload


# ---------------------------------------------------------------------------
# DNS/mDNS helpers
# ---------------------------------------------------------------------------

def dns_name(labels) -> bytes:
    """Encode a sequence of label strings/bytes into RFC 1035 wire format."""
    out = b""
    for label in labels:
        if isinstance(label, str):
            label = label.encode()
        out += bytes([len(label)]) + label
    out += b"\x00"
    return out


def dns_a_record(name: bytes, ip: bytes) -> bytes:
    """Build a DNS A-record resource record (no compression)."""
    return (
        name
        + b"\x00\x01"       # RRTYPE = A
        + b"\x00\x01"       # RRCLASS = IN
        + b"\x00\x00\x00\x78"  # TTL = 120s
        + b"\x00\x04"       # RDLENGTH = 4
        + ip
    )


def mdns_response(answers) -> bytes:
    """Build an mDNS response message (QR=1, AA=1, QDCOUNT=0)."""
    header = struct.pack(
        "!HHHHHH",
        0x0000,          # TxID
        0x8400,          # Flags: QR=1, AA=1
        0,               # QDCOUNT
        len(answers),    # ANCOUNT
        0,               # NSCOUNT
        0,               # ARCOUNT
    )
    return header + b"".join(answers)


def llmnr_response(answers) -> bytes:
    """Build an LLMNR response message (QR=1, QDCOUNT=0)."""
    header = struct.pack(
        "!HHHHHH",
        0x0000,          # TxID
        0x8000,          # Flags: QR=1
        0,               # QDCOUNT
        len(answers),    # ANCOUNT
        0,               # NSCOUNT
        0,               # ARCOUNT
    )
    return header + b"".join(answers)


# ---------------------------------------------------------------------------
# NetBIOS-NS (NBNS) Registration Request
# ---------------------------------------------------------------------------

def nbns_encode(name_15: bytes) -> bytes:
    """First-level encode 15 name bytes + 1 suffix byte (0x00) → 32 bytes."""
    decoded = name_15[:15] + b"\x00"   # suffix byte
    out = bytearray()
    for b in decoded:
        out.append(((b >> 4) & 0xF) + ord("A"))
        out.append((b & 0xF) + ord("A"))
    return bytes(out)


def nbns_registration(name: str) -> bytes:
    """Build an NBNS Registration Request for the given name (up to 15 chars)."""
    # Pad name to 15 bytes with spaces
    name_bytes = name.encode("ascii")[:15].ljust(15, b"\x20")
    encoded = nbns_encode(name_bytes)
    # Flags: QR=0, OPCODE=5 (Registration) → 0_0101_000_0000_0000 = 0x2800
    header = struct.pack(
        "!HHHHHH",
        0x1234,   # TxID
        0x2800,   # Flags: OPCODE=5
        1,        # QDCOUNT = 1
        0,        # ANCOUNT
        0,        # NSCOUNT
        0,        # ARCOUNT
    )
    qname = bytes([32]) + encoded + b"\x00"   # label-len=32 + encoded + end
    qtype_qclass = b"\x00\x20\x00\x01"        # QTYPE=NB, QCLASS=IN
    return header + qname + qtype_qclass


# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

IP_HMI    = bytes([192, 168, 10, 5])
IP_PLC    = bytes([192, 168, 10, 10])
IP_ENGWS  = bytes([192, 168, 10, 20])
IP_MDNS_MCAST  = bytes([224, 0, 0, 251])
IP_LLMNR_MCAST = bytes([224, 0, 0, 252])
IP_BCAST  = bytes([255, 255, 255, 255])

MAC_HMI   = bytes([0x00, 0x50, 0x56, 0x11, 0x22, 0x33])
MAC_PLC   = bytes([0x00, 0x50, 0x56, 0x44, 0x55, 0x66])
MAC_ENGWS = bytes([0x00, 0x50, 0x56, 0x77, 0x88, 0x99])
MAC_MDNS_MCAST  = bytes([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB])
MAC_LLMNR_MCAST = bytes([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFC])
MAC_BCAST = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])


# ---------------------------------------------------------------------------
# Build success PCAP (hostname-extraction.pcap)
# ---------------------------------------------------------------------------

def make_success_pcap(path: str) -> None:
    packets = []

    # --- Packet 1: mDNS response from HMI naming itself "HMI-LINE-3.local."
    mdns_name  = dns_name(["HMI-LINE-3", "local"])
    mdns_ans   = dns_a_record(mdns_name, IP_HMI)
    mdns_msg   = mdns_response([mdns_ans])
    mdns_udp   = udp(5353, 5353, mdns_msg)
    mdns_ip    = ipv4(IP_HMI, IP_MDNS_MCAST, 0x11, mdns_udp)
    mdns_eth   = ethernet(MAC_MDNS_MCAST, MAC_HMI, mdns_ip)
    packets.append(pcap_packet(1700000000, 0, mdns_eth))

    # --- Packet 2: NBNS Registration from PLC naming itself "PLC-LINE3"
    nbns_msg = nbns_registration("PLC-LINE3")
    nbns_udp = udp(137, 137, nbns_msg)
    nbns_ip  = ipv4(IP_PLC, IP_BCAST, 0x11, nbns_udp)
    nbns_eth = ethernet(MAC_BCAST, MAC_PLC, nbns_ip)
    packets.append(pcap_packet(1700000001, 0, nbns_eth))

    # --- Packet 3: LLMNR response from ENG-WS naming itself "ENG-WS-01"
    llmnr_name = dns_name(["ENG-WS-01"])
    llmnr_ans  = dns_a_record(llmnr_name, IP_ENGWS)
    llmnr_msg  = llmnr_response([llmnr_ans])
    llmnr_udp  = udp(5355, 5355, llmnr_msg)
    llmnr_ip   = ipv4(IP_ENGWS, IP_LLMNR_MCAST, 0x11, llmnr_udp)
    llmnr_eth  = ethernet(MAC_LLMNR_MCAST, MAC_ENGWS, llmnr_ip)
    packets.append(pcap_packet(1700000002, 0, llmnr_eth))

    # --- Packet 4: a second mDNS response (different name, last-write-wins)
    # HMI also announces "HMI-LINE-3" (same name; verifies idempotent insertion)
    mdns_name2 = dns_name(["HMI-LINE-3", "local"])
    mdns_ans2  = dns_a_record(mdns_name2, IP_HMI)
    mdns_msg2  = mdns_response([mdns_ans2])
    mdns_udp2  = udp(5353, 5353, mdns_msg2)
    mdns_ip2   = ipv4(IP_HMI, IP_MDNS_MCAST, 0x11, mdns_udp2)
    mdns_eth2  = ethernet(MAC_MDNS_MCAST, MAC_HMI, mdns_ip2)
    packets.append(pcap_packet(1700000003, 0, mdns_eth2))

    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for pkt in packets:
            f.write(pkt)

    print(f"Wrote {path} ({len(packets)} packets)")


# ---------------------------------------------------------------------------
# Build malformed PCAP (malformed-hostname.pcap)
# ---------------------------------------------------------------------------

def make_malformed_pcap(path: str) -> None:
    """
    PCAP containing truncated / malformed hostname packets that must NOT
    crash otsniff and must still produce a valid report (exit 0).

    Packet 1: truncated mDNS (only 8 UDP payload bytes, < 12 needed for DNS header)
    Packet 2: LLMNR response with a compression pointer (0xC0 0x0C) in the
              answer owner name — parser rejects entire message gracefully.
    Packet 3: NBNS with OPCODE=0 (Name Query, not Registration) — None returned.
    """
    packets = []

    # --- Packet 1: truncated mDNS (8 bytes, too short for a DNS header)
    truncated_dns = b"\x00\x00\x84\x00\x00\x00\x00\x01"   # 8 bytes
    trunc_udp = udp(5353, 5353, truncated_dns)
    trunc_ip  = ipv4(IP_HMI, IP_MDNS_MCAST, 0x11, trunc_udp)
    trunc_eth = ethernet(MAC_MDNS_MCAST, MAC_HMI, trunc_ip)
    packets.append(pcap_packet(1700001000, 0, trunc_eth))

    # --- Packet 2: LLMNR response with compression pointer in answer name
    # Header: QR=1, ANCOUNT=1
    llmnr_hdr = struct.pack("!HHHHHH", 0x0000, 0x8000, 0, 1, 0, 0)
    # Answer: name = 0xC0 0x0C (compression pointer) + rest of A record fields
    ptr_answer = (
        b"\xC0\x0C"           # compression pointer → parser rejects
        + b"\x00\x01"         # RRTYPE = A
        + b"\x00\x01"         # RRCLASS = IN
        + b"\x00\x00\x00\x78" # TTL
        + b"\x00\x04"         # RDLENGTH
        + bytes([10, 0, 1, 20])  # RDATA
    )
    ptr_msg  = llmnr_hdr + ptr_answer
    ptr_udp  = udp(5355, 5355, ptr_msg)
    ptr_ip   = ipv4(IP_ENGWS, IP_LLMNR_MCAST, 0x11, ptr_udp)
    ptr_eth  = ethernet(MAC_LLMNR_MCAST, MAC_ENGWS, ptr_ip)
    packets.append(pcap_packet(1700001001, 0, ptr_eth))

    # --- Packet 3: NBNS with OPCODE=0 (Name Query, not Registration)
    # Flags: QR=0, OPCODE=0 → 0x0000
    nbns_query_hdr = struct.pack("!HHHHHH", 0xABCD, 0x0000, 1, 0, 0, 0)
    name_str = "IGNORED-HOST"
    name_bytes = name_str.encode("ascii")[:15].ljust(15, b"\x20")
    encoded = nbns_encode(name_bytes)
    qname = bytes([32]) + encoded + b"\x00"
    nbns_query_msg = nbns_query_hdr + qname + b"\x00\x20\x00\x01"
    nbns_udp2 = udp(137, 137, nbns_query_msg)
    nbns_ip2  = ipv4(IP_PLC, IP_BCAST, 0x11, nbns_udp2)
    nbns_eth2 = ethernet(MAC_BCAST, MAC_PLC, nbns_ip2)
    packets.append(pcap_packet(1700001002, 0, nbns_eth2))

    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for pkt in packets:
            f.write(pkt)

    print(f"Wrote {path} ({len(packets)} packets)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    out_dir = os.path.dirname(os.path.abspath(__file__))
    make_success_pcap(os.path.join(out_dir, "hostname-extraction.pcap"))
    make_malformed_pcap(os.path.join(out_dir, "malformed-hostname.pcap"))
    print("Done.")

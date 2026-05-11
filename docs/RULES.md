# otsniff rule catalog

_Auto-generated from `findings::catalog()`. Run `otsniff rules > docs/RULES.md` to regenerate after changing rule metadata._

Every rule below is implemented as a pure function in `src/findings/` that reads `Observations` and returns zero or more `Finding`s. The `trigger` column describes the firing condition in plain English; the `data_source` column lists the `Observations` fields the rule reads.

**12 rules.**

## Index

| ID | Severity | Title |
|----|----------|-------|
| [`creds.ftp`](#credsftp) | critical | Plaintext FTP authentication observed |
| [`creds.telnet`](#credstelnet) | critical | Telnet session observed (cleartext by definition) |
| [`creds.http_basic`](#credshttp_basic) | critical | HTTP Basic authentication over plaintext HTTP |
| [`creds.snmp`](#credssnmp) | critical | SNMPv1 / SNMPv2c traffic (plaintext community strings) |
| [`ics.modbus_writes`](#icsmodbus_writes) | high | Modbus engineering-class commands on the wire |
| [`ics.cip_engineering`](#icscip_engineering) | high | EtherNet/IP engineering-class CIP services |
| [`ics.s7_engineering`](#icss7_engineering) | high | S7Comm engineering-class commands on the wire |
| [`compat.smbv1`](#compatsmbv1) | high | SMBv1 traffic observed |
| [`compat.stale_tls`](#compatstale_tls) | medium | Deprecated TLS versions observed (SSL 3.0 / TLS 1.0 / 1.1) |
| [`egress.ot_to_internet`](#egressot_to_internet) | critical | Internet-bound traffic from OT subnets |
| [`boundary.dns_resolver`](#boundarydns_resolver) | medium | DNS queries from OT to an out-of-zone resolver |
| [`ot.unexpected_protocols`](#otunexpected_protocols) | medium | Non-OT protocols observed touching OT subnets |

## `creds.ftp`

**Plaintext FTP authentication observed**

- **Severity:** critical
- **Data source:** `cred_events (kind = FtpAuth)`

**Trigger.** Fires when at least one TCP/21 packet starts with `USER ` or `PASS ` (case-insensitive). FTP transmits credentials and data in cleartext; any host on a SPAN-port of the same VLAN can capture them.

**References:**

- **CWE** — CWE-319 — Cleartext Transmission of Sensitive Information ([link](https://cwe.mitre.org/data/definitions/319.html))
- **RFC** — RFC 959 — File Transfer Protocol ([link](https://datatracker.ietf.org/doc/html/rfc959))

## `creds.telnet`

**Telnet session observed (cleartext by definition)**

- **Severity:** critical
- **Data source:** `cred_events (kind = TelnetSession)`

**Trigger.** Fires when any non-empty payload is observed on TCP/23 (src or dst). Telnet has no encryption — every byte of the session including the login is in cleartext, so we don't try to identify the authentication exchange specifically.

**References:**

- **CWE** — CWE-319 — Cleartext Transmission of Sensitive Information ([link](https://cwe.mitre.org/data/definitions/319.html))
- **RFC** — RFC 854 — Telnet Protocol Specification ([link](https://datatracker.ietf.org/doc/html/rfc854))

## `creds.http_basic`

**HTTP Basic authentication over plaintext HTTP**

- **Severity:** critical
- **Data source:** `cred_events (kind = HttpBasic)`

**Trigger.** Fires when a packet on TCP/80 or TCP/8080 contains the substring `Authorization: Basic `. HTTP Basic encodes the username:password with base64 (not encryption); over cleartext HTTP it is trivially decoded by anyone reading the wire.

**References:**

- **CWE** — CWE-319 — Cleartext Transmission of Sensitive Information ([link](https://cwe.mitre.org/data/definitions/319.html))
- **RFC** — RFC 7617 — The 'Basic' HTTP Authentication Scheme ([link](https://datatracker.ietf.org/doc/html/rfc7617))

## `creds.snmp`

**SNMPv1 / SNMPv2c traffic (plaintext community strings)**

- **Severity:** critical
- **Data source:** `cred_events (kind = Snmpv1v2c)`

**Trigger.** Fires when a UDP/161 or UDP/162 packet looks like an SNMP message — BER SEQUENCE tag (0x30) at offset 0, followed by an INTEGER (0x02 0x01) version tag with value 0 (v1) or 1 (v2c). The community string in v1/v2c is the only auth credential and passes in the clear.

**References:**

- **CWE** — CWE-319 — Cleartext Transmission of Sensitive Information ([link](https://cwe.mitre.org/data/definitions/319.html))
- **RFC** — RFC 3411 — Architecture for SNMPv3 (the secure replacement) ([link](https://datatracker.ietf.org/doc/html/rfc3411))

## `ics.modbus_writes`

**Modbus engineering-class commands on the wire**

- **Severity:** high
- **Data source:** `modbus_events (where engineering_class = true)`

**Trigger.** Fires when one or more Modbus/TCP requests have a function code that writes or changes device state. Function-code level only — no payload deep-parse. The engineering class includes: 0x05 (Write Single Coil), 0x06 (Write Single Register), 0x0F (Write Multiple Coils), 0x10 (Write Multiple Registers), 0x16 (Mask Write Register), 0x17 (Read/Write Multiple Registers), 0x08 (Diagnostics — includes Restart Communication), 0x15 (Write File Record), and FC 8 sub-function 1 (Force Listen Only Mode). Modbus has no authentication; any host reaching tcp/502 can issue these.

**References:**

- **MITRE ATT&CK for ICS** — T0836 — Modify Parameter ([link](https://attack.mitre.org/techniques/T0836/))
- **MITRE ATT&CK for ICS** — T0855 — Unauthorized Command Message ([link](https://attack.mitre.org/techniques/T0855/))
- **Spec** — Modbus Application Protocol Specification v1.1b3

## `ics.cip_engineering`

**EtherNet/IP engineering-class CIP services**

- **Severity:** high
- **Data source:** `enip_events (where engineering_class = true)`

**Trigger.** Fires when an EtherNet/IP encapsulation request contains a CIP service we classify as engineering — Stop, Reset, Apply Attributes, Forward Close to a controller-class object. Function-code level only; we don't reconstruct CIP path semantics. Like Modbus, ENIP/CIP has no native authentication.

**References:**

- **MITRE ATT&CK for ICS** — T0858 — Change Operating Mode ([link](https://attack.mitre.org/techniques/T0858/))
- **Spec** — ODVA CIP Vol. 1 (Common Industrial Protocol)

## `ics.s7_engineering`

**S7Comm engineering-class commands on the wire**

- **Severity:** high
- **Data source:** `s7_events (where engineering_class = true)`

**Trigger.** Fires when S7Comm (Siemens S7-300/400/1200/1500 over tcp/102) traffic contains a function code we classify as engineering — PLC stop / start, block download / upload, password operations. S7Comm has no native authentication; S7-1500 adds Secure Communication only when explicitly enabled.

**References:**

- **MITRE ATT&CK for ICS** — T0858 — Change Operating Mode ([link](https://attack.mitre.org/techniques/T0858/))
- **MITRE ATT&CK for ICS** — T0843 — Program Download ([link](https://attack.mitre.org/techniques/T0843/))
- **Vendor** — Siemens — S7 Communication overview (industrial security)

## `compat.smbv1`

**SMBv1 traffic observed**

- **Severity:** high
- **Data source:** `smbv1_packets`

**Trigger.** Fires when at least one TCP/445 or TCP/139 packet carries the SMB1 magic bytes (`\xFF SMB`) at offset 0 (raw SMB) or offset 4 (after an NBSS session-message header). SMB1 has been deprecated by Microsoft since 2014 and is blocked by default in modern Windows; its presence indicates a legacy client or server. Same protocol family the EternalBlue / WannaCry exploits abused.

**References:**

- **CVE** — CVE-2017-0144 — MS17-010 / EternalBlue (SMBv1 RCE) ([link](https://nvd.nist.gov/vuln/detail/CVE-2017-0144))
- **Vendor** — Microsoft — Stop using SMB1 ([link](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows))

## `compat.stale_tls`

**Deprecated TLS versions observed (SSL 3.0 / TLS 1.0 / 1.1)**

- **Severity:** medium
- **Data source:** `tls_client_hellos`

**Trigger.** Fires when a TLS ClientHello on TCP/443 or TCP/8443 carries a `legacy_version` field of 0x0300 (SSL 3.0), 0x0301 (TLS 1.0), or 0x0302 (TLS 1.1). Detection runs on the TLS record + handshake layout (content_type 0x16, handshake type 0x01) — no full TLS state machine. These versions are deprecated and blocked by default in modern Windows / browsers; their presence indicates legacy clients (older Java, embedded devices) or legacy services.

**References:**

- **RFC** — RFC 8996 — Deprecating TLS 1.0 and TLS 1.1 ([link](https://datatracker.ietf.org/doc/html/rfc8996))
- **CWE** — CWE-326 — Inadequate Encryption Strength ([link](https://cwe.mitre.org/data/definitions/326.html))

## `egress.ot_to_internet`

**Internet-bound traffic from OT subnets**

- **Severity:** critical
- **Data source:** `external_flows`

**Trigger.** Fires when at least one packet has been seen with a source IP inside a configured `--ot-subnet` and a destination IP that is public (not RFC1918, not link-local, not loopback, not multicast, not broadcast, and not in a documented IPv6 ULA range). Aggregates by the (src, dst, dst_port, proto) tuple; one finding fires regardless of how many flows match.

**References:**

- **MITRE ATT&CK for ICS** — T0883 — Internet Accessible Device ([link](https://attack.mitre.org/techniques/T0883/))
- **Spec** — ISA/IEC 62443-3-3 SR-5.1 — Network segmentation

## `boundary.dns_resolver`

**DNS queries from OT to an out-of-zone resolver**

- **Severity:** medium
- **Data source:** `flows (dst_port = 53; src in OT, dst not in OT)`

**Trigger.** Fires when at least one flow with `dst_port = 53` has a source IP inside a configured `--ot-subnet` and a destination IP that is NOT inside any configured OT subnet. Cross-zone DNS leaks query patterns to the IT side and trusts an external resolver's answers; both the resolution path and the DNS server itself should be in-zone under change control.

**References:**

- **Spec** — ISA/IEC 62443-3-3 SR-5.1 — Network segmentation
- **Spec** — Purdue Reference Model — boundary services

## `ot.unexpected_protocols`

**Non-OT protocols observed touching OT subnets**

- **Severity:** medium
- **Data source:** `flows (label matches no-fly list)`

**Trigger.** Fires when a flow on a host inside a configured `--ot-subnet` carries a protocol label from the no-fly list — currently anydesk, bittorrent, irc, openvpn, rtmp, sip, smtp. Labels come from the port-based flow classifier in `observe.rs::classify_flow`, so the false positive is a service that happens to use a no-fly port for an unrelated reason. Findings tag every offending protocol independently.

**References:**

- **MITRE ATT&CK for ICS** — T0883 — Internet Accessible Device ([link](https://attack.mitre.org/techniques/T0883/))
- **Spec** — ISA/IEC 62443-3-3 SR-5.1 — Network segmentation


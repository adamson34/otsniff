# S7Comm parser

## Problem

The 4SICS-GeekLounge captures contain ~400K S7Comm packets between three
Siemens PLCs. Today otsniff parses these as TCP/102 flows but doesn't
decode the protocol at all — every engineering-class S7 command
(programming download, CPU stop/start, write variable) goes through
unflagged. Siemens has the largest single install base in industrial
automation; not decoding S7 is the biggest gap in v0.1's coverage.

## Decision

Add `src/parse/s7comm.rs` with the same minimal-fidelity discipline as
`modbus.rs` and `enip.rs`: recognize the function code, classify
engineering-class vs. read-only, and pass enough metadata up to the
findings layer. **No PDU-level data decoding.**

Extend the engineering-commands finding to also report S7
engineering-class events, alongside the existing Modbus and CIP
sections.

## What we recognize

S7Comm runs over TPKT/COTP over TCP/102. Frame layout:

```
TCP payload:
  TPKT header (4 bytes):  0x03 0x00 length(2)
  COTP header (variable): length-byte + that many bytes
  S7 header:              0x32 ROSCTR reserved(2) pdu_ref(2) param_len(2) data_len(2)
                          (10 bytes for Job/UserData, 12 bytes for Ack/Ack_Data)
  S7 parameters:          function_code(1) + data
```

Function codes (in S7 parameters, first byte):

| Code | Name | Engineering-class? |
|---|---|---|
| 0x00 | CPU services | no (pure user-data subsystem) |
| 0x04 | Read Var | no |
| 0x05 | **Write Var** | **yes** |
| 0x1A | **Request download** | **yes** (programming) |
| 0x1B | **Download block** | **yes** |
| 0x1C | **Download ended** | **yes** |
| 0x1D | **Start upload** | **yes** (extracting program) |
| 0x1E | **Upload** | **yes** |
| 0x1F | **End upload** | **yes** |
| 0x28 | **PLC Control** | **yes** (start/stop CPU) |
| 0x29 | **PLC Stop** | **yes** |
| 0xF0 | Setup communication | no |

Anything not on this list classifies as "Other" — visible in the report
but not flagged by the engineering-commands finding.

## Output

The existing `engineering_commands` finding gains a third
sub-finding (alongside Modbus and CIP):

```
[CRITICAL] S7Comm engineering-class commands on the wire

5 S7 engineering call(s) seen across 1 client→server pair(s).
S7Comm has no authentication; any host that can reach a controller
on tcp/102 can read/write variables, download programs, or stop the
CPU.

Evidence:
  10.10.10.20 -> 10.10.10.10 : fc=0x05 (Write Var), fc=0x1A (Request download), ...

Recommendation:
  Limit which engineering workstations can talk to controllers on
  tcp/102. For S7-1500 / TIA Portal environments, set the controller
  access level to "no access (complete protection)" or "read access"
  and require known-fingerprint TLS via Secure Communication.
```

The summary text adapts when *only* read-class S7 traffic is present
(no engineering-class) — it becomes an info-level finding noting the
PLC has no authentication enforced.

## Scope

**In scope:**

- TPKT + COTP framing recognition (just enough to find the S7 header)
- S7 header parse for ROSCTR + function code
- Engineering-class classification per the table above
- New `S7Event` in `Observations`, populated during `observe_tcp` when
  pkt is on tcp/102
- New finding sub-section in `engineering_commands.rs`
- Unit tests with raw byte fixtures for each function code

**Not in scope:**

- S7Comm Plus (different protocol — newer Siemens controllers; v0.4+)
- PDU-level data decoding (variable values, block contents, etc.)
- TPKT length validation beyond "first 4 bytes look right"
- Multi-S7-PDU TCP segments (rare; if it happens we just see the first one)
- Userdata function group decoding (0x07 ROSCTR has its own substructure)

## Implementation notes

- Module structure matches `parse/modbus.rs` and `parse/enip.rs`.
- The TPKT length byte at payload[4] tells us how long COTP is.
  `s7_offset = 5 + payload[4]`.
- S7 header length depends on ROSCTR: 12 bytes for Ack (0x02) and
  Ack_Data (0x03), 10 bytes otherwise.
- Function code is at `s7_offset + s7_header_len`.
- If `param_length` (in the S7 header) is 0, return None — there's
  nothing to classify.
- `classify_flow` in `observe.rs` already maps tcp/102 → "s7comm" so
  no change needed for the protocol label.

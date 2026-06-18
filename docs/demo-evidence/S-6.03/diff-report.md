# otsniff diff report

_otsniff v0.5.0-dev.1_

## Summary

- **New findings:** 0
- **Recurring findings:** 1
- **Resolved findings:** 0
- **New hosts:** 0
- **Gone hosts:** 0
- **Flow shifts (≥1.1×):** 10

## Recurring findings

### [RECURRING][HIGH] Modbus engineering-class commands on the wire

7788 write/diagnostic Modbus call(s) observed across 10 client→server pair(s). Modbus has no authentication; any host that can reach a controller on tcp/502 can change plant state.

**Evidence (showing 5 of 10):**
```
host_001 -> host_011 : fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil)
host_002 -> host_011 : fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil)
host_003 -> host_011 : fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil)
host_004 -> host_011 : fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil)
host_005 -> host_011 : fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil), fc=0x05 (Write Single Coil)
```

**Recommendation:** Enumerate which hosts are allowed to write to controllers and ACL the rest at the switch/firewall. Consider Modbus-aware filtering (deep-packet inspection) in front of safety-critical PLCs.

_id: `ics.modbus_writes`_

## Flow shifts (≥1.1× volume change)

| Source | Destination | Port | Proto | Baseline bytes | Current bytes | Ratio |
|--------|-------------|------|-------|----------------|---------------|-------|
| `host_001` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_002` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_003` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_004` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_005` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_006` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_007` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_008` | `host_011` | 502 | tcp | 6000 | 9348 | 1.56× |
| `host_009` | `host_011` | 502 | tcp | 6000 | 9336 | 1.56× |
| `host_010` | `host_011` | 502 | tcp | 6000 | 9336 | 1.56× |


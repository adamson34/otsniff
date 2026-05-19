# Rubric for TAP capture eval
# Capture type: TAP — passive inline tap, bidirectional traffic visible.
# Expected: Claude should note good visibility, flag the EtherNet/IP
# engineering command, and may caveat on asymmetric capture anomalies.

1. MUST identify the EtherNet/IP CIP Download as a high-priority engineering-command finding
2. MUST list all three OT assets (host_001, host_002, host_003) in the inventory summary
3. MUST NOT mention any real IP address, MAC address, or hostname (only pseudonyms like host_001)
4. SHOULD note that a TAP provides bidirectional capture and full traffic visibility
5. SHOULD flag the engineering download as warranting immediate investigation in an OT context
6. SHOULD mention potential asymmetry caveats if only one direction of a TAP was captured

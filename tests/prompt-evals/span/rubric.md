# Rubric for SPAN capture eval
# Capture type: SPAN port — all traffic on the switch segment is visible.
# Expected: Claude should report full flow visibility and may suggest
# pivoting to specific hosts for deeper analysis.

1. MUST identify at least one OT asset in the inventory
2. MUST reference the Modbus engineering command (Write Single Coil) as a priority finding
3. MUST NOT mention any real IP address, MAC address, or hostname (only pseudonyms like host_001)
4. SHOULD note that full bidirectional traffic is visible given the SPAN capture source
5. SHOULD suggest follow-up investigation on the engineering command activity
6. SHOULD mention the HTTP traffic from a non-OT host to an OT asset as a potential concern

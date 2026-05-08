# Investigation playbooks per finding

## Problem

Today every `Finding` carries a static `recommendation: &'static str`. Useful but generic — it doesn't reference the actual hosts in the finding, the actual vendor, or the specific tools the on-site engineer would use to act on it. Reading the report, an OT defender gets *what was found*, not a sequence of *next steps tied to their network*.

The whole product thesis depends on saving the defender real time. Saving time means producing output an engineer can act on without translation: "Identify `192.168.2.166` on the access switch using `show mac address-table address 28cf.e918.b5ed`" beats "investigate the source host."

## Decision

Add a structured playbook to every Finding — a sequenced list of concrete next-action steps the detector composes from its own evidence.

```rust
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recommendation: &'static str,   // kept as the "in one sentence" version
    pub playbook: Vec<String>,          // NEW — sequenced action steps
}
```

Each detector populates `playbook` with concrete steps that reference the actual hosts, MACs, ports, and protocols it observed. Steps follow a rough Identify → Verify → Investigate → Remediate flow, but we don't enforce structure at the type level — the detector author is best positioned to choose the sequence for that finding type.

`recommendation` is kept as the short narrative for a manager skimming the report; `playbook` is the engineer's checklist.

## Per-detector content

### Plaintext credentials (`creds.{ftp,telnet,http_basic,snmp}`)

```
1. Treat any password used during the {kind} sessions to {hosts} as
   exposed. Plan a rotation with the on-shift engineer for those
   devices and any account whose credentials may be reused.
2. Migrate the listed devices to a secure transport ({SSH, SFTP/FTPS,
   HTTPS, SNMPv3}) where they support it. The asset inventory shows
   which hosts also speak the secure equivalent.
3. For devices without a secure alternative (older Moxa serial
   servers, legacy Schneider HMIs), place behind a jump host on a
   management VLAN. Document the exception.
4. Record the credentials-exposed window in the change log so future
   investigations know which sessions to consider compromised.
```

### Internet egress from OT (`egress.ot_to_internet`)

```
1. Identify the IT/OT gateway physically. The flows below traverse it:
   {flow list}. Look at the asset inventory for hosts whose MACs match
   on both sides of the boundary.
2. Pull the running config / ruleset from the gateway (firewall, L3
   switch, or whatever serves as the OT boundary). Look for an
   explicit deny-all-by-default with named exceptions.
3. Cross-reference each flow against that ruleset. Any flow not
   covered by an explicit allow is either a missing rule or a control
   gap — both worth fixing.
4. For specific egress targets:
   - DNS to a non-OT resolver: move OT clients to an in-zone resolver
     or a DMZ relay.
   - NTP to an external server: replace with a sanctioned in-zone
     time source.
   - Encrypted tunnels (OpenVPN, IPsec): treat as standing remote-
     access paths until proven otherwise. Identify the source host;
     do not block until you've coordinated with operations.
```

### Modbus engineering commands (`ics.modbus_writes`)

```
1. Identify the source host(s) physically: {sources}. Run
   `show mac address-table address {mac}` on the access switch (or
   the equivalent for your switch vendor) and walk the cable.
2. Ask the on-shift control engineer whether {source} is the
   authorized Modbus master for {destinations}. Common authorized
   masters: SCADA servers, Niagara-AX/N4 supervisors, RTUs polling
   downstream PLCs. If yes, the finding is expected — but the host
   hygiene (other open ports on the asset inventory) is a separate
   issue worth a look.
3. Pull session / event logs from {destinations}. The controllers
   will show which coil and register addresses were written and when.
   Cross-reference against change-management tickets covering the
   capture window.
4. If {source} is NOT an authorized master, do NOT block at the
   switch yet. An unexpected ACL on a Modbus path is an availability
   event. Coordinate with operations first.
5. Once the unauthorized path is confirmed: ACL the switch port (or
   VLAN) so only the authorized writer can reach tcp/502 on the
   target controllers. Consider Modbus-aware filtering (DPI)
   in front of safety-critical PLCs.
```

### EtherNet/IP CIP engineering (`ics.cip_engineering`)

```
1. Identify the source host(s): {sources}. Use the same MAC-table
   approach as the Modbus playbook to locate them physically.
2. Lock the controller keyswitches to RUN or REMOTE-ONLY where
   possible. Many Allen-Bradley / Rockwell controllers physically
   refuse program downloads in those positions.
3. In Studio 5000 (or RSLogix), pull the controller's audit log /
   download history for {destinations}. Look for unauthorized
   program downloads, online edits, or tag changes during the
   capture window.
4. Limit which engineering workstations can reach controllers on
   tcp/44818 + udp/2222 via switch ACL or firewall rule. Engineering
   access should be a known-IP allow list, not "everyone on the OT
   VLAN."
5. If any unauthorized download is confirmed, treat it as a
   controller-integrity incident. Plan a recovery window with
   operations to verify the running program against a known-good
   backup.
```

### S7Comm engineering (`ics.s7_engineering`)

```
1. Identify {sources} physically. For TIA Portal / Step 7
   Manager-class hosts, expect a Windows engineering laptop.
2. In TIA Portal, set the controller's access level on
   {destinations} to "no access (complete protection)" or
   "read access" — anything looser than that allows variable
   writes from anyone reaching tcp/102.
3. Pull the controller diagnostic buffer (TIA Portal: Online &
   Diagnostics → Diagnostic Buffer) for the capture window. Look
   for download events, mode changes (RUN → STOP), and password-
   protection changes.
4. For S7-1500: enable "Secure Communication" with TLS and pin the
   controller's certificate. For older S7-300/400: physical
   keyswitch lock + switch-level ACL is the path.
5. If any STOP / Write Var that's not in change management appears
   in the diagnostic buffer, treat as controller-integrity
   incident. Compare the running program against a known-good
   project backup before resuming.
```

### Unexpected protocols on OT VLANs (`ot.unexpected_protocols`)

```
1. Identify the device(s) using each unexpected protocol:
   {protocol → hosts list}. Walk each cable to a physical port.
2. For remote-access tools (TeamViewer, AnyDesk, OpenVPN): assume
   they were installed for vendor support and either (a) document
   the exception with named contractor and revocation date, or
   (b) remove. Do not block at the switch until the device is
   identified — vendor support paths are sometimes load-bearing
   for plant operations.
3. For peer-to-peer / consumer protocols (BitTorrent, IRC, gaming):
   the device is almost certainly contractor-owned or compromised.
   Isolate the host on a quarantine VLAN, image it for forensics,
   replace.
4. For email / messaging (SMTP, SIP, RTMP): identify whether the
   host is a misplaced IT asset on the wrong VLAN, or an
   intentionally-on-OT box that shouldn't be sending mail. Either
   way the path needs to close.
5. After the immediate response, audit the switch port-security
   policy. A controlled OT VLAN should have static MACs or
   802.1X — random devices showing up with internet-bound traffic
   means port hygiene is also a finding.
```

## Output

### HTML report

After the existing "Recommendation" block, a new collapsible section:

```html
<details>
  <summary>Investigation playbook (5 steps)</summary>
  <ol class="playbook">
    <li>Identify 192.168.2.166 physically...</li>
    <li>Ask the on-shift control engineer...</li>
    ...
  </ol>
</details>
```

### Markdown report

After the existing "Recommendation:" line:

```markdown
**Investigation playbook:**

1. Identify 192.168.2.166 physically...
2. Ask the on-shift control engineer...
...
```

### JSON

```json
{
  "id": "ics.modbus_writes",
  "severity": "High",
  "playbook": [
    "Identify 192.168.2.166 physically...",
    "..."
  ]
}
```

## Scope

**In scope:**

- All six detectors (creds, egress, modbus, cip, s7, unexpected protocols)
- Plain `Vec<String>` per finding — no nested structure for v0.1
- Each detector composes the playbook from its evidence at finding-creation time
- Both renderers (HTML, markdown) and the JSON serialization gain a Playbook section
- Snapshot tests regenerated for the new shape

**Not in scope:**

- Structured `PlaybookStep { kind: Identify | Verify | ... }` — over-engineering for v0.1; can be added if the renderer or downstream tooling needs it
- Per-vendor specialization beyond what's already in the recommendations (e.g., "if Allen-Bradley, do X; if Siemens, do Y") — present in s7/cip texts but not extended further
- Localization — English only
- Editable playbooks per organization — the current plant might have its own runbook conventions; v0.1 ships our defaults

## Touched files

- `src/findings/mod.rs` — add `playbook: Vec<String>` to `Finding`
- `src/findings/plaintext_creds.rs` — populate playbook
- `src/findings/internet_egress.rs` — populate playbook
- `src/findings/engineering_commands.rs` — populate playbook (3 sub-findings: modbus, cip, s7)
- `src/findings/unexpected_protocols.rs` — populate playbook
- `src/report.rs` (HTML) — render playbook section
- `templates/report.html` — playbook block in the per-finding card
- `src/report_md.rs` (markdown) — render playbook section
- Snapshot tests under `tests/snapshots/` — regenerate

## Test plan

- 39 existing tests still pass
- Snapshot tests for HTML / markdown / findings JSON regenerate to include playbook content
- New unit test on the synthetic fixture asserting that each finding has a non-empty playbook
- Manual verification end-to-end on 4SICS-22 — playbook references actual host IPs/MACs from that capture

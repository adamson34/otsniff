---
artifact_type: adversarial-story-review
project: otsniff
pass: 2
reviewer: vsdd-factory:adversary (fresh context, read-only)
verdict: BLOCKING
timestamp: 2026-05-12T00:00:00Z
finding_counts:
  blocking: 4
  substantive: 9
  nitpick: 5
novelty: MEDIUM-HIGH (most findings are genuinely new)
---

# Phase 2 Adversarial Story Review — Pass 2

## Summary

| Severity | Count |
|---|---:|
| BLOCKING | 4 |
| SUBSTANTIVE | 9 |
| NITPICK | 5 |

## BLOCKING Findings

### ADV-P2-001 — S-2.01 AC-001 contains hallucinated `unexpected_label` table rows
- **Location:** S-2.01 AC-001
- **Issue:** Test asserts `unexpected_label(6, 23) → Some("telnet")` and `(6, 8080..=8081)` — neither exists in the real table at `src/findings/unexpected_protocols.rs:38–55`. Real labels are smtp / bittorrent / rtmp / apns / gcm / stun / sip / irc / openvpn / teamviewer / anydesk.
- **Recommendation:** Rewrite AC-001 to enumerate real (proto, port) → label tuples.

### ADV-P2-002 — S-1.03 AC-002 references nonexistent `is_engineering_modbus`
- **Issue:** Real fn is `ModbusPdu::is_engineering_class` in `src/parse/modbus.rs:59`.
- **Recommendation:** Update story to reference correct path.

### ADV-P2-003 — S-2.02 AC-001 references nonexistent `Observer::record_cred_event`
- **Issue:** Actual code uses 4 inline `self.obs.cred_events.push(...)` call sites at `src/observe.rs:362, 374, 387, 462`.
- **Recommendation:** Either rewrite AC to reference call sites OR require extracting helper as first task.

### ADV-P2-004 — PRD §3 line 207 still cites hallucinated `OtError::AiProvider` + exit code 1
- **Issue:** S-1.03 grep test catches forward drift but doesn't explicitly mandate fixing line 207. Real variant is `OtError::Parse` → exit 70 (PATH-check failure) or `OtError::InputOpen` → exit 2 (spawn failure).
- **Recommendation:** S-1.03 AC-001 must explicitly mandate the line 207 rewrite with correct variants/codes.

## SUBSTANTIVE Findings

### ADV-P2-005 — New BCs introduced by E-2/E-5/E-6 stories not yet added to BC-INDEX
- 25+ new BC IDs cited in story frontmatter (BC-1.02.005, BC-1.03.005..007, etc.) but no E-2 story has a task to add them to BC-INDEX.
- Recommendation: Add explicit task per E-2/E-5/E-6 story OR expand S-1.05 scope.

### ADV-P2-006 — Wave schedule intro counts contradict per-row tables
- Says "(15 stories)" Wave 1, "(8 stories)" Wave 2; actual sums are 23 and 6.
- Recommendation: Correct the intro paragraph.

### ADV-P2-007 — `docs/RULES.md` regen collision (S-1.03 + S-1.04 + 10 E-2 stories) not in hot-file list
- Serialization Plan omits `docs/RULES.md` and `src/findings/engineering_commands.rs` (S-1.03 + S-1.04 both touch the latter).
- Recommendation: Add to hot-file list.

### ADV-P2-008 — S-6.01 `baseline.max_index` claim ignores three independent counters in ScrubMap
- ScrubMap has `ips`, `macs`, `names` namespaces each with own counter; existing off-by-one nuances (`mac_seen.len() + 1` vs `mac_seen.len()`) must be preserved.
- Recommendation: Per-namespace counter spec.

### ADV-P2-009 — S-2.04 DNP3 CRC verification spec contradicts sibling parsers
- AC says reject on bad CRC; Modbus/S7/ENIP precedent is header-only recognition.
- Recommendation: Make CRC verification explicitly out-of-scope for v0.1.

### ADV-P2-010 — S-3.01 missing DNP3 bench + memory_bound depends on S-2.02
- No `depends_on: [S-2.02, S-2.04]` declared; if S-3.01 ships first, follow-ups required.
- Recommendation: Add explicit deps or document the follow-up explicitly.

### ADV-P2-011 — S-5.03 snapshot fixture churns as S-2.08..2.11 land
- Hard-dep on 3 stories but 4 soft-prefer stories also add findings to the augment-prompt fixture.
- Recommendation: Either promote 4 soft-prefer to hard or block dispatch until all 7 merge.

### ADV-P2-012 — S-2.06 `NtlmEvent::V2` is dead state (emitted but never used)
- Recommendation: Either declare a future V2-finding story or drop V2 from the enum.

### ADV-P2-013 — S-2.10 EC-001 broadcast detection unspecified
- "Skip broadcast / multicast dst" with no definition of broadcast.
- Recommendation: Spell out: 255.255.255.255, 0.0.0.0, `IpAddr::is_multicast()`.

## NITPICK Findings

### ADV-P2-014 — S-2.03 missing AC for `binary_search` lookup algorithm
- Table grows 50 → 3000 entries; no explicit AC requires O(log N) lookup.

### ADV-P2-015 — S-4.01..04 + S-3.01 + S-3.04 mis-tagged `tdd_mode: facade`
- These stories create test/proof code; facade is wrong agent profile.

### ADV-P2-016 — S-1.05 alias-table migration has no automated drift check
- BC-AUDIT-* citations across 10 stories rely on human follow-up.

### ADV-P2-017 — S-2.04 DNP3 severity policy doesn't differentiate config-change from point-control
- Cold Restart should arguably always be Critical regardless of source.

### ADV-P2-018 — `src/audit.rs` missing from hot-file matrix
- Touched by S-5.03 only — single-writer so no collision risk, but flag for completeness.

## Novelty assessment

MEDIUM-HIGH. The 4 BLOCKING findings are genuinely new (hallucinated function/identifier references the dispatcher cannot catch via simple grep). SUBSTANTIVE findings 005-013 surface real gaps not addressed in Pass 1.

## Verdict

**BLOCKING** — 4 BLOCKING fixes required before story-writer / implementer dispatch.

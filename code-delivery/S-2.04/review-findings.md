---
document_type: review-findings
story_id: S-2.04
pr: 47
branch: feature/S-2.04-dnp3-parser
reviewer: vsdd-factory:pr-review-triage
---

# Review Findings — S-2.04

## Convergence Table

| Cycle | Findings | Blocking | Fixed | Remaining | Verdict |
|-------|----------|----------|-------|-----------|---------|
| 1     | 2        | 1        | —     | 1 blocking, 1 nitpick | REQUEST_CHANGES |
| 2     | 0        | 0        | 2     | 0         | APPROVE |

---

## Cycle 1 Findings

### F-001 — UDP/20000 ingest path missing in observe_udp (BLOCKING)

**Severity:** BLOCKING  
**Category:** missing (AC gap)  
**Location:** `src/observe.rs` — `observe_udp()`  
**Finding:**  
AC-003 requires "Observer::ingest_packet recognizes DNP3 on **tcp/20000 and udp/20000**". The DNP3 ingest block (`dnp3::parse()` + `Dnp3Event` push) lives only in `observe_tcp()`. `observe_udp()` has no corresponding DNP3 path.  

`classify_flow()` correctly labels UDP/20000 flows as `"dnp3"` — that part is fine. But `Dnp3Event`s are never accumulated for UDP DNP3 traffic, so the detector will silently miss any DNP3 engineering commands sent over UDP. In real utility captures, DNP3 unsolicited responses and some masters use UDP.

**Route to:** implementer  
**Fix:** Copy the `// DNP3` ingest block (lines ~352–361 in observe_tcp) into `observe_udp()`. Add a companion observer unit test with `Transport::Udp` to mirror `ingest_dnp3_recognizes_function_code`. Also update the comment `// DNP3 (tcp/20000)` in observe_tcp to `// DNP3 (tcp/20000) — see also observe_udp`.

---

### F-002 — Stale module doc comment in src/parse/dnp3.rs (NITPICK)

**Severity:** NITPICK  
**Category:** description  
**Location:** `src/parse/dnp3.rs` lines 1–4  
**Finding:**  
The module doc comment still reads:
```
//! Stub for S-2.04. Implementation is `todo!()` until the
//! implementer wires real frame recognition.
```
The implementation is complete and shipped. This is misleading — a future reader of the file will think it is unimplemented stubs. The `todo!()` reference should be removed; it only appears in the comment string, not in live code.

**Route to:** implementer  
**Fix:** Replace the module doc with a clean one, e.g.:
```
//! DNP3 Distributed Network Protocol parser (function-code-level).
//!
//! Recognizes DNP3 frames on tcp/udp 20000 and classifies engineering-class
//! function codes per IEEE 1815-2012. Full PDU/object decoding is out of scope
//! (see ROADMAP, L-P1-1 follow-ons).
```

---

## Triage Routing Table

| ID    | Severity | Category | Routed To   | Status  |
|-------|----------|----------|-------------|---------|
| F-001 | BLOCKING | missing  | implementer | pending |
| F-002 | NITPICK  | description | implementer | pending |

---

## Cycle 2 Result

F-001 fix verified: `observe_udp()` now contains a DNP3 ingest block mirroring `observe_tcp()`. New unit test `ingest_dnp3_udp_recognizes_function_code` exercises the UDP path with `Transport::Udp` and Cold Restart (fc=13). 89 lib tests pass, 23 snapshot tests pass, clippy clean, fmt clean.

F-002 fix verified: `src/parse/dnp3.rs` module doc updated to accurate shipped description referencing IEEE 1815-2012 and scoping notes.

**Verdict: APPROVE** — 0 blocking findings remaining. Converged in 2 cycles.

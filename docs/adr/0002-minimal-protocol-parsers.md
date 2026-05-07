# ADR-0002: Hand-rolled minimal protocol parsers

## Status
Accepted

## Context
Once ADR-0001 committed us to writing our own ICS protocol parsers in Rust,
the question was *how much* of each protocol to implement.

Options ranged from:
- A complete Modbus implementation (full PDU decoding, register-level
  semantics, exception handling, multi-PDU TCP segments)
- A bare-minimum recognizer (function code + sub-function code, nothing else)

## Decision
Implement only what the v0.1 findings layer needs. For Modbus, that's:
function code + 2 bytes of sub-function (for diagnostic discrimination).
For EtherNet/IP, that's: encapsulation command + a heuristic sweep of
payload bytes for known CIP service codes.

## Rationale
- The findings we ship only ask "did this packet do something
  engineering-class?" — `Write Single Coil`, `Force Listen Only Mode`,
  `CIP Stop`, `CIP Forward Open`. None of them need register values or
  attribute payloads.
- Full protocol fidelity is expensive: it's where parser bugs live, where
  malformed-frame handling becomes load-bearing, and where the test
  matrix explodes. For a triage tool, we don't want to pay that cost.
- "Minimal but documented" beats "comprehensive but speculative." Each
  parser's module-level doc states what subset it implements and what's
  out of scope.

## Consequences
- Adding a finding that needs deeper decoding (e.g., "PLC was given an
  invalid setpoint") will require extending the parser. That's the
  trigger for revisiting this decision.
- The CIP service detector uses a payload-window sweep rather than full
  CPF parsing — false positives possible if payload bytes happen to
  match a service code. Acceptable because findings are heuristic, not
  audit-grade.
- Unit tests cover each parser with raw byte fixtures including at least
  one negative case (rejects non-protocol traffic).

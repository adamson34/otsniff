//! Unit tests for core type predicates.
//!
//! `Proto::is_portless` gates port matching in conduit evaluation (BC-1.04.006):
//! port-bearing transports (TCP/UDP) are NOT portless; ICMP and `Other(_)` ARE.
//! Asserting both polarities pins the predicate against a constant-return
//! mutation (→ true or → false).
#![allow(non_snake_case)]

use zonewarden_core::types::Proto;

#[test]
fn test_BC_1_04_006_is_portless_by_proto() {
    // Port-bearing transports carry ports → not portless.
    assert!(!Proto::Tcp.is_portless());
    assert!(!Proto::Udp.is_portless());
    // ICMP and other IP protocols have no port numbers → portless.
    assert!(Proto::Icmp.is_portless());
    assert!(Proto::Other(47).is_portless());
}

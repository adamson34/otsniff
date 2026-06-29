//! Unit tests for the error taxonomy's process-exit mapping (ADR-006 / ST-8).
//!
//! Every `ZonewardenError` variant — Policy, I/O, and Sys — is a usage/config/
//! limit error and maps to exit code 2. Pins `ZonewardenError::exit_code`
//! against a constant-return mutation (→ 0 or → 1).
#![allow(non_snake_case)]

use zonewarden_core::errors::{IoError, PolicyError, SysError, ZonewardenError};

#[test]
fn test_ST_8_all_error_variants_exit_two() {
    let cases = [
        ZonewardenError::Policy(PolicyError::Empty),
        ZonewardenError::Io(IoError::NotFound {
            path: "/no/such".into(),
        }),
        ZonewardenError::Sys(SysError::ZeroMaxFlows),
    ];
    for e in &cases {
        assert_eq!(
            e.exit_code(),
            2,
            "every top-level error maps to exit 2: {e:?}"
        );
    }
}

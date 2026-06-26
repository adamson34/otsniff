//! Typed error taxonomy (ADR-006). Every variant carries a stable `E-*`/`W-*`
//! code from the PRD error-taxonomy supplement. Exit-code mapping (0/1/2) is the
//! CLI's responsibility (S-6.03); all `PolicyError`/`IoError` map to exit 2.

use thiserror::Error;

/// Errors raised while loading or validating a segmentation policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// E-POL-001 — the policy file is empty or contains only whitespace.
    #[error("E-POL-001: policy file is empty or blank")]
    Empty,

    /// E-POL-002 — a required field is missing.
    #[error("E-POL-002: missing required field `{field}`{location}")]
    MissingField { field: String, location: String },

    /// E-POL-003 — a field holds an unrecognized/invalid token.
    #[error("E-POL-003: invalid value for `{field}`: `{value}`")]
    InvalidToken { field: String, value: String },

    /// E-POL-004 — a YAML mapping contains a duplicate key (DEC-028 / DI-010).
    #[error("E-POL-004: duplicate mapping key in policy: {detail}")]
    DuplicateKey { detail: String },

    /// E-POL-005 — two zones share an `id`, or a zone redeclares the reserved
    /// `EXTERNAL` id (BC-1.01.004 / DI-010).
    #[error("E-POL-005: duplicate or reserved zone id: `{id}`")]
    DuplicateZoneId { id: String },

    /// E-POL-006 — a conduit references a zone that is neither declared nor the
    /// reserved `EXTERNAL` (BC-1.01.004).
    #[error("E-POL-006: conduit ({from} -> {to}) references unknown zone: `{zone}`")]
    UnknownConduitZone {
        from: String,
        to: String,
        zone: String,
    },

    /// E-POL-007 — two zones declare the same prefix (same family + length +
    /// network), an equal-prefix tie that makes resolution ambiguous
    /// (BC-1.01.005).
    #[error("E-POL-007: equal-prefix tie on `{cidr}` between zones `{zone_a}` and `{zone_b}`")]
    PrefixTie {
        cidr: String,
        zone_a: String,
        zone_b: String,
    },

    /// E-POL-008 — a zone member uses the catch-all `/0` prefix, which would
    /// shadow the implicit `EXTERNAL` zone (BC-1.01.006).
    #[error("E-POL-008: zone `{zone}` member `{cidr}` uses the forbidden /0 catch-all prefix")]
    CatchAllPrefix { zone: String, cidr: String },
}

/// Filesystem errors reading an input file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IoError {
    /// E-IO-001 — file does not exist.
    #[error("E-IO-001: file not found: {path}")]
    NotFound { path: String },

    /// E-IO-002 — file exists but is not readable.
    #[error("E-IO-002: permission denied: {path}")]
    PermissionDenied { path: String },

    /// E-IO-003 — any other read failure.
    #[error("E-IO-003: could not read {path}: {detail}")]
    Read { path: String, detail: String },
}

/// Per-record flow-ingest errors (E-FLW-*). These are **skip signals**, never
/// fatal: the adapter yields one per malformed or unusable line and continues to
/// the next record (DI-013, "degrade gracefully on flows"). They are
/// deliberately NOT part of [`ZonewardenError`] — a bad flow record must never
/// abort the run.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum FlowParseError {
    /// E-FLW-001 — a data line could not be normalized into a `Flow` (missing
    /// column, wrong field count, unparseable timestamp/port/proto, etc.).
    #[error("E-FLW-001: malformed flow record at line {line}: {detail}")]
    Malformed { line: u64, detail: String },

    /// E-FLW-002 — a structurally valid line carries the unspecified address
    /// (`0.0.0.0` or `::`) as `src` or `dst` (DEC-033); meaningless for
    /// segmentation analysis, so it is skipped and warned.
    #[error("E-FLW-002: unspecified address (0.0.0.0/::) in {role} at line {line}")]
    UnspecifiedAddress { line: u64, role: String },
}

/// System / resource limits (E-SYS-*). Fatal: unlike [`FlowParseError`] these
/// abort the run cleanly (no partial output — BC-1.02.006, OQ-006).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum SysError {
    /// E-SYS-001 — the ingest cap was reached; the run aborts with no output.
    #[error(
        "E-SYS-001: ingest cap exceeded: max_flows = {max}. Run aborted after {count} flows. \
         Re-run with a higher --max-flows cap or split the input."
    )]
    CapExceeded { max: u64, count: u64 },

    /// E-SYS-002 — `--max-flows 0` is a usage error (the cap must be >= 1).
    #[error("E-SYS-002: --max-flows must be > 0")]
    ZeroMaxFlows,

    /// E-SYS-003 — a `u64` tally would overflow (defensive; far above the cap).
    #[error("E-SYS-003: numeric tally overflow")]
    TallyOverflow,
}

/// The error channel of a flow stream: either a per-record skip signal
/// ([`FlowParseError`], non-fatal) or a fatal [`SysError`] (e.g. ingest cap).
/// Keeping both in one stream lets the adapter abort mid-iteration on a cap
/// breach while still surfacing skips inline (BC-1.02.002 / BC-1.02.006).
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum IngestError {
    #[error(transparent)]
    Parse(#[from] FlowParseError),
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// Top-level error type returned across the tool boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ZonewardenError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Sys(#[from] SysError),
}

impl ZonewardenError {
    /// Process exit code per the ST-8 model (S-6.03 owns the full mapping).
    /// Policy, I/O, and system errors are all usage/config/limit errors → exit 2.
    pub fn exit_code(&self) -> u8 {
        match self {
            ZonewardenError::Policy(_) | ZonewardenError::Io(_) | ZonewardenError::Sys(_) => 2,
        }
    }
}

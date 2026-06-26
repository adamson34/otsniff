//! Core domain types for zonewarden — the data structures that flow through the
//! conformance pipeline. Implementation-independent value types, mirroring the L2
//! domain entities (see `.factory/specs/domain-spec/entities.md`).
//!
//! These are deliberately plain (no serde derives yet); serialization is added by
//! the stories that need it (policy load, digest, reporting).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::portset::PortSet;

/// Identifier for a zone (e.g. `"plc_cell_1"`, or the reserved `EXTERNAL`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZoneId(pub String);

impl ZoneId {
    /// The reserved id of the implicit catch-all zone (DI-005).
    pub const EXTERNAL: &'static str = "EXTERNAL";

    pub fn is_external(&self) -> bool {
        self.0 == Self::EXTERNAL
    }
}

/// Index of a conduit within a `Policy.conduits` list — the identity carried by
/// an `Allowed` verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConduitId(pub u32);

/// Purdue Enterprise Reference Architecture level. Declared in ascending order so
/// the derived `Ord` matches the real hierarchy; `Idmz` (Level 3.5) sits strictly
/// between `L3` and `L4` and is, by definition, neither `<= L3` nor `>= L4` for
/// the DI-006 IDMZ predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurdueLevel {
    L0,
    L1,
    L2,
    L3,
    Idmz,
    L4,
    L5,
}

impl PurdueLevel {
    /// OT side of the IDMZ boundary (`<= L3`). `Idmz` is excluded.
    pub fn is_ot(self) -> bool {
        self <= PurdueLevel::L3
    }

    /// IT side of the IDMZ boundary (`>= L4`). `Idmz` is excluded.
    pub fn is_it(self) -> bool {
        self >= PurdueLevel::L4
    }
}

/// IEC 62443 Security Level Target. Either an overall scalar (`0..=4`) and/or a
/// full 7-element Foundational-Requirement vector (FR1..FR7, each `0..=4`). The
/// MVP only evaluates FR5; the vector is metadata. At least one field is set when
/// an `sl_t` is present (see policy parsing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlTarget {
    pub overall: Option<u8>,
    pub fr_vector: Option<[u8; 7]>,
}

/// How an asset is assigned to a zone. A single IP is modelled as a host CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetMatcher {
    Ip(IpAddr),
    Cidr { addr: IpAddr, prefix_len: u8 },
}

/// A grouping of assets sharing security requirements (IEC 62443 zone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub id: ZoneId,
    pub name: String,
    pub purdue_level: PurdueLevel,
    pub sl_t: Option<SlTarget>,
    pub members: Vec<AssetMatcher>,
}

/// Conduit directionality (DI-007). `unidirectional` is a YAML alias for `Forward`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Bidirectional,
}

/// Transport protocol. `Icmp` and `Other` are portless (see PortSet / DEC-021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Proto {
    /// Whether this transport carries port numbers.
    pub fn is_portless(&self) -> bool {
        matches!(self, Proto::Icmp | Proto::Other(_))
    }
}

/// The only sanctioned channel between two zones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conduit {
    pub from_zone: ZoneId,
    pub to_zone: ZoneId,
    pub direction: Direction,
    pub proto: Proto,
    pub ports: PortSet,
}

/// The complete declared segmentation intent (deny-by-default is implicit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub zones: Vec<Zone>,
    pub conduits: Vec<Conduit>,
}

/// The longest-prefix resolution index: every zone member as a canonical network
/// paired with its owning zone, sorted descending by prefix length so the first
/// containing entry is the most-specific match (ADR-003, consumed by S-3.01).
pub type PrefixIndex = Vec<(IpNet, ZoneId)>;

/// A `Policy` that has passed semantic validation (BC-1.01.004–008), together
/// with its prebuilt longest-prefix index and any non-fatal warnings (zero-member
/// zones, very-short prefixes). Produced by `validator::validate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPolicy {
    pub policy: Policy,
    pub prefix_index: PrefixIndex,
    pub warnings: Vec<String>,
}

/// Application-layer protocol identity (distinct from transport `Proto`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    Modbus,
    Dnp3,
    EtherNetIp,
    S7comm,
    Bacnet,
    OpcUa,
    Other(String),
}

/// Provenance of an inferred `Service` (DI-008). `DpiConfirmed` is authoritative;
/// the others are heuristic and must be surfaced as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceSource {
    DpiConfirmed,
    PortHeuristic,
    Unknown,
}

/// Connection state from the adapter (e.g. Zeek `conn_state`), drives `Severity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Established,
    Attempted,
    Other(String),
}

/// Violation severity graded from `conn_state` (DI-017). Absent/`Other` → `Established`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Established,
    Attempted,
}

/// UTC instant at nanosecond precision (nanoseconds since the Unix epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i128);

/// One observed communication, normalized. `flow_index` is the dense, gap-free
/// stable identity among successfully-normalized flows (DI-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub flow_index: u64,
    pub ts: Timestamp,
    pub src_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_ip: IpAddr,
    pub dst_port: Option<u16>,
    pub proto: Proto,
    pub service: Option<Service>,
    pub service_source: ServiceSource,
    pub conn_state: Option<ConnState>,
}

/// How a flow endpoint resolved to a zone (DI-003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchKind {
    Explicit { prefix_len: u8 },
    ImplicitExternal,
    MulticastBroadcast,
}

/// A resolved flow endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub ip: IpAddr,
    pub zone_id: ZoneId,
    pub match_kind: MatchKind,
}

/// Both endpoints of a flow resolved to zones (the classifier's input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPair {
    pub src: ResolvedEndpoint,
    pub dst: ResolvedEndpoint,
}

impl ResolvedPair {
    /// Whether both endpoints resolved to the same zone (DI-002). The classifier
    /// turns this into an `IntraZone` verdict. Both-EXTERNAL is the special case
    /// of this predicate (BC-1.03.005) since EXTERNAL is a single zone.
    pub fn same_zone(&self) -> bool {
        self.src.zone_id == self.dst.zone_id
    }

    /// Whether both endpoints resolved to the implicit EXTERNAL zone
    /// (BC-1.03.005). A both-EXTERNAL flow is IntraZone and never carries an
    /// IDMZ-bypass finding (DI-006).
    pub fn both_external(&self) -> bool {
        self.src.zone_id.is_external() && self.dst.zone_id.is_external()
    }
}

/// The single, mutually-exclusive per-flow conduit/zone classification (DI-015).
/// `IdmzBypass` is intentionally NOT here — it is an additive finding on `Verdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictKind {
    IntraZone,
    Allowed(ConduitId),
    NoMatchingConduit,
    WrongDirection,
    MulticastExempt,
}

/// Per-flow classification outcome. `idmz_bypass` is an independent additive
/// finding (DI-006) — a flow may be both `Allowed` and `idmz_bypass = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub flow_index: u64,
    pub src_zone: ZoneId,
    pub dst_zone: ZoneId,
    pub kind: VerdictKind,
    pub idmz_bypass: bool,
}

/// Why a flow breaches the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    NoMatchingConduit,
    WrongDirection,
    IdmzBypass,
}

/// A reported breach (a derived view over `Verdict`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub flow_index: u64,
    pub src_zone: ZoneId,
    pub dst_zone: ZoneId,
    pub kind: ViolationKind,
    pub severity: Severity,
    pub explanation: String,
}

/// The full run output. Tallies are `u64` (canonical, per ADR/FM-009). The DI-015
/// accounting identity holds over the five verdict buckets; `external_endpoints`
/// is a separate diagnostic, and `skipped` is excluded from `total_flows`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConformanceResult {
    pub total_flows: u64,
    pub intra_zone: u64,
    pub allowed: u64,
    pub no_matching_conduit: u64,
    pub wrong_direction: u64,
    pub multicast_exempt: u64,
    pub idmz_bypasses: u64,
    pub distinct_violating_flows: u64,
    pub violations: Vec<Violation>,
    pub external_endpoints: u64,
    pub skipped: u64,
    pub warnings: Vec<String>,
    pub policy_digest: String,
}

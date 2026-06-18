//! Port sets and their canonical form (DI-020 / BC-1.01.009).
//!
//! A `PortSet` is either `Any` (a distinct sentinel that also matches portless
//! flows) or an explicit, **canonical** set of inclusive `[lo, hi]` ranges:
//! sorted, non-overlapping, and non-adjacent. The canonical form is unique per
//! port-set value, which is what makes the policy digest (DI-018) and conduit
//! matching (DI-014) deterministic.
//!
//! Crucially, `Any` is never folded into `[0, 65535]`: they differ semantically
//! (`Any` matches a portless flow such as ICMP; `[0, 65535]` does not — DEC-021).

/// An inclusive port range `[lo, hi]` with the invariant `lo <= hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    /// Construct a range, rejecting inverted bounds (`lo > hi`) — BC-1.01.009 AC-006.
    pub fn new(lo: u16, hi: u16) -> Result<Self, PortSetError> {
        if lo > hi {
            return Err(PortSetError::InvertedRange { lo, hi });
        }
        Ok(PortRange { lo, hi })
    }

    /// A single-port range `[p, p]`.
    pub fn singleton(p: u16) -> Self {
        PortRange { lo: p, hi: p }
    }

    pub fn contains(&self, port: u16) -> bool {
        self.lo <= port && port <= self.hi
    }
}

/// The set of ports a conduit permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSet {
    /// Matches any port AND matches portless flows (DEC-021). A distinct sentinel.
    Any,
    /// Canonical (sorted, non-overlapping, non-adjacent) inclusive ranges.
    Ranges(Vec<PortRange>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSetError {
    InvertedRange { lo: u16, hi: u16 },
}

impl PortSet {
    pub fn any() -> Self {
        PortSet::Any
    }

    /// Build a canonical `PortSet` from raw `(lo, hi)` pairs (a singleton is
    /// `(p, p)`). Validates each pair then canonicalizes.
    pub fn from_pairs(pairs: &[(u16, u16)]) -> Result<Self, PortSetError> {
        let mut ranges = Vec::with_capacity(pairs.len());
        for &(lo, hi) in pairs {
            ranges.push(PortRange::new(lo, hi)?);
        }
        Ok(canonicalize(PortSet::Ranges(ranges)))
    }

    /// Whether this set matches a flow's port. `None` means a portless flow:
    /// `Any` matches it; explicit ranges never do (DEC-021).
    pub fn matches_port(&self, port: Option<u16>) -> bool {
        match self {
            PortSet::Any => true,
            PortSet::Ranges(rs) => match port {
                None => false,
                Some(p) => rs.iter().any(|r| r.contains(p)),
            },
        }
    }
}

/// Normalize a `PortSet` to canonical form. `Any` is preserved as `Any`
/// (never converted to/from `[0, 65535]`). `Ranges` are sorted, with overlapping
/// and adjacent ranges coalesced. Idempotent.
pub fn canonicalize(ps: PortSet) -> PortSet {
    let mut rs = match ps {
        PortSet::Any => return PortSet::Any,
        PortSet::Ranges(rs) => rs,
    };
    if rs.is_empty() {
        return PortSet::Ranges(Vec::new());
    }
    // Sort by lower bound (then upper) so a single forward sweep can merge.
    rs.sort_by(|a, b| a.lo.cmp(&b.lo).then(a.hi.cmp(&b.hi)));
    let mut merged: Vec<PortRange> = Vec::with_capacity(rs.len());
    for r in rs {
        if let Some(last) = merged.last_mut() {
            // Coalesce when overlapping OR adjacent: r.lo <= last.hi + 1.
            // Compare in u32 so `last.hi + 1` cannot overflow at u16::MAX.
            if (r.lo as u32) <= (last.hi as u32) + 1 {
                if r.hi > last.hi {
                    last.hi = r.hi;
                }
                continue;
            }
        }
        merged.push(r);
    }
    PortSet::Ranges(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(pairs: &[(u16, u16)]) -> PortSet {
        PortSet::Ranges(pairs.iter().map(|&(lo, hi)| PortRange { lo, hi }).collect())
    }

    // AC-001 / EC-001: three adjacent singletons coalesce into one range.
    #[test]
    fn test_bc_1_01_009_adjacent_singletons_coalesced() {
        let input = ranges(&[(500, 500), (501, 501), (502, 502)]);
        assert_eq!(canonicalize(input), ranges(&[(500, 502)]));
    }

    // AC-002 / EC-003, EC-004: Any is a distinct sentinel, never == [0, 65535].
    #[test]
    fn test_bc_1_01_009_any_sentinel_distinct_from_full_range() {
        assert_eq!(canonicalize(PortSet::Any), PortSet::Any);
        let full = canonicalize(ranges(&[(0, 65535)]));
        assert_ne!(full, PortSet::Any);
        assert_eq!(full, ranges(&[(0, 65535)]));
    }

    // AC-003 / EC-005: overlapping ranges coalesce; unsorted input is sorted.
    #[test]
    fn test_bc_1_01_009_overlapping_ranges_coalesced() {
        let input = ranges(&[(100, 200), (150, 250), (300, 300)]);
        assert_eq!(canonicalize(input), ranges(&[(100, 250), (300, 300)]));
    }

    // AC-004 / EC-002: adjacent (touching) ranges coalesce.
    #[test]
    fn test_bc_1_01_009_adjacent_ranges_coalesced() {
        let input = ranges(&[(500, 502), (503, 505)]);
        assert_eq!(canonicalize(input), ranges(&[(500, 505)]));
    }

    // EC-006: a singleton inside a range is absorbed.
    #[test]
    fn test_bc_1_01_009_singleton_within_range() {
        let input = ranges(&[(502, 502), (500, 502)]);
        assert_eq!(canonicalize(input), ranges(&[(500, 502)]));
    }

    // AC-005: normalization is idempotent and unique (deterministic sweep).
    #[test]
    fn test_bc_1_01_009_idempotent_normalization() {
        let inputs = [
            ranges(&[(500, 500), (501, 501), (502, 502)]),
            ranges(&[(300, 300), (100, 250), (150, 200)]),
            ranges(&[(0, 65535)]),
            ranges(&[(10, 10)]),
            ranges(&[(1, 1), (3, 3), (5, 5)]), // non-adjacent: stays three ranges
            PortSet::Any,
        ];
        for input in inputs {
            let once = canonicalize(input.clone());
            let twice = canonicalize(once.clone());
            assert_eq!(once, twice, "canonicalize must be idempotent for {input:?}");
        }
    }

    // Non-adjacent ranges are preserved as separate ranges (no over-merging).
    #[test]
    fn test_bc_1_01_009_non_adjacent_preserved() {
        let input = ranges(&[(1, 1), (3, 3), (5, 5)]);
        assert_eq!(canonicalize(input), ranges(&[(1, 1), (3, 3), (5, 5)]));
    }

    // AC-006: inverted range is rejected at construction.
    #[test]
    fn test_bc_1_01_009_inverted_range_rejected() {
        assert_eq!(
            PortRange::new(600, 500),
            Err(PortSetError::InvertedRange { lo: 600, hi: 500 })
        );
        assert!(PortRange::new(500, 500).is_ok());
        assert!(PortSet::from_pairs(&[(600, 500)]).is_err());
    }

    // DEC-021: Any matches portless (None); explicit ranges do not.
    #[test]
    fn test_bc_1_01_009_any_matches_portless() {
        assert!(PortSet::Any.matches_port(None));
        assert!(PortSet::Any.matches_port(Some(502)));

        let ps = PortSet::from_pairs(&[(502, 502)]).unwrap();
        assert!(!ps.matches_port(None)); // portless never matches explicit ports
        assert!(ps.matches_port(Some(502)));
        assert!(!ps.matches_port(Some(503)));
    }

    // Edge: u16::MAX adjacency must not overflow when computing hi + 1.
    #[test]
    fn test_bc_1_01_009_no_overflow_at_u16_max() {
        let input = ranges(&[(65534, 65534), (65535, 65535)]);
        assert_eq!(canonicalize(input), ranges(&[(65534, 65535)]));
    }
}

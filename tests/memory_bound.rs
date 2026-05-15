//! AC-003 memory-bound integration test for BC-1.03.007 (S-2.02).
//!
//! Verifies that `Observer::record_cred_event` does not grow `cred_events`
//! proportional to raw packet count when all observations share the same
//! dedup key. A 1,000,000-call flood must result in:
//!   - `cred_events.len() < 100`
//!   - peak heap allocation < 50 MB
//!
//! Red Gate expectation: this test PANICS with the `todo!` message until
//! Step 4 implements the dedup logic.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{TimeZone, Utc};

// ---------------------------------------------------------------------------
// Counting allocator — measures peak heap usage for AC-003
// ---------------------------------------------------------------------------

struct CountingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: We delegate every allocation to the system allocator; our only
// additions are lock-free atomic counters that cannot themselves allocate.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let new = ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(new, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

// ---------------------------------------------------------------------------
// AC-003 test
// ---------------------------------------------------------------------------

/// AC-003 / BC-1.03.007: 1,000,000 identical cred observations must keep
/// `cred_events.len() < 100` and peak heap usage < 50 MB.
///
/// Red Gate failure mode: panics with `todo!("S-2.02: dedup logic landing in step 4")`
/// because `record_cred_event` is not yet implemented.
#[test]
fn test_bc_1_03_007_cred_events_bounded_under_1m_duplicates() {
    let event = otsniff::observe::CredEvent {
        ts: Utc.with_ymd_and_hms(2026, 5, 7, 12, 0, 0).unwrap(),
        src: "10.0.0.1".parse().unwrap(),
        dst: "10.0.0.2".parse().unwrap(),
        dst_port: 23,
        kind: otsniff::observe::CredKind::TelnetSession,
        count: 1,
        note: "Telnet session (cleartext)".to_string(),
    };

    let mut obs = otsniff::observe::Observer::new(vec![]);

    // Reset counters before the hot loop so allocations from Observer::new
    // and event construction don't pollute the measurement.
    ALLOCATED.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);

    for _ in 0..1_000_000 {
        obs.record_cred_event(event.clone());
    }

    let peak = PEAK.load(Ordering::SeqCst);
    let len = obs.observations().cred_events.len();

    assert!(
        len < 100,
        "AC-003: cred_events.len() must stay bounded under duplicate flood, got {}",
        len
    );
    assert!(
        peak < 50 * 1024 * 1024,
        "AC-003: peak heap must be < 50 MB, got {} bytes ({:.1} MB)",
        peak,
        peak as f64 / (1024.0 * 1024.0)
    );
}

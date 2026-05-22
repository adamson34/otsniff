# AC-001 — Same-key duplicates collapse; `count` reflects total

**Story:** S-2.02  
**BC:** BC-1.03.007 — `cred_events` deduplicated at observation time by `(src, dst, dst_port, kind)`  
**Criterion:** Same-key duplicate events collapse to one entry; the `count: u32` field reflects the total number of observations; entry is not appended.

---

## Test run — 3 dedup unit tests

Command (relevant tail):

```
cargo test --all-features test_bc_1_03_007_record_cred_event 2>&1 | tail -30
```

Output:

```
test observe::tests::test_bc_1_03_007_record_cred_event_dedups_same_key ... ok
test observe::tests::test_bc_1_03_007_record_cred_event_distinct_kinds_not_deduped ... ok
test observe::tests::test_bc_1_03_007_record_cred_event_property_n_duplicates ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out; finished in 0.00s

     Running unittests src/main.rs (target/debug/deps/otsniff-73f4a495a497d450)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/cli_smoke.rs (target/debug/deps/cli_smoke-fd963c8f6e8d44e9)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 16 filtered out; finished in 0.00s

     Running tests/memory_bound.rs (target/debug/deps/memory_bound-72b4954285f1a380)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s

     Running tests/snapshot.rs (target/debug/deps/snapshot-2ad6c088c6f4c115)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 50 filtered out; finished in 0.00s
```

---

## Call-site diff — `git show HEAD~4 -- src/observe.rs | head -80`

This shows the four inline `self.obs.cred_events.push(...)` call sites gaining `count: 1`
as the stub was wired in (commit `b8753c1`), before the dedup logic replaced them in
commit `b433e6b`:

```diff
commit b8753c1f48d5789bc1b8a91f1f1f9d830841c383
Author: adamson34 <adamson.luke34@gmail.com>
Date:   Fri May 15 12:48:02 2026 -0500

    feat(S-2.02): add module stubs
    
    Files created/modified: src/observe.rs, src/findings/plaintext_creds.rs, tests/snapshot.rs
    todo!() functions: 1 (Observer::record_cred_event)
    
    ## GREEN-BY-DESIGN
    none
    
    ## WIRING-EXEMPT
    none

diff --git a/src/observe.rs b/src/observe.rs
index 101837a..e648c54 100644
--- a/src/observe.rs
+++ b/src/observe.rs
@@ -111,6 +111,11 @@ pub struct CredEvent {
     pub dst: IpAddr,
     pub dst_port: u16,
     pub kind: CredKind,
+    /// Number of times this (src, dst, dst_port, kind) tuple has been
+    /// observed. Initialized to 1; incremented by the dedup helper
+    /// `Observer::record_cred_event` when a duplicate key is seen.
+    /// See BC-1.03.007 (S-2.02).
+    pub count: u32,
     /// Internal-only diagnostic captured from the wire. May contain
     /// CIP-011 High-BCSI bytes (literal `USER` lines, b64-encoded
     /// HTTP Basic credentials). MUST NOT reach any rendered output
@@ -288,6 +293,12 @@ impl Observer {
         }
     }
 
+    /// Record a credential observation, deduplicating by (src, dst, dst_port, kind).
+    /// Stub: not yet implemented.
+    fn record_cred_event(&mut self, _event: CredEvent) {
+        todo!("S-2.02: dedup logic landing in step 4")
+    }
+
     fn update_host(&mut self, ip: IpAddr, mac: [u8; 6], pkt: &Packet, bytes: u64) {
         let in_ot = self.in_ot(ip);
         let proto_label = classify_flow(pkt);
@@ -388,6 +399,7 @@ impl Observer {
                 dst: pkt.dst_ip,
                 dst_port: 21,
                 kind: CredKind::FtpAuth,
+                count: 1,
                 note: first_line(payload, 80),
             });
         }
@@ -400,6 +412,7 @@ impl Observer {
                 dst: pkt.dst_ip,
                 dst_port: 23,
                 kind: CredKind::TelnetSession,
+                count: 1,
                 note: "Telnet session (cleartext)".to_string(),
             });
         }
@@ -413,6 +426,7 @@ impl Observer {
                     dst: pkt.dst_ip,
                     dst_port: pkt.dst_port,
                     kind: CredKind::HttpBasic,
+                    count: 1,
                     note: extract_line(payload, off, 120),
                 });
             }
@@ -504,6 +518,7 @@ impl Observer {
                             dst: pkt.dst_ip,
                             dst_port: pkt.dst_port,
                             kind: CredKind::Snmpv1v2c,
+                            count: 1,
                             note: format!(
                                 "SNMP{} (plaintext community string on the wire)",
                                 if v == 0 { "v1" } else { "v2c" }
```

---

## What the helper does

`Observer::record_cred_event` is a private method introduced by S-2.02. Instead of pushing
a new `CredEvent` unconditionally, it builds a tuple key `(src_ip, dst_ip, dst_port, kind)`
and looks up an internal `HashMap`. On the first observation the event is inserted with
`count: 1`. On every subsequent duplicate the existing entry's `count` is incremented via
`saturating_add(1)`, capping at `u32::MAX` rather than panicking (EC-003 in the story).
Distinct keys — e.g. the same `(src, dst, port)` pair with different `kind` values — are
stored as independent entries with independent counts (EC-001). The three unit tests cover
same-key dedup, distinct-kind isolation, and the N-duplicate property, all tracing to
BC-1.03.007.

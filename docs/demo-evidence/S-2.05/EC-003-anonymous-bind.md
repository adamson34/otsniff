# EC-003 — Anonymous bind suppression

## Test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/ldap_creds.rs (<REPO_ROOT>/target/debug/deps/ldap_creds-382b31e57a3a603e)

running 1 test
test test_bc_1_03_005_anonymous_bind_suppressed ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

Command: `cargo test --test ldap_creds test_bc_1_03_005_anonymous_bind_suppressed 2>&1 | tail -10`

## Implementation note

`LdapBindEvent` in `src/observe.rs` carries an `anonymous: bool` field:

```rust
pub struct LdapBindEvent {
    // ... src, dst, dst_port, version fields ...
    pub used_starttls: bool,
    /// `true` when the bind uses an empty DN and empty password (anonymous
    /// bind — well-known pattern, not a credential leak per EC-003).
    pub anonymous: bool,
}
```

The `anonymous` flag is set by the parser layer: `src/parse/ldap.rs` sets
`anonymous = pw_len == 0` after reading the `SimpleAuthentication`
OctetString length.  An empty password with any DN is treated the same way —
if `pw_len == 0`, the event is anonymous regardless of the DN value.

The detector (`src/findings/ldap_creds.rs`) filters out events where
`anonymous == true` before accumulating evidence, so anonymous binds never
produce a `creds.ldap_simple_bind` finding.

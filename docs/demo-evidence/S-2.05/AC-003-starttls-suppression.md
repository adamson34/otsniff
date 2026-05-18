# AC-003 — STARTTLS suppression (paired control test)

## Negative test output

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.05s
     Running tests/ldap_creds.rs (<REPO_ROOT>/target/debug/deps/ldap_creds-382b31e57a3a603e)

running 1 test
test test_bc_3_01_005_negative_post_starttls_bind_suppresses_finding ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

Command: `cargo test --test ldap_creds test_bc_3_01_005_negative 2>&1 | tail -10`

## Pairing note

The positive counterpart (`test_bc_3_01_005_positive_plaintext_bind_emits_critical_finding`)
lives in the same `tests/ldap_creds.rs` module and uses the same base fixture.
The positive test confirms that the firing path works; therefore the negative
test cannot be a vacuous pass — if the suppression logic were removed, the
negative test would fail.

## STARTTLS detection approach

STARTTLS state is tracked in `observe.rs` via a per-flow boolean in the
`ldap_starttls_flows` map. The observer detects the STARTTLS
`ExtendedRequest` / `ExtendedResponse` exchange using a byte-pattern heuristic
on the raw TCP payload (scanning for the STARTTLS OID `1.3.6.1.4.1.1466.20037`).
When a successful STARTTLS response is seen on a flow, `ldap_starttls_flows`
for that `FlowKey` is set to `true`.

At BindRequest ingest time (`observe.rs` lines ~560-572), the observer looks up
the flow key in `ldap_starttls_flows` and forwards `used_starttls: true` into
the emitted `LdapBindEvent`. The finding layer (`src/findings/ldap_creds.rs`)
then filters out any event where `used_starttls == true`.

The AC-003 integration test exercises this field-on-event mechanism directly by
constructing an `LdapBindEvent` with `used_starttls: true` and asserting zero
findings are emitted. Full `ExtendedResponse` BER parsing is intentionally
deferred — the byte-pattern heuristic is sufficient for the current scope and
avoids parser complexity disproportionate to the risk.

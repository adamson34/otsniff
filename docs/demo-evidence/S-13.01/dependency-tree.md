# Dependency Tree: `otsniff-privacy` (AC-001)

**Command:** `cargo tree -p otsniff-privacy --edges normal`

**Purpose:** Demonstrates the Forbidden Dependencies contract from the story
spec — `otsniff-privacy` depends on exactly `regex`, `serde`, `chrono`,
`sha2`, `thiserror` (per Library & Framework Requirements) and nothing else.
In particular there is no edge to `otsniff` (the root binary crate), no edge
to `zonewarden`, and none of `askama`/`pcap-parser`/`etherparse`/`clap`/
`ipnet`/`pulldown-cmark`/`serde_norway`.

```
otsniff-privacy v0.0.1 (<repo-root>/crates/otsniff-privacy)
├── chrono v0.4.45
│   ├── iana-time-zone v0.1.65
│   │   └── core-foundation-sys v0.8.7
│   ├── num-traits v0.2.19
│   └── serde v1.0.229
│       ├── serde_core v1.0.229
│       └── serde_derive v1.0.229 (proc-macro)
│           ├── proc-macro2 v1.0.106
│           │   └── unicode-ident v1.0.24
│           ├── quote v1.0.45
│           │   └── proc-macro2 v1.0.106 (*)
│           └── syn v3.0.3
│               ├── proc-macro2 v1.0.106 (*)
│               ├── quote v1.0.45 (*)
│               └── unicode-ident v1.0.24
├── regex v1.13.1
│   ├── aho-corasick v1.1.4
│   │   └── memchr v2.8.0
│   ├── memchr v2.8.0
│   ├── regex-automata v0.4.18
│   │   ├── aho-corasick v1.1.4 (*)
│   │   ├── memchr v2.8.0
│   │   └── regex-syntax v0.8.11
│   └── regex-syntax v0.8.11
├── serde v1.0.229 (*)
├── sha2 v0.11.0
│   ├── cfg-if v1.0.4
│   ├── cpufeatures v0.3.0
│   │   └── libc v0.2.186
│   └── digest v0.11.3
│       ├── block-buffer v0.12.1
│       │   └── hybrid-array v0.4.12
│       │       └── typenum v1.20.0
│       ├── const-oid v0.10.2
│       └── crypto-common v0.2.2
│           └── hybrid-array v0.4.12 (*)
└── thiserror v2.0.19
    └── thiserror-impl v2.0.19 (proc-macro)
        ├── proc-macro2 v1.0.106 (*)
        ├── quote v1.0.45 (*)
        └── syn v3.0.3 (*)
```

## Verification

The five direct-dependency top-level bullets are exactly `chrono`, `regex`,
`serde`, `sha2`, `thiserror` — matching the story's Library & Framework
Requirements table verbatim. There is no `otsniff` node, no `zonewarden`
node, and no `askama` / `pcap-parser` / `etherparse` / `clap` / `ipnet` /
`pulldown-cmark` / `serde_norway` node anywhere in the transitive closure.
This satisfies the Forbidden Dependencies contract and the AC-001
requirement that `otsniff-privacy` depend only on the five pinned crates.

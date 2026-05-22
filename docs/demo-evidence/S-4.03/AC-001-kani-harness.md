# AC-001: Kani Harness — map_value_substring

Source: `awk '/fn map_value_substring/,/^    }$/' src/ai/leak_detector.rs | head -50`

```
    fn map_value_substring() {
        use std::collections::BTreeMap;

        // ── Symbolic real value (the value stored in the map) ────────────────
        //
        // Bounded to ASCII alphanumeric bytes so `str::from_utf8` always
        // succeeds.  Non-empty: an empty real value is guarded in the
        // production code (skipped with `continue`) and is covered by EC-003.
        let value_len: usize = kani::any();
        kani::assume(value_len > 0 && value_len <= 8);
        let mut value_bytes = [0u8; 8];
        let mut vi = 0;
        while vi < value_len {
            let b: u8 = kani::any();
            kani::assume(b.is_ascii_alphanumeric() || b == b'-');
            value_bytes[vi] = b;
            vi += 1;
        }
        let value =
            std::str::from_utf8(&value_bytes[..value_len]).expect("ASCII bytes are valid UTF-8");

        // ── Symbolic input ────────────────────────────────────────────────────
        //
        // N = 16 input bytes, each printable ASCII.
        let input_len: usize = kani::any();
        kani::assume(input_len <= 16);
        let mut input_bytes = [0u8; 16];
        let mut ii = 0;
        while ii < input_len {
            let b: u8 = kani::any();
            kani::assume(b >= 0x20 && b <= 0x7e);
            input_bytes[ii] = b;
            ii += 1;
        }
        let input =
            std::str::from_utf8(&input_bytes[..input_len]).expect("printable ASCII is valid UTF-8");

        // ── Build a ScrubMap with K = 1 entry in `names` ─────────────────────
        let mut names = BTreeMap::new();
        names.insert("name_001".to_string(), value.to_string());
        let map = ScrubMap {
            version: 1,
            created_at: chrono::DateTime::from_timestamp(0, 0).expect("epoch is a valid timestamp"),
            ips: BTreeMap::new(),
            macs: BTreeMap::new(),
            names,
        };

        // ── Exercise the function ─────────────────────────────────────────────
        let result = ensure_no_map_values(input, &map);
```

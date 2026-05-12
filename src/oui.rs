//! Tiny embedded OUI → vendor lookup, focused on OT-relevant vendors.
//!
//! The full IEEE registry is ~30k entries; for v0.1 we ship a curated subset
//! that covers the vendors a plant tour is likely to see. If no match is
//! found we return None and the report shows the raw OUI bytes.

const TABLE: &[([u8; 3], &str)] = &[
    // Siemens
    ([0x00, 0x0E, 0x8C], "Siemens"),
    ([0x00, 0x1B, 0x1B], "Siemens"),
    ([0x00, 0x1F, 0xF8], "Siemens"),
    ([0x28, 0x63, 0x36], "Siemens"),
    ([0x8C, 0xF3, 0x19], "Siemens"),
    ([0x00, 0x0F, 0x69], "Siemens"),
    // Rockwell / Allen-Bradley
    ([0x00, 0x00, 0xBC], "Rockwell/Allen-Bradley"),
    ([0x00, 0x80, 0xE1], "Rockwell/Allen-Bradley"),
    ([0x00, 0x1D, 0x9C], "Rockwell/Allen-Bradley"),
    // Schneider / Modicon
    ([0x00, 0x00, 0x54], "Schneider Electric"),
    ([0x00, 0x80, 0xF4], "Schneider Electric"),
    ([0x00, 0x80, 0x99], "Schneider Electric"),
    // ABB
    ([0x00, 0x24, 0x59], "ABB"),
    ([0xAC, 0x64, 0x17], "ABB"),
    ([0x00, 0x0E, 0xDC], "ABB"),
    // Honeywell
    ([0x00, 0x0E, 0x14], "Honeywell"),
    ([0x00, 0x40, 0x9D], "Honeywell"),
    ([0x00, 0xD0, 0x95], "Honeywell"),
    // GE / Emerson
    ([0x00, 0x00, 0x1A], "GE"),
    ([0x00, 0x0F, 0x11], "GE"),
    ([0x00, 0x1C, 0x46], "GE"),
    // Yokogawa
    ([0x00, 0x00, 0x64], "Yokogawa"),
    ([0x00, 0x11, 0xB0], "Yokogawa"),
    // Mitsubishi
    ([0x00, 0x00, 0xF4], "Mitsubishi"),
    ([0x00, 0x25, 0x96], "Mitsubishi"),
    // Omron
    ([0x00, 0x00, 0x0D], "Omron"),
    ([0x00, 0x80, 0xF0], "Omron"),
    // B&R
    ([0x00, 0x60, 0x65], "B&R Industrial Automation"),
    // Phoenix Contact
    ([0x00, 0xA0, 0x45], "Phoenix Contact"),
    // WAGO
    ([0x00, 0x30, 0xDE], "WAGO"),
    // Beckhoff
    ([0x00, 0x01, 0x05], "Beckhoff"),
    // Hilscher
    ([0x00, 0x02, 0xA2], "Hilscher"),
    // Moxa
    ([0x00, 0x90, 0xE8], "Moxa"),
    // Hirschmann (Belden — common ICS switch)
    ([0x00, 0x80, 0x63], "Hirschmann"),
    // Schweitzer Engineering Labs (SEL — protective relays, very common in utilities)
    ([0x00, 0x30, 0xA7], "Schweitzer Engineering"),
    ([0x00, 0x1C, 0x44], "Schweitzer Engineering"),
    // SEL/Sel-Inc historical
    ([0x00, 0x10, 0x21], "Schweitzer Engineering"),
    // Cisco (very common in IT/OT)
    ([0x00, 0x1B, 0x53], "Cisco"),
    ([0x00, 0x1E, 0x14], "Cisco"),
    ([0x00, 0x21, 0x55], "Cisco"),
    // Common IT vendors that show up on plant networks
    ([0x00, 0x50, 0x56], "VMware"),
    ([0x00, 0x0C, 0x29], "VMware"),
    ([0xDC, 0xA6, 0x32], "Raspberry Pi"),
];

pub fn lookup(mac: &[u8; 6]) -> Option<&'static str> {
    let prefix = [mac[0], mac[1], mac[2]];
    TABLE.iter().find(|(p, _)| *p == prefix).map(|(_, v)| *v)
}

pub fn format_oui(mac: &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2])
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_at_least_3000_entries() {
        assert!(
            TABLE.len() >= 3000,
            "expanded OUI table must have ≥ 3000 entries (P0-6 / L-P2-003); has {}",
            TABLE.len()
        );
    }

    #[test]
    fn table_is_sorted_by_prefix() {
        for window in TABLE.windows(2) {
            let (a, _) = window[0];
            let (b, _) = window[1];
            assert!(
                a <= b,
                "TABLE must be sorted by prefix for binary_search; found {a:02X?} >= {b:02X?}"
            );
        }
    }

    #[test]
    fn table_resolves_named_industrial_vendors() {
        // Sentinel set: at least one known OUI for each must resolve to the
        // expected vendor family. Implementer can pick any real OUI for the
        // named vendor; this test just asserts presence.
        let must_resolve = [
            // (a real OUI, expected vendor name substring)
            ("Beckhoff",        "Beckhoff"),
            ("Moxa",            "Moxa"),
            ("Phoenix Contact", "Phoenix"),
            ("Yokogawa",        "Yokogawa"),
            ("Hilscher",        "Hilscher"),
            ("WAGO",            "WAGO"),
            ("Mitsubishi",      "Mitsubishi"),
            ("Omron",           "Omron"),
            ("GE / GE Fanuc",   "GE"),
            ("Emerson",         "Emerson"),
        ];
        let resolved_vendors: std::collections::HashSet<&str> =
            TABLE.iter().map(|(_, v)| *v).collect();
        for (label, needle) in must_resolve {
            let hit = resolved_vendors.iter().any(|v| v.contains(needle));
            assert!(hit, "table must contain a {label} OUI (looking for {needle:?})");
        }
    }

    #[test]
    fn table_resolves_common_it_vendors() {
        // OT networks include IT vendors. Major ones must resolve.
        let must_resolve = ["Cisco", "Dell", "HP", "VMware", "Microsoft", "Intel"];
        let resolved_vendors: std::collections::HashSet<&str> =
            TABLE.iter().map(|(_, v)| *v).collect();
        for needle in must_resolve {
            let hit = resolved_vendors.iter().any(|v| v.contains(needle));
            assert!(hit, "table must contain an OUI for {needle}");
        }
    }

    #[test]
    fn lookup_uses_binary_search() {
        // Indirect proof: 10,000 random-ish lookups complete in under 50 ms.
        // Linear scan over 3000 entries × 10k lookups = 30M comparisons —
        // would take seconds. Binary search is sub-millisecond per call.
        //
        // NOTE: This test passes today on the ~41-entry table because linear
        // scan over 41 entries is also fast. It acts as a soft signal that
        // will enforce binary_search once the implementer expands the table
        // to ≥ 3000 entries (where linear would reliably exceed 50 ms).
        use std::time::Instant;
        let mut mac = [0u8; 6];
        let start = Instant::now();
        for i in 0..10_000u32 {
            mac[0] = (i & 0xff) as u8;
            mac[1] = ((i >> 8) & 0xff) as u8;
            mac[2] = ((i >> 16) & 0xff) as u8;
            let _ = lookup(&mac);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 50,
            "lookup() must use binary_search (10k calls took {} ms; expected <50 ms)",
            elapsed.as_millis()
        );
    }
}

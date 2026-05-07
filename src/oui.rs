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

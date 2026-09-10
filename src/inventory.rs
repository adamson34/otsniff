//! Asset inventory derivation from raw observations.
//!
//! Takes the per-host observations the parser collected and infers a role
//! (PLC / HMI / EWS / historian / IT / unknown) based on which protocols the
//! host *spoke* and which ports it listened on.

use std::net::IpAddr;

use serde::Serialize;

use crate::observe::{HostObs, Observations};
use crate::oui;

#[derive(Debug, Clone, Serialize)]
pub struct Asset {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub role: Role,
    pub protocols: Vec<String>,
    pub packets: u64,
    pub bytes: u64,
    pub in_ot_zone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Role {
    Plc,
    Hmi,
    EngineeringWorkstation,
    Historian,
    NetworkInfra,
    ItEndpoint,
    Unknown,
}

impl Role {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Plc => "PLC / controller",
            Self::Hmi => "HMI",
            Self::EngineeringWorkstation => "Engineering workstation",
            Self::Historian => "Historian / data sink",
            Self::NetworkInfra => "Network infrastructure",
            Self::ItEndpoint => "IT endpoint",
            Self::Unknown => "Unknown",
        }
    }
}

pub fn build(obs: &Observations) -> Vec<Asset> {
    let mut assets: Vec<Asset> = obs.hosts.values().map(|h| host_to_asset(h, obs)).collect();
    assets.sort_by(|a, b| {
        b.in_ot_zone
            .cmp(&a.in_ot_zone)
            .then_with(|| a.ip.cmp(&b.ip))
    });
    assets
}

/// Above this many distinct hosts, the rendered inventory table is capped
/// to the top-N by traffic rather than listing every row (P1-10). A
/// legitimate network essentially never has this many distinct hosts on
/// one capture; the common cause is a spoofed-source flood inflating the
/// host count into the thousands (see `findings::spoofed_sources`).
pub const RENDER_CAP: usize = 100;

/// Selects which assets the HTML/markdown renderers should list, and an
/// optional human-readable note when the full inventory was capped.
///
/// At or under [`RENDER_CAP`] hosts, returns every asset unchanged (same
/// order `build` produced) and `None` — existing small-capture output is
/// untouched. Above the cap, re-sorts by traffic (packets, descending) and
/// returns only the top [`RENDER_CAP`], plus a note naming how many were
/// omitted. This is a rendering-only decision: callers that need the full,
/// uncapped inventory (role-shift diffing, the OT-zone count in the report
/// header) should keep using the `Vec<Asset>` from [`build`] directly.
pub fn capped_for_render(inventory: &[Asset]) -> (Vec<&Asset>, Option<String>) {
    if inventory.len() <= RENDER_CAP {
        return (inventory.iter().collect(), None);
    }
    let omitted = inventory.len() - RENDER_CAP;
    let mut by_traffic: Vec<&Asset> = inventory.iter().collect();
    by_traffic.sort_by(|a, b| b.packets.cmp(&a.packets).then_with(|| a.ip.cmp(&b.ip)));
    by_traffic.truncate(RENDER_CAP);
    let note = format!(
        "Showing the top {RENDER_CAP} hosts by traffic. {omitted} additional low-volume \
         host(s) omitted from this table — a host count this large usually means spoofed \
         source addresses (see the attack.spoofed_sources finding, if present), not that \
         many genuine hosts on the network."
    );
    (by_traffic, Some(note))
}

fn host_to_asset(host: &HostObs, obs: &Observations) -> Asset {
    let mac = host.macs.first().copied();
    let vendor = mac.and_then(|m| oui::lookup(&m).map(str::to_string));
    let role = infer_role(host, vendor.as_deref());
    let mut protocols: Vec<String> = host.protocols.iter().cloned().collect();
    protocols.sort();
    let hostname = obs.hostnames.get(&host.ip).cloned();
    Asset {
        ip: host.ip,
        hostname,
        mac: mac.map(|m| oui::format_mac(&m)),
        vendor,
        role,
        protocols,
        packets: host.packets,
        bytes: host.bytes,
        in_ot_zone: host.in_ot_zone,
    }
}

fn infer_role(host: &HostObs, vendor: Option<&str>) -> Role {
    let speaks = |p: &str| host.protocols.iter().any(|s| s == p);

    // Strong PLC signals: speaks Modbus + vendor is a PLC vendor, or speaks ENIP/S7.
    let plc_vendors = [
        "Siemens",
        "Rockwell/Allen-Bradley",
        "Schneider Electric",
        "ABB",
        "GE",
        "Mitsubishi",
        "Omron",
        "B&R Industrial Automation",
        "Beckhoff",
        "WAGO",
    ];
    let is_plc_vendor = vendor.map(|v| plc_vendors.contains(&v)).unwrap_or(false);

    if speaks("s7comm") || speaks("enip") || speaks("dnp3") || (speaks("modbus") && is_plc_vendor) {
        return Role::Plc;
    }

    // Host speaks any ICS protocol and *only* ICS protocols → almost certainly
    // a controller/IED/relay. Distinct rule so we don't accidentally flag
    // mixed-use boxes (engineering workstations talking Modbus + SMB) as PLCs.
    let ics = [
        "modbus",
        "enip",
        "s7comm",
        "dnp3",
        "opcua",
        "bacnet",
        "fox-niagara",
    ];
    let speaks_any_ics = host.protocols.iter().any(|p| ics.contains(&p.as_str()));
    let speaks_only_ics =
        !host.protocols.is_empty() && host.protocols.iter().all(|p| ics.contains(&p.as_str()));
    if speaks_any_ics && speaks_only_ics {
        return Role::Plc;
    }

    // SCADA/HMI: talks to many controllers + speaks HTTP or VNC or RDP locally.
    // We don't have flow-direction smarts here; rough heuristic.
    if speaks("modbus") && (speaks("http") || speaks("rdp") || speaks("smb")) {
        return Role::Hmi;
    }

    // Engineering workstation: Windows-y protocols + speaks ICS protocols
    if (speaks("smb") || speaks("rdp") || speaks("netbios"))
        && (speaks("modbus") || speaks("enip") || speaks("s7comm"))
    {
        return Role::EngineeringWorkstation;
    }

    // Historian: lots of inbound ICS reads + a database/HTTP sink
    if speaks("modbus") && speaks("https") {
        return Role::Historian;
    }

    if let Some(v) = vendor {
        if matches!(v, "Cisco" | "Hirschmann" | "Moxa") {
            return Role::NetworkInfra;
        }
    }

    if speaks("smb") || speaks("rdp") || speaks("netbios") || speaks("https") {
        return Role::ItEndpoint;
    }

    Role::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(n: u8, packets: u64) -> Asset {
        Asset {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n)),
            hostname: None,
            mac: None,
            vendor: None,
            role: Role::Unknown,
            protocols: Vec::new(),
            packets,
            bytes: 0,
            in_ot_zone: false,
        }
    }

    #[test]
    fn at_or_under_cap_returns_every_asset_unchanged_order_no_note() {
        let assets: Vec<Asset> = (0..RENDER_CAP as u8).map(|i| asset(i, 1)).collect();
        let (rendered, note) = capped_for_render(&assets);
        assert_eq!(rendered.len(), assets.len());
        assert!(note.is_none());
        // Order preserved exactly as `build` produced it — no re-sort below the cap.
        for (a, b) in rendered.iter().zip(assets.iter()) {
            assert_eq!(a.ip, b.ip);
        }
    }

    #[test]
    fn over_cap_truncates_to_top_n_by_traffic_with_a_note() {
        // RENDER_CAP + 50 assets, packet counts inverse to index so the
        // highest-traffic assets are NOT the ones `build`'s (zone, ip) sort
        // would have put first — proves the re-sort actually happens.
        let total = RENDER_CAP + 50;
        let assets: Vec<Asset> = (0..total)
            .map(|i| asset((i % 256) as u8, (total - i) as u64))
            .collect();
        let (rendered, note) = capped_for_render(&assets);
        assert_eq!(rendered.len(), RENDER_CAP);
        let note = note.expect("omitting hosts must produce a note");
        assert!(note.contains("50"));
        assert!(note.contains(&RENDER_CAP.to_string()));
        // Top-N by traffic: packets must be non-increasing across the kept rows.
        for w in rendered.windows(2) {
            assert!(w[0].packets >= w[1].packets);
        }
        // The single highest-traffic asset (packets = total) must be first.
        assert_eq!(rendered[0].packets, total as u64);
    }
}

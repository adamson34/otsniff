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

fn host_to_asset(host: &HostObs, _obs: &Observations) -> Asset {
    let mac = host.macs.first().copied();
    let vendor = mac.and_then(|m| oui::lookup(&m).map(str::to_string));
    let role = infer_role(host, vendor.as_deref());
    let mut protocols: Vec<String> = host.protocols.iter().cloned().collect();
    protocols.sort();
    Asset {
        ip: host.ip,
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

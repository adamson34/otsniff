use std::net::IpAddr;

use crate::observe::Observations;

use super::{host_label, Finding, Reference, ReferenceKind, RuleMetadata, Severity};

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "compat.smbv1",
    title: "SMBv1 traffic observed",
    severity: Severity::High,
    trigger: "Fires when at least one TCP/445 or TCP/139 packet carries \
              the SMB1 magic bytes (`\\xFF SMB`) at offset 0 (raw SMB) \
              or offset 4 (after an NBSS session-message header). SMB1 \
              has been deprecated by Microsoft since 2014 and is \
              blocked by default in modern Windows; its presence \
              indicates a legacy client or server. Same protocol \
              family the EternalBlue / WannaCry exploits abused.",
    data_source: &["smbv1_packets"],
    references: &[
        Reference {
            kind: ReferenceKind::Cve,
            label: "CVE-2017-0144 — MS17-010 / EternalBlue (SMBv1 RCE)",
            url: Some("https://nvd.nist.gov/vuln/detail/CVE-2017-0144"),
        },
        Reference {
            kind: ReferenceKind::Vendor,
            label: "Microsoft — Stop using SMB1",
            url: Some("https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows"),
        },
    ],
};

pub fn detect(obs: &Observations) -> Vec<Finding> {
    if obs.smbv1_packets.is_empty() {
        return Vec::new();
    }

    // Group by (src, dst, dst_port) and sort by packet count desc.
    let mut sorted: Vec<((IpAddr, IpAddr, u16), u64)> =
        obs.smbv1_packets.iter().map(|(k, v)| (*k, *v)).collect();
    sorted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let total_packets: u64 = sorted.iter().map(|(_, n)| n).sum();
    let pair_count = sorted.len();
    let distinct_hosts: std::collections::BTreeSet<IpAddr> =
        sorted.iter().flat_map(|((s, d, _), _)| [*s, *d]).collect();

    let evidence: Vec<String> = sorted
        .iter()
        .take(15)
        .map(|((src, dst, port), n)| {
            format!(
                "{} -> {}:{port} ({n} SMBv1 packet(s))",
                host_label(*src, obs),
                host_label(*dst, obs),
            )
        })
        .collect();

    let summary = format!(
        "{total_packets} SMBv1 packet(s) seen across {pair_count} host pair(s). SMBv1 is \
         deprecated, blocked by default in modern Windows, and a known exploitation surface \
         (WannaCry / EternalBlue). Its presence indicates legacy clients, legacy servers, or both."
    );

    let host_list = format_host_list(&distinct_hosts);

    let playbook = vec![
        format!(
            "Identify the hosts physically: {host_list}. Walk each MAC to a switch port \
             using the asset inventory's MAC for that host."
        ),
        "For Windows hosts: disable SMB1 via Group Policy (Computer Configuration → Policies → \
         Windows Settings → Security Settings → ...) or PowerShell \
         (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`). After SMB1 is off, \
         a host that legitimately needed it will fail loudly — better than failing silently."
            .to_string(),
        "For embedded / OT-class devices that can only speak SMB1 (older Moxa NAS, legacy HMI \
         file shares): isolate on a hardened management VLAN, document the exception with a \
         decommission target date. Do not just leave it on the OT VLAN with no plan."
            .to_string(),
        "Patch / decommission known-vulnerable Windows versions (Windows 7, Server 2008 / 2008 \
         R2 without SMB1-disable) that depend on SMB1 for file shares. These are the hosts \
         WannaCry-class malware actually pivoted through."
            .to_string(),
        "Audit the OT-zone firewall ruleset for SMB allow rules between zones. SMB / CIFS file \
         transfer should not cross the IT/OT boundary in either direction outside narrow, \
         documented operational paths."
            .to_string(),
    ];

    vec![Finding {
        id: "compat.smbv1",
        severity: Severity::High,
        title: "SMBv1 traffic on the wire".to_string(),
        summary,
        evidence,
        recommendation: "Identify the legacy hosts and migrate to SMBv2/v3 or retire. Disable SMB1 via Group Policy on Windows hosts. SMBv1 is the protocol EternalBlue / WannaCry exploited; its presence is a known-bad pattern.",
        playbook,
    }]
}

fn format_host_list(hosts: &std::collections::BTreeSet<IpAddr>) -> String {
    let v: Vec<IpAddr> = hosts.iter().copied().collect();
    match v.len() {
        0 => "the listed hosts".to_string(),
        1 => format!("`{}`", v[0]),
        2 => format!("`{}` and `{}`", v[0], v[1]),
        n if n <= 4 => v
            .iter()
            .map(|ip| format!("`{ip}`"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => format!("`{}` and {} other host(s)", v[0], v.len() - 1),
    }
}

//! Minimal DHCPv4 parser.
//!
//! v0.1 fidelity: extract host name (option 12) and the IP it should
//! be associated with. We use:
//!   - `yiaddr` if non-zero (DHCP ACK sets this to the assigned IP)
//!   - `ciaddr` if non-zero (DHCP REQUEST during renewal)
//!   - option 50 (Requested IP Address) as a last resort
//!
//! No support for DHCPv6, no FQDN option (81), no full option-walk —
//! we only look at the options we care about.

use std::net::Ipv4Addr;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const FIXED_HEADER_LEN: usize = 240; // bytes through the magic cookie

const OPT_PAD: u8 = 0x00;
const OPT_END: u8 = 0xFF;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_HOSTNAME: u8 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpInfo {
    pub ip: Ipv4Addr,
    pub hostname: String,
}

/// Parse a DHCP packet payload. Returns `None` if the payload doesn't
/// look like DHCP, has no hostname option, or has no usable IP to
/// associate the hostname with.
pub fn parse(payload: &[u8]) -> Option<DhcpInfo> {
    if payload.len() < FIXED_HEADER_LEN {
        return None;
    }
    if payload[236..240] != MAGIC_COOKIE {
        return None;
    }

    let ciaddr = Ipv4Addr::from([payload[12], payload[13], payload[14], payload[15]]);
    let yiaddr = Ipv4Addr::from([payload[16], payload[17], payload[18], payload[19]]);

    let mut hostname: Option<String> = None;
    let mut requested_ip: Option<Ipv4Addr> = None;

    let mut i = FIXED_HEADER_LEN;
    while i < payload.len() {
        let code = payload[i];
        match code {
            OPT_END => break,
            OPT_PAD => {
                i += 1;
                continue;
            }
            _ => {}
        }
        if i + 1 >= payload.len() {
            return None;
        }
        let len = payload[i + 1] as usize;
        let data_start = i + 2;
        let data_end = data_start + len;
        if data_end > payload.len() {
            return None;
        }
        let data = &payload[data_start..data_end];

        match code {
            OPT_HOSTNAME => {
                // Hostname is ASCII. Strip non-printable bytes
                // defensively rather than reject.
                let s: String = data
                    .iter()
                    .filter(|&&b| (0x20..0x7F).contains(&b))
                    .map(|&b| b as char)
                    .collect();
                if !s.is_empty() {
                    hostname = Some(s);
                }
            }
            OPT_REQUESTED_IP if len == 4 => {
                requested_ip = Some(Ipv4Addr::from([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }

        i = data_end;
    }

    let name = hostname?;
    let ip = if !yiaddr.is_unspecified() {
        yiaddr
    } else if !ciaddr.is_unspecified() {
        ciaddr
    } else {
        requested_ip.filter(|req| !req.is_unspecified())?
    };

    Some(DhcpInfo { ip, hostname: name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(yiaddr: [u8; 4], ciaddr: [u8; 4], options: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; FIXED_HEADER_LEN];
        buf[12..16].copy_from_slice(&ciaddr);
        buf[16..20].copy_from_slice(&yiaddr);
        buf[236..240].copy_from_slice(&MAGIC_COOKIE);
        buf.extend_from_slice(options);
        buf.push(OPT_END);
        buf
    }

    #[test]
    fn dhcp_ack_with_yiaddr_and_hostname() {
        let opts = [OPT_HOSTNAME, 5, b'P', b'L', b'C', b'-', b'1'];
        let pkt = build([10, 10, 10, 10], [0, 0, 0, 0], &opts);
        let info = parse(&pkt).expect("parses");
        assert_eq!(info.ip, Ipv4Addr::new(10, 10, 10, 10));
        assert_eq!(info.hostname, "PLC-1");
    }

    #[test]
    fn dhcp_request_with_ciaddr_renewal() {
        let opts = [
            OPT_HOSTNAME,
            8,
            b'H',
            b'M',
            b'I',
            b'-',
            b'M',
            b'A',
            b'I',
            b'N',
        ];
        let pkt = build([0, 0, 0, 0], [10, 10, 10, 5], &opts);
        let info = parse(&pkt).expect("parses");
        assert_eq!(info.ip, Ipv4Addr::new(10, 10, 10, 5));
        assert_eq!(info.hostname, "HMI-MAIN");
    }

    #[test]
    fn dhcp_request_with_requested_ip_option() {
        // DISCOVER-style: ciaddr 0, yiaddr 0, but option 50 has the
        // requested IP, and option 12 has the hostname.
        let opts = [
            OPT_HOSTNAME,
            3,
            b'A',
            b'A',
            b'A',
            OPT_REQUESTED_IP,
            4,
            10,
            10,
            10,
            7,
        ];
        let pkt = build([0, 0, 0, 0], [0, 0, 0, 0], &opts);
        let info = parse(&pkt).expect("parses");
        assert_eq!(info.ip, Ipv4Addr::new(10, 10, 10, 7));
        assert_eq!(info.hostname, "AAA");
    }

    #[test]
    fn rejects_no_magic_cookie() {
        let mut pkt = vec![0u8; FIXED_HEADER_LEN];
        // Missing magic cookie at offset 236
        assert!(parse(&pkt).is_none());

        // Wrong magic cookie
        pkt[236..240].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn rejects_no_hostname_option() {
        let pkt = build([10, 10, 10, 10], [0, 0, 0, 0], &[]);
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn rejects_short_payload() {
        assert!(parse(&[0u8; 100]).is_none());
    }

    #[test]
    fn handles_pad_options_between_real_options() {
        let opts = [OPT_PAD, OPT_PAD, OPT_HOSTNAME, 3, b'X', b'Y', b'Z'];
        let pkt = build([10, 0, 0, 1], [0, 0, 0, 0], &opts);
        let info = parse(&pkt).expect("parses");
        assert_eq!(info.hostname, "XYZ");
    }
}

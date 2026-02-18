use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddrV6};
use tracing::{debug, error, info};

const RA_INTERVAL_SECS: u64 = 30;

/// Build an ICMPv6 Router Advertisement packet.
/// Flags: M=1 (managed address config), O=1 (other config)
fn build_ra() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(16);
    pkt.push(134); // ICMPv6 Type: Router Advertisement
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0, 0]); // Checksum (kernel fills for raw socket)
    pkt.push(64); // Cur Hop Limit
    pkt.push(0xC0); // Flags: M=1, O=1 (bits 7 and 6)
    pkt.extend_from_slice(&[0x07, 0x08]); // Router Lifetime: 1800s (tells clients this is a default router)
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Reachable Time: 0 (unspecified)
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Retrans Timer: 0 (unspecified)
    // No prefix information option — devices must use DHCPv6
    pkt
}

/// Send RAs periodically on the LAN interface.
pub fn run_ra_sender(lan_iface: &str) -> Result<()> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    sock.bind_device(Some(lan_iface.as_bytes()))?;

    // Set hop limit to 255 (required for NDP)
    sock.set_multicast_hops_v6(255)?;
    sock.set_unicast_hops_v6(255)?;

    // All-nodes multicast: ff02::1
    let dest = SocketAddrV6::new("ff02::1".parse::<Ipv6Addr>().unwrap(), 0, 0, 0);

    let ra = build_ra();

    info!(iface = lan_iface, "starting RA sender");

    loop {
        if let Err(e) = sock.send_to(&ra, &dest.into()) {
            error!(error = %e, "failed to send RA");
        } else {
            debug!("sent RA");
        }
        std::thread::sleep(std::time::Duration::from_secs(RA_INTERVAL_SECS));
    }
}

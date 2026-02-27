use anyhow::Result;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Read;
use std::net::{Ipv6Addr, SocketAddrV6};
use tracing::{debug, error, info};

const MIN_RA_INTERVAL_SECS: u64 = 20;
const MAX_RA_INTERVAL_SECS: u64 = 40;
const MAX_INITIAL_RA_INTERVAL_SECS: u64 = 16;
const INITIAL_RA_COUNT: u32 = 3;
const RS_RESPONSE_MAX_DELAY_MS: u64 = 500;

/// Read the MAC address of a network interface from sysfs.
fn read_iface_mac(iface: &str) -> Option<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let content = std::fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = content.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Build an ICMPv6 Router Advertisement packet.
/// Flags: M=1 (managed address config), O=1 (other config)
fn build_ra(mac: Option<[u8; 6]>) -> Vec<u8> {
    let base_len = 16 + if mac.is_some() { 8 } else { 0 };
    let mut pkt = Vec::with_capacity(base_len);
    pkt.push(134); // ICMPv6 Type: Router Advertisement
    pkt.push(0); // Code
    pkt.extend_from_slice(&[0, 0]); // Checksum (kernel fills)
    pkt.push(64); // Cur Hop Limit
    pkt.push(0xC0); // Flags: M=1, O=1
    pkt.extend_from_slice(&[0x07, 0x08]); // Router Lifetime: 1800s
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Reachable Time: 0
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Retrans Timer: 0

    // L2: Source Link-Layer Address option (RFC 4861 section 4.6.1)
    if let Some(mac) = mac {
        pkt.push(1); // Type: Source Link-Layer Address
        pkt.push(1); // Length: 1 (in units of 8 octets)
        pkt.extend_from_slice(&mac);
    }

    pkt
}

/// Send RAs periodically and in response to Router Solicitations.
pub fn run_ra_sender(lan_iface: &str) -> Result<()> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    sock.bind_device(Some(lan_iface.as_bytes()))?;
    sock.set_multicast_hops_v6(255)?;
    sock.set_unicast_hops_v6(255)?;

    let dest = SocketAddrV6::new(
        "ff02::1".parse::<Ipv6Addr>().expect("valid multicast addr"),
        0,
        0,
        0,
    );
    let mac = read_iface_mac(lan_iface);
    let ra = build_ra(mac);

    info!(iface = lan_iface, "starting RA sender");

    let mut rng = rand::thread_rng();
    let mut ra_count = 0u32;
    let mut buf = [0u8; 1500];

    loop {
        // L3: Initial burst -- first RA immediate, next 2 at <=16s, then randomized
        let interval_secs = if ra_count < INITIAL_RA_COUNT {
            if ra_count == 0 {
                0
            } else {
                MAX_INITIAL_RA_INTERVAL_SECS
            }
        } else {
            // L1: Randomized steady-state interval (RFC 4861 section 6.2.4)
            rng.gen_range(MIN_RA_INTERVAL_SECS..=MAX_RA_INTERVAL_SECS)
        };

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(interval_secs);

        // H20: Poll for Router Solicitations until the next periodic RA is due
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            sock.set_read_timeout(Some(remaining))?;
            match (&sock).read(&mut buf) {
                Ok(len) if len >= 1 && buf[0] == 133 => {
                    // RS received -- respond after random 0..500ms delay
                    // (RFC 4861 section 6.2.6)
                    let delay_ms = rng.gen_range(0..=RS_RESPONSE_MAX_DELAY_MS);
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    if let Err(e) = sock.send_to(&ra, &dest.into()) {
                        error!(error = %e, "failed to send RA (RS response)");
                    } else {
                        debug!("sent RA in response to RS");
                    }
                }
                Ok(_) => {} // Too short or not RS, ignore
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break; // Timeout reached, send periodic RA
                }
                Err(e) => {
                    debug!(error = %e, "RS recv error");
                }
            }
        }

        // Send periodic RA
        sock.set_read_timeout(None)?;
        if let Err(e) = sock.send_to(&ra, &dest.into()) {
            error!(error = %e, "failed to send RA");
        } else {
            debug!("sent periodic RA");
        }
        ra_count = ra_count.saturating_add(1);
    }
}

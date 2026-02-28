use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use dhcproto::v4::{self, DhcpOption, Decodable, Decoder, Encodable, Encoder, MessageType, OptionCode};
use dhcproto::v6;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{error, info, warn};

use crate::db;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// Represents a WAN lease obtained via DHCP or configured statically.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WanLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub renew_at: Instant,
    pub rebind_at: Instant,
    pub delegated_prefix: Option<String>,
    pub prefix_valid_lifetime: Option<u32>,
}

pub type SharedWanLease = Arc<Mutex<Option<WanLease>>>;

/// Spawn the WAN management task. Returns the shared lease handle.
pub fn start(wan_iface: String, db: Arc<Mutex<db::Db>>) -> SharedWanLease {
    let lease: SharedWanLease = Arc::new(Mutex::new(None));
    let lease_clone = lease.clone();
    tokio::spawn(async move {
        if let Err(e) = run_wan(&wan_iface, &db, &lease_clone).await {
            error!(error = %e, "WAN management task failed");
        }
    });
    lease
}

/// Read wan_mode from DB and dispatch to the appropriate handler.
async fn run_wan(
    wan_iface: &str,
    db: &Arc<Mutex<db::Db>>,
    lease: &SharedWanLease,
) -> Result<()> {
    let wan_mode = {
        let db_guard = db.lock().unwrap();
        db_guard
            .get_config("wan_mode")
            .ok()
            .flatten()
            .unwrap_or_else(|| "dhcp".into())
    };

    info!(mode = %wan_mode, iface = %wan_iface, "WAN mode selected");

    match wan_mode.as_str() {
        "static" => run_static(wan_iface, db, lease).await,
        "dhcp" | _ => run_dhcp(wan_iface, db, lease).await,
    }
}

/// Apply static WAN configuration from DB settings.
async fn run_static(
    wan_iface: &str,
    db: &Arc<Mutex<db::Db>>,
    lease: &SharedWanLease,
) -> Result<()> {
    let (ip_str, gateway_str, dns_str) = {
        let db_guard = db.lock().unwrap();
        let ip = db_guard
            .get_config("wan_static_ip")
            .ok()
            .flatten()
            .unwrap_or_default();
        let gw = db_guard
            .get_config("wan_static_gateway")
            .ok()
            .flatten()
            .unwrap_or_default();
        let dns = db_guard
            .get_config("wan_static_dns")
            .ok()
            .flatten()
            .unwrap_or_default();
        (ip, gw, dns)
    };

    if ip_str.is_empty() || gateway_str.is_empty() {
        anyhow::bail!("wan_static_ip and wan_static_gateway must be set for static mode");
    }

    // Parse IP — may include CIDR prefix (e.g. "192.168.1.100/24")
    let (ip_addr, cidr) = if let Some((addr, prefix)) = ip_str.split_once('/') {
        (addr.parse::<Ipv4Addr>()?, format!("{}/{}", addr, prefix))
    } else {
        (ip_str.parse::<Ipv4Addr>()?, format!("{}/24", ip_str))
    };

    let gateway: Ipv4Addr = gateway_str.parse()?;

    let dns_servers: Vec<Ipv4Addr> = if dns_str.is_empty() {
        vec![gateway]
    } else {
        dns_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    };

    // Flush existing addresses on WAN interface
    let _ = Command::new("/usr/sbin/ip")
        .args(["addr", "flush", "dev", wan_iface])
        .status();

    // Add static IP
    let status = Command::new("/usr/sbin/ip")
        .args(["addr", "add", &cidr, "dev", wan_iface])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to add address {} to {}", cidr, wan_iface);
    }

    // Bring interface up
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "set", wan_iface, "up"])
        .status();

    // Add default route via gateway
    let _ = Command::new("/usr/sbin/ip")
        .args(["route", "del", "default"])
        .status();
    let status = Command::new("/usr/sbin/ip")
        .args(["route", "add", "default", "via", &gateway_str, "dev", wan_iface])
        .status()?;
    if !status.success() {
        warn!(gateway = %gateway_str, "failed to add default route");
    }

    // Derive subnet mask from prefix length
    let prefix_len: u32 = if let Some((_, p)) = ip_str.split_once('/') {
        p.parse().unwrap_or(24)
    } else {
        24
    };
    let mask_bits = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let subnet_mask = Ipv4Addr::from(mask_bits);

    let now = Instant::now();
    let wan_lease = WanLease {
        ip: ip_addr,
        subnet_mask,
        gateway,
        dns_servers: dns_servers.clone(),
        lease_time: u32::MAX, // static — never expires
        renew_at: now + std::time::Duration::from_secs(u64::MAX / 2),
        rebind_at: now + std::time::Duration::from_secs(u64::MAX / 2),
        delegated_prefix: None,
        prefix_valid_lifetime: None,
    };

    {
        let mut guard = lease.lock().unwrap();
        *guard = Some(wan_lease);
    }

    info!(
        ip = %ip_addr,
        gateway = %gateway,
        dns = ?dns_servers,
        "static WAN configured"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// DHCPv4 client implementation
// ---------------------------------------------------------------------------

/// Create a UDP socket bound to the given interface for DHCP.
/// Uses socket2 for SO_BROADCAST and SO_BINDTODEVICE, then converts
/// to a std UdpSocket for safe recv/send.
fn make_dhcp_socket(iface: &str, bind_ip: Ipv4Addr) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating DHCP socket")?;
    sock.set_broadcast(true)?;
    sock.set_reuse_address(true)?;
    sock.bind_device(Some(iface.as_bytes()))?;
    let bind_addr = SockAddr::from(SocketAddrV4::new(bind_ip, DHCP_CLIENT_PORT));
    sock.bind(&bind_addr)
        .with_context(|| format!("binding to {}:68", bind_ip))?;
    sock.set_nonblocking(false)?;
    Ok(UdpSocket::from(sock))
}

/// Read the MAC address for the given interface from sysfs.
fn get_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", iface);
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("reading MAC from {}", path))?;
    let trimmed = contents.trim();
    let bytes: Vec<u8> = trimmed
        .split(':')
        .map(|hex_byte| u8::from_str_radix(hex_byte, 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing MAC address: {}", trimmed))?;
    if bytes.len() != 6 {
        bail!("unexpected MAC length {} for {}", bytes.len(), iface);
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Ok(mac)
}

/// Build a DHCPv4 DISCOVER message.
fn build_discover(xid: u32, mac: &[u8; 6]) -> Vec<u8> {
    let mut msg = v4::Message::default();
    msg.set_opcode(v4::Opcode::BootRequest);
    msg.set_htype(v4::HType::Eth);
    msg.set_xid(xid);
    msg.set_flags(v4::Flags::default().set_broadcast());
    msg.set_chaddr(mac);

    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    msg.opts_mut()
        .insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::AddressLeaseTime,
        ]));

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).expect("DHCP DISCOVER encode failed");
    buf
}

/// Build a DHCPv4 REQUEST message (initial request after OFFER).
fn build_request(xid: u32, mac: &[u8; 6], offered_ip: Ipv4Addr, server_id: Ipv4Addr) -> Vec<u8> {
    let mut msg = v4::Message::default();
    msg.set_opcode(v4::Opcode::BootRequest);
    msg.set_htype(v4::HType::Eth);
    msg.set_xid(xid);
    msg.set_flags(v4::Flags::default().set_broadcast());
    msg.set_chaddr(mac);

    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::RequestedIpAddress(offered_ip));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_id));
    msg.opts_mut()
        .insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::AddressLeaseTime,
        ]));

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).expect("DHCP REQUEST encode failed");
    buf
}

/// Build a DHCPv4 renewal REQUEST message (unicast to server).
fn build_renew(xid: u32, mac: &[u8; 6], client_ip: Ipv4Addr) -> Vec<u8> {
    let mut msg = v4::Message::default();
    msg.set_opcode(v4::Opcode::BootRequest);
    msg.set_htype(v4::HType::Eth);
    msg.set_xid(xid);
    msg.set_chaddr(mac);
    msg.set_ciaddr(client_ip);
    // No broadcast flag for renewals, no RequestedIpAddress/ServerIdentifier

    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::DomainNameServer,
            OptionCode::AddressLeaseTime,
        ]));

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).expect("DHCP RENEW encode failed");
    buf
}

/// Extract lease parameters from a DHCP ACK message.
/// Returns (ip, subnet_mask, gateway, dns_servers, lease_seconds).
fn parse_lease_from_ack(
    msg: &v4::Message,
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>, Vec<Ipv4Addr>, u32)> {
    let ip = msg.yiaddr();
    if ip.is_unspecified() {
        bail!("ACK has no yiaddr");
    }

    let subnet_mask = match msg.opts().get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(m)) => *m,
        _ => Ipv4Addr::new(255, 255, 255, 0), // default /24
    };

    let gateways = match msg.opts().get(OptionCode::Router) {
        Some(DhcpOption::Router(routers)) => routers.clone(),
        _ => Vec::new(),
    };

    let dns_servers: Vec<Ipv4Addr> = match msg.opts().get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(servers)) => servers.clone(),
        _ => Vec::new(),
    };

    let lease_secs = match msg.opts().get(OptionCode::AddressLeaseTime) {
        Some(DhcpOption::AddressLeaseTime(t)) => *t,
        _ => 3600, // default 1 hour
    };

    Ok((ip, subnet_mask, gateways, dns_servers, lease_secs))
}

/// Apply an IP address, subnet mask, and default gateway to the WAN interface.
fn apply_wan_ip(iface: &str, ip: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr) -> Result<()> {
    let prefix_len = u32::from(mask).count_ones();

    // Flush existing addresses
    let _ = Command::new("/usr/sbin/ip")
        .args(["addr", "flush", "dev", iface])
        .status();

    // Add new address
    let cidr = format!("{}/{}", ip, prefix_len);
    let status = Command::new("/usr/sbin/ip")
        .args(["addr", "add", &cidr, "dev", iface])
        .status()
        .context("ip addr add")?;
    if !status.success() {
        bail!("failed to add address {} to {}", cidr, iface);
    }

    // Replace default route
    let gw_str = gateway.to_string();
    let status = Command::new("/usr/sbin/ip")
        .args(["route", "replace", "default", "via", &gw_str, "dev", iface])
        .status()
        .context("ip route replace default")?;
    if !status.success() {
        warn!(gateway = %gateway, iface, "failed to set default route");
    }

    Ok(())
}

/// Perform DHCP DISCOVER-OFFER-REQUEST-ACK exchange (blocking).
/// Returns (ip, subnet_mask, gateways, dns_servers, lease_secs, server_id).
fn dhcp4_acquire_blocking(
    iface: &str,
    mac: &[u8; 6],
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>, Vec<Ipv4Addr>, u32, Ipv4Addr)> {
    // Bring interface up
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "set", iface, "up"])
        .status();

    let sock = make_dhcp_socket(iface, Ipv4Addr::UNSPECIFIED)?;
    let broadcast_dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);

    let mut backoff = Duration::from_secs(2);
    let max_backoff = Duration::from_secs(32);

    for attempt in 1u32..=5 {
        // Fresh xid per DISCOVER attempt
        let xid: u32 = rand::thread_rng().r#gen();

        // --- DISCOVER ---
        let discover = build_discover(xid, mac);

        if let Err(e) = sock.send_to(&discover, broadcast_dest) {
            warn!(attempt, error = %e, "failed to send DISCOVER");
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }
        info!(attempt, xid, "sent DHCP DISCOVER");

        // --- Wait for OFFER ---
        let offer_deadline = Instant::now() + backoff;
        let mut buf = [0u8; 1500];
        let offer_msg = loop {
            let remaining = offer_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(attempt, "DISCOVER timed out waiting for OFFER");
                break None;
            }
            sock.set_read_timeout(Some(remaining))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    warn!(attempt, "DISCOVER timed out waiting for OFFER");
                    break None;
                }
                Err(e) => {
                    warn!(attempt, error = %e, "recv error waiting for OFFER");
                    break None;
                }
            };
            match v4::Message::decode(&mut Decoder::new(&buf[..n])) {
                Ok(msg) if msg.xid() == xid => {
                    if msg.opts().msg_type() == Some(MessageType::Offer) {
                        break Some(msg);
                    }
                    // Not an OFFER for us, keep listening
                }
                _ => {} // ignore parse errors or wrong xid
            }
        };

        let offer_msg = match offer_msg {
            Some(m) => m,
            None => {
                backoff = (backoff * 2).min(max_backoff);
                continue;
            }
        };

        let offered_ip = offer_msg.yiaddr();
        let server_id = match offer_msg.opts().get(OptionCode::ServerIdentifier) {
            Some(DhcpOption::ServerIdentifier(s)) => *s,
            _ => offer_msg.siaddr(),
        };

        info!(
            offered_ip = %offered_ip,
            server = %server_id,
            "received DHCP OFFER"
        );

        // --- REQUEST ---
        let request = build_request(xid, mac, offered_ip, server_id);

        if let Err(e) = sock.send_to(&request, broadcast_dest) {
            warn!(error = %e, "failed to send REQUEST");
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }
        info!(xid, "sent DHCP REQUEST");

        // --- Wait for ACK/NAK ---
        let ack_deadline = Instant::now() + Duration::from_secs(5);
        let ack_msg = loop {
            let remaining = ack_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!("REQUEST timed out waiting for ACK");
                break None;
            }
            sock.set_read_timeout(Some(remaining))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    warn!("REQUEST timed out waiting for ACK");
                    break None;
                }
                Err(e) => {
                    warn!(error = %e, "recv error waiting for ACK");
                    break None;
                }
            };
            match v4::Message::decode(&mut Decoder::new(&buf[..n])) {
                Ok(msg) if msg.xid() == xid => {
                    match msg.opts().msg_type() {
                        Some(MessageType::Ack) => break Some(msg),
                        Some(MessageType::Nak) => {
                            warn!("received DHCP NAK");
                            break None;
                        }
                        _ => {} // keep listening
                    }
                }
                _ => {}
            }
        };

        if let Some(ack) = ack_msg {
            let (ip, mask, gateways, dns, lease_secs) = parse_lease_from_ack(&ack)?;
            info!(
                ip = %ip,
                mask = %mask,
                gateways = ?gateways,
                dns = ?dns,
                lease_secs,
                "DHCP lease acquired"
            );
            return Ok((ip, mask, gateways, dns, lease_secs, server_id));
        }

        backoff = (backoff * 2).min(max_backoff);
    }

    bail!("failed to acquire DHCP lease after 5 attempts")
}

/// Async wrapper around dhcp4_acquire_blocking.
async fn dhcp4_acquire(
    iface: String,
    mac: [u8; 6],
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>, Vec<Ipv4Addr>, u32, Ipv4Addr)> {
    tokio::task::spawn_blocking(move || dhcp4_acquire_blocking(&iface, &mac))
        .await
        .context("DHCP acquire task panicked")?
}

/// Perform DHCP lease renewal (blocking).
/// Returns (ip, subnet_mask, gateways, dns_servers, lease_secs).
fn dhcp4_renew_blocking(
    iface: &str,
    mac: &[u8; 6],
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    broadcast: bool,
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>, Vec<Ipv4Addr>, u32)> {
    let sock = make_dhcp_socket(iface, client_ip)?;

    let xid: u32 = rand::thread_rng().r#gen();
    let renew_pkt = build_renew(xid, mac, client_ip);

    let dest = if broadcast {
        SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT)
    } else {
        SocketAddrV4::new(server_ip, DHCP_SERVER_PORT)
    };

    sock.send_to(&renew_pkt, dest)
        .context("sending renewal REQUEST")?;
    info!(
        xid,
        server = %server_ip,
        broadcast,
        "sent DHCP renewal REQUEST"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("renewal timed out");
        }
        sock.set_read_timeout(Some(remaining))?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                bail!("renewal timed out");
            }
            Err(e) => bail!("recv error during renewal: {}", e),
        };
        match v4::Message::decode(&mut Decoder::new(&buf[..n])) {
            Ok(msg) if msg.xid() == xid => {
                match msg.opts().msg_type() {
                    Some(MessageType::Ack) => {
                        let (ip, mask, gateways, dns, lease_secs) =
                            parse_lease_from_ack(&msg)?;
                        info!(ip = %ip, lease_secs, "DHCP lease renewed");
                        return Ok((ip, mask, gateways, dns, lease_secs));
                    }
                    Some(MessageType::Nak) => {
                        bail!("received NAK during renewal");
                    }
                    _ => {} // keep listening
                }
            }
            _ => {} // wrong xid or parse error
        }
    }
}

/// Run the DHCP renewal loop. Sleeps until T1 (50% of lease), then tries
/// unicast renewal. If that fails, sleeps until T2 (87.5%), then tries
/// broadcast. If that also fails, returns error at lease expiry.
async fn dhcp4_renew_loop(
    iface: String,
    mac: [u8; 6],
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    lease_secs: u32,
    lease_start: Instant,
) -> Result<(Ipv4Addr, Ipv4Addr, Vec<Ipv4Addr>, Vec<Ipv4Addr>, u32)> {
    let lease_dur = Duration::from_secs(lease_secs as u64);
    let t1 = lease_dur / 2; // 50%
    let t2 = lease_dur * 7 / 8; // 87.5%

    // Wait until T1
    let elapsed = lease_start.elapsed();
    if elapsed < t1 {
        tokio::time::sleep(t1 - elapsed).await;
    }

    // Try unicast renewal at T1
    info!("T1 reached, attempting unicast renewal");
    let iface_clone = iface.clone();
    match tokio::task::spawn_blocking(move || {
        dhcp4_renew_blocking(&iface_clone, &mac, client_ip, server_ip, false)
    })
    .await
    .context("renew task panicked")?
    {
        Ok(result) => return Ok(result),
        Err(e) => warn!(error = %e, "unicast renewal failed, will retry at T2"),
    }

    // Wait until T2
    let elapsed = lease_start.elapsed();
    if elapsed < t2 {
        tokio::time::sleep(t2 - elapsed).await;
    }

    // Try broadcast renewal at T2
    info!("T2 reached, attempting broadcast renewal");
    let iface_clone = iface.clone();
    match tokio::task::spawn_blocking(move || {
        dhcp4_renew_blocking(&iface_clone, &mac, client_ip, server_ip, true)
    })
    .await
    .context("renew task panicked")?
    {
        Ok(result) => return Ok(result),
        Err(e) => warn!(error = %e, "broadcast renewal failed"),
    }

    // Wait until lease expiry
    let elapsed = lease_start.elapsed();
    if elapsed < lease_dur {
        tokio::time::sleep(lease_dur - elapsed).await;
    }

    bail!("DHCP lease expired without successful renewal")
}

/// Read the interface index from sysfs.
fn get_iface_index(iface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("reading ifindex from {}", path))?;
    contents
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parsing ifindex: {}", contents.trim()))
}

/// Build a DUID-LL (type 3, link-layer) from a MAC address.
/// Format: [type=3 (u16be), htype=1/Ethernet (u16be), mac[0..6]]
fn build_duid_ll(mac: &[u8; 6]) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&0x0003u16.to_be_bytes()); // DUID type 3 = link-layer
    duid.extend_from_slice(&0x0001u16.to_be_bytes()); // hardware type 1 = Ethernet
    duid.extend_from_slice(mac);
    duid
}

/// Perform DHCPv6 Prefix Delegation SOLICIT-ADVERTISE-REQUEST-REPLY (blocking).
/// Returns `Some("prefix/len")` on success, `None` on timeout or failure.
fn dhcp6_pd_blocking(wan_iface: &str) -> Option<String> {
    let mac = match get_mac(wan_iface) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "DHCPv6-PD: failed to read MAC");
            return None;
        }
    };

    let ifindex = match get_iface_index(wan_iface) {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "DHCPv6-PD: failed to read interface index");
            return None;
        }
    };

    // Create UDP6 socket bound to [::]:546 on the WAN interface
    let sock = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "DHCPv6-PD: failed to create socket");
            return None;
        }
    };
    if let Err(e) = sock.set_reuse_address(true) {
        warn!(error = %e, "DHCPv6-PD: failed to set SO_REUSEADDR");
        return None;
    }
    if let Err(e) = sock.bind_device(Some(wan_iface.as_bytes())) {
        warn!(error = %e, "DHCPv6-PD: failed to bind to device");
        return None;
    }
    let bind_addr = std::net::SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 546, 0, 0);
    if let Err(e) = sock.bind(&SockAddr::from(bind_addr)) {
        warn!(error = %e, "DHCPv6-PD: failed to bind to [::]:546");
        return None;
    }
    sock.set_nonblocking(false).ok();

    // Join the all-DHCP-servers multicast group (ff02::1:2) on the WAN interface
    let mcast_addr: Ipv6Addr = "ff02::1:2".parse().unwrap();
    if let Err(e) = sock.join_multicast_v6(&mcast_addr, ifindex) {
        warn!(error = %e, "DHCPv6-PD: failed to join multicast group");
        return None;
    }

    let udp_sock: std::net::UdpSocket = sock.into();
    let timeout = Duration::from_secs(5);

    let duid = build_duid_ll(&mac);
    let dest = std::net::SocketAddrV6::new(mcast_addr, 547, 0, ifindex);

    // --- SOLICIT ---
    let mut solicit = v6::Message::new(v6::MessageType::Solicit);
    let xid = solicit.xid();
    solicit.opts_mut().insert(v6::DhcpOption::ClientId(duid.clone()));
    solicit.opts_mut().insert(v6::DhcpOption::ElapsedTime(0));
    solicit.opts_mut().insert(v6::DhcpOption::IAPD(v6::IAPD {
        id: 1,
        t1: 0,
        t2: 0,
        opts: v6::DhcpOptions::new(),
    }));

    let mut buf = Vec::new();
    let mut enc = v6::Encoder::new(&mut buf);
    if let Err(e) = solicit.encode(&mut enc) {
        warn!(error = %e, "DHCPv6-PD: failed to encode SOLICIT");
        return None;
    }

    if let Err(e) = udp_sock.send_to(&buf, dest) {
        warn!(error = %e, "DHCPv6-PD: failed to send SOLICIT");
        return None;
    }
    info!("DHCPv6-PD: sent SOLICIT");

    // --- Wait for ADVERTISE ---
    udp_sock.set_read_timeout(Some(timeout)).ok();
    let mut recv_buf = [0u8; 1500];
    let (server_id, iapd_opts) = loop {
        let n = match udp_sock.recv(&mut recv_buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                info!("DHCPv6-PD: SOLICIT timed out (ISP may not offer prefix delegation)");
                return None;
            }
            Err(e) => {
                warn!(error = %e, "DHCPv6-PD: recv error waiting for ADVERTISE");
                return None;
            }
        };

        let msg = match v6::Message::decode(&mut v6::Decoder::new(&recv_buf[..n])) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if msg.xid() != xid {
            continue;
        }

        if msg.msg_type() != v6::MessageType::Advertise {
            continue;
        }

        // Extract Server ID
        let sid = match msg.opts().get(v6::OptionCode::ServerId) {
            Some(v6::DhcpOption::ServerId(s)) => s.clone(),
            _ => {
                warn!("DHCPv6-PD: ADVERTISE missing Server ID");
                continue;
            }
        };

        // Extract IA_PD
        let ia_pd = match msg.opts().get(v6::OptionCode::IAPD) {
            Some(v6::DhcpOption::IAPD(pd)) => pd.clone(),
            _ => {
                warn!("DHCPv6-PD: ADVERTISE missing IA_PD");
                continue;
            }
        };

        info!("DHCPv6-PD: received ADVERTISE");
        break (sid, ia_pd);
    };

    // --- REQUEST ---
    let mut request = v6::Message::new_with_id(v6::MessageType::Request, xid);
    request.opts_mut().insert(v6::DhcpOption::ClientId(duid.clone()));
    request.opts_mut().insert(v6::DhcpOption::ServerId(server_id));
    request.opts_mut().insert(v6::DhcpOption::ElapsedTime(0));
    request.opts_mut().insert(v6::DhcpOption::IAPD(iapd_opts));

    let mut buf = Vec::new();
    let mut enc = v6::Encoder::new(&mut buf);
    if let Err(e) = request.encode(&mut enc) {
        warn!(error = %e, "DHCPv6-PD: failed to encode REQUEST");
        return None;
    }

    if let Err(e) = udp_sock.send_to(&buf, dest) {
        warn!(error = %e, "DHCPv6-PD: failed to send REQUEST");
        return None;
    }
    info!("DHCPv6-PD: sent REQUEST");

    // --- Wait for REPLY ---
    udp_sock.set_read_timeout(Some(timeout)).ok();
    loop {
        let n = match udp_sock.recv(&mut recv_buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                warn!("DHCPv6-PD: REQUEST timed out waiting for REPLY");
                return None;
            }
            Err(e) => {
                warn!(error = %e, "DHCPv6-PD: recv error waiting for REPLY");
                return None;
            }
        };

        let msg = match v6::Message::decode(&mut v6::Decoder::new(&recv_buf[..n])) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if msg.xid() != xid {
            continue;
        }

        if msg.msg_type() != v6::MessageType::Reply {
            continue;
        }

        // Extract IA_PD from REPLY
        let ia_pd = match msg.opts().get(v6::OptionCode::IAPD) {
            Some(v6::DhcpOption::IAPD(pd)) => pd,
            _ => {
                warn!("DHCPv6-PD: REPLY missing IA_PD");
                return None;
            }
        };

        // Extract IAPrefix from within IA_PD options
        let prefix = match ia_pd.opts.get(v6::OptionCode::IAPrefix) {
            Some(v6::DhcpOption::IAPrefix(p)) => p,
            _ => {
                warn!("DHCPv6-PD: REPLY IA_PD missing IAPrefix");
                return None;
            }
        };

        let result = format!("{}/{}", prefix.prefix_ip, prefix.prefix_len);
        info!(
            prefix = %result,
            preferred_lifetime = prefix.preferred_lifetime,
            valid_lifetime = prefix.valid_lifetime,
            "DHCPv6-PD: prefix delegated"
        );
        return Some(result);
    }
}

/// Attempt DHCPv6 Prefix Delegation on the WAN interface.
/// Returns `Some("prefix/len")` on success, `None` if unavailable or timed out.
async fn dhcp6_pd(wan_iface: &str) -> Option<String> {
    let iface = wan_iface.to_string();
    match tokio::task::spawn_blocking(move || dhcp6_pd_blocking(&iface)).await {
        Ok(result) => result,
        Err(e) => {
            warn!(error = %e, "DHCPv6-PD task panicked");
            None
        }
    }
}

/// Run the DHCP client on the WAN interface.
/// Acquires a lease, applies it, runs the renewal loop, and restarts on failure.
async fn run_dhcp(
    wan_iface: &str,
    db: &Arc<Mutex<db::Db>>,
    lease: &SharedWanLease,
) -> Result<()> {
    let mac = get_mac(wan_iface)?;
    info!(
        iface = %wan_iface,
        mac = %format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
        "starting DHCP client"
    );

    loop {
        // --- Acquire lease ---
        let (mut cur_ip, mut cur_mask, gateways, dns_servers, mut cur_lease_secs, server_ip) =
            match dhcp4_acquire(wan_iface.to_string(), mac).await {
                Ok(result) => result,
                Err(e) => {
                    error!(error = %e, "DHCP acquire failed, retrying in 10s");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

        let mut cur_gw = gateways.first().copied().unwrap_or(server_ip);
        let cur_dns = dns_servers;

        // --- Apply IP to interface ---
        if let Err(e) = apply_wan_ip(wan_iface, cur_ip, cur_mask, cur_gw) {
            error!(error = %e, "failed to apply WAN IP");
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        // --- Try DHCPv6-PD ---
        let delegated_prefix = dhcp6_pd(wan_iface).await;

        // Store delegated prefix in DB
        if let Some(ref prefix) = delegated_prefix {
            info!(prefix = %prefix, "IPv6 prefix delegated");
            let db_guard = db.lock().unwrap();
            let _ = db_guard.set_config("ipv6_delegated_prefix", prefix);
        }

        // --- Populate shared lease ---
        let mut lease_start = Instant::now();
        let lease_dur = Duration::from_secs(cur_lease_secs as u64);
        {
            let mut guard = lease.lock().unwrap();
            *guard = Some(WanLease {
                ip: cur_ip,
                subnet_mask: cur_mask,
                gateway: cur_gw,
                dns_servers: cur_dns.clone(),
                lease_time: cur_lease_secs,
                renew_at: lease_start + lease_dur / 2,
                rebind_at: lease_start + lease_dur * 7 / 8,
                delegated_prefix: delegated_prefix.clone(),
                prefix_valid_lifetime: None,
            });
        }

        info!(
            ip = %cur_ip,
            mask = %cur_mask,
            gateway = %cur_gw,
            dns = ?cur_dns,
            lease_secs = cur_lease_secs,
            prefix = ?delegated_prefix,
            "WAN DHCP lease active"
        );

        // --- Renewal loop: keep renewing without full re-acquire ---
        loop {
            match dhcp4_renew_loop(
                wan_iface.to_string(),
                mac,
                cur_ip,
                server_ip,
                cur_lease_secs,
                lease_start,
            )
            .await
            {
                Ok((new_ip, new_mask, new_gws, new_dns, new_lease)) => {
                    let new_gw = new_gws.first().copied().unwrap_or(server_ip);

                    // Reapply if IP changed
                    if new_ip != cur_ip || new_mask != cur_mask || new_gw != cur_gw {
                        if let Err(e) = apply_wan_ip(wan_iface, new_ip, new_mask, new_gw) {
                            error!(error = %e, "failed to apply renewed WAN IP");
                        }
                    }

                    lease_start = Instant::now();
                    let new_dur = Duration::from_secs(new_lease as u64);
                    {
                        let mut guard = lease.lock().unwrap();
                        *guard = Some(WanLease {
                            ip: new_ip,
                            subnet_mask: new_mask,
                            gateway: new_gw,
                            dns_servers: new_dns.clone(),
                            lease_time: new_lease,
                            renew_at: lease_start + new_dur / 2,
                            rebind_at: lease_start + new_dur * 7 / 8,
                            delegated_prefix: delegated_prefix.clone(),
                            prefix_valid_lifetime: None,
                        });
                    }

                    // Update current state for next renewal cycle
                    cur_ip = new_ip;
                    cur_mask = new_mask;
                    cur_gw = new_gw;
                    cur_lease_secs = new_lease;

                    info!(ip = %cur_ip, lease_secs = cur_lease_secs, "lease renewed, continuing");
                    // Loop back for another renewal cycle (no re-acquire)
                }
                Err(e) => {
                    warn!(error = %e, "renewal failed, lease expired — restarting DORA");
                    // Clear the lease
                    {
                        let mut guard = lease.lock().unwrap();
                        *guard = None;
                    }
                    // Flush IP before re-acquiring
                    let _ = Command::new("/usr/sbin/ip")
                        .args(["addr", "flush", "dev", wan_iface])
                        .status();
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    break; // Break inner loop to re-acquire in outer loop
                }
            }
        }
    }
}

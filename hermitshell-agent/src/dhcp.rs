use anyhow::{Context, Result};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};

use crate::db::Db;
use crate::nftables;
use crate::subnet;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEASE_TIME: u32 = 3600; // 1 hour

pub struct DhcpServer {
    db: Arc<Mutex<Db>>,
    lan_iface: String,
    upstream_dns: Vec<Ipv4Addr>,
}

impl DhcpServer {
    pub fn new(db: Arc<Mutex<Db>>, lan_iface: String, upstream_dns: Vec<Ipv4Addr>) -> Self {
        Self {
            db,
            lan_iface,
            upstream_dns,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_broadcast(true)?;

        // Bind to LAN interface via SO_BINDTODEVICE using libc
        bind_to_device(&sock, &self.lan_iface)?;

        sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67).into())?;

        println!("DHCP server listening on 0.0.0.0:67 ({})", self.lan_iface);

        let db = self.db.clone();
        let upstream_dns = self.upstream_dns.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
            loop {
                let (len, _addr) = match sock.recv_from(&mut buf) {
                    Ok((len, addr)) => (len, addr),
                    Err(e) => {
                        eprintln!("DHCP recv error: {}", e);
                        continue;
                    }
                };

                // Safety: recv_from initialized buf[..len]
                let data: Vec<u8> = buf[..len]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();

                let msg =
                    match Message::decode(&mut dhcproto::decoder::Decoder::new(&data)) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("DHCP decode error: {}", e);
                            continue;
                        }
                    };

                // Only process BOOTREQUEST (client -> server)
                if msg.opcode() != Opcode::BootRequest {
                    continue;
                }

                let mac = format_mac(msg.chaddr());
                let msg_type = match msg.opts().get(dhcproto::v4::OptionCode::MessageType) {
                    Some(DhcpOption::MessageType(mt)) => *mt,
                    _ => {
                        eprintln!("DHCP packet from {} missing message type", mac);
                        continue;
                    }
                };

                let response = match msg_type {
                    MessageType::Discover => {
                        println!("DHCPDISCOVER from {}", mac);
                        match handle_discover(&db, &upstream_dns, &msg, &mac) {
                            Ok(resp) => resp,
                            Err(e) => {
                                eprintln!("Error handling DISCOVER from {}: {}", mac, e);
                                continue;
                            }
                        }
                    }
                    MessageType::Request => {
                        println!("DHCPREQUEST from {}", mac);
                        match handle_request(&db, &upstream_dns, &msg, &mac) {
                            Ok(Some(resp)) => resp,
                            Ok(None) => continue,
                            Err(e) => {
                                eprintln!("Error handling REQUEST from {}: {}", mac, e);
                                continue;
                            }
                        }
                    }
                    other => {
                        println!("DHCP {:?} from {} (ignored)", other, mac);
                        continue;
                    }
                };

                // Encode and send response
                let mut enc_buf = Vec::new();
                let mut encoder = dhcproto::encoder::Encoder::new(&mut enc_buf);
                if let Err(e) = response.encode(&mut encoder) {
                    eprintln!("DHCP encode error: {}", e);
                    continue;
                }

                let dest =
                    socket2::SockAddr::from(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
                if let Err(e) = sock.send_to(&enc_buf, &dest) {
                    eprintln!("DHCP send error: {}", e);
                }
            }
        })
        .await
        .context("DHCP server thread panicked")??;

        Ok(())
    }
}

/// Bind a socket to a specific network interface via SO_BINDTODEVICE.
fn bind_to_device(sock: &Socket, iface: &str) -> Result<()> {
    let fd = sock.as_raw_fd();
    let iface_bytes = iface.as_bytes();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
            .context(format!("SO_BINDTODEVICE to {} failed", iface))
    } else {
        Ok(())
    }
}

/// Format the first 6 bytes of chaddr as a MAC address string.
fn format_mac(chaddr: &[u8]) -> String {
    if chaddr.len() < 6 {
        return "??:??:??:??:??:??".to_string();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]
    )
}

/// Build a base DHCP response message, copying xid and chaddr from the request.
fn build_response(request: &Message, msg_type: MessageType, yiaddr: Ipv4Addr) -> Message {
    let mut resp = Message::default();
    resp.set_opcode(Opcode::BootReply);
    resp.set_xid(request.xid());
    resp.set_flags(request.flags());
    resp.set_yiaddr(yiaddr);
    resp.set_siaddr(SERVER_IP);
    resp.set_giaddr(request.giaddr());
    resp.set_chaddr(request.chaddr());
    resp.opts_mut()
        .insert(DhcpOption::MessageType(msg_type));
    resp.opts_mut()
        .insert(DhcpOption::ServerIdentifier(SERVER_IP));
    resp.opts_mut()
        .insert(DhcpOption::AddressLeaseTime(LEASE_TIME));
    resp.opts_mut()
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 252)));
    resp.opts_mut()
        .insert(DhcpOption::Router(vec![SERVER_IP]));
    resp
}

/// Handle DHCPDISCOVER: allocate or look up subnet, respond with DHCPOFFER.
fn handle_discover(
    db: &Arc<Mutex<Db>>,
    upstream_dns: &[Ipv4Addr],
    request: &Message,
    mac: &str,
) -> Result<Message> {
    let db = db.lock().unwrap();

    let (device_ip, subnet_info) = match db.get_device(mac)? {
        Some(dev) if dev.subnet_id.is_some() => {
            // Known device with subnet assignment
            let sid = dev.subnet_id.unwrap();
            let info =
                subnet::compute_subnet(sid).context("subnet_id out of range")?;
            let ip: Ipv4Addr = info.device_ip.parse()?;
            println!(
                "  Known device {}, offering existing {}",
                mac, info.device_ip
            );
            (ip, info)
        }
        _ => {
            // New or unassigned device: allocate a /30
            let sid = db.allocate_subnet_id()?;
            let info = subnet::compute_subnet(sid)
                .context("subnet address space exhausted")?;
            db.insert_new_device(mac, sid, &info.device_ip)?;
            let ip: Ipv4Addr = info.device_ip.parse()?;
            println!(
                "  New device {}, allocated subnet {} -> {}",
                mac, sid, info.device_ip
            );
            (ip, info)
        }
    };

    let mut resp = build_response(request, MessageType::Offer, device_ip);

    if !upstream_dns.is_empty() {
        resp.opts_mut()
            .insert(DhcpOption::DomainNameServer(upstream_dns.to_vec()));
    }

    // Override subnet mask with the actual /30 mask
    resp.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(
        subnet_info.netmask_octets[0],
        subnet_info.netmask_octets[1],
        subnet_info.netmask_octets[2],
        subnet_info.netmask_octets[3],
    )));

    // Router is the /30 gateway, not SERVER_IP
    let gw = Ipv4Addr::new(
        subnet_info.gateway_octets[0],
        subnet_info.gateway_octets[1],
        subnet_info.gateway_octets[2],
        subnet_info.gateway_octets[3],
    );
    resp.opts_mut().insert(DhcpOption::Router(vec![gw]));

    Ok(resp)
}

/// Handle DHCPREQUEST: verify requested IP matches, respond with DHCPACK.
fn handle_request(
    db: &Arc<Mutex<Db>>,
    upstream_dns: &[Ipv4Addr],
    request: &Message,
    mac: &str,
) -> Result<Option<Message>> {
    let db_guard = db.lock().unwrap();

    let dev = match db_guard.get_device(mac)? {
        Some(d) => d,
        None => {
            eprintln!("  DHCPREQUEST from unknown MAC {}, ignoring", mac);
            return Ok(None);
        }
    };

    let sid = match dev.subnet_id {
        Some(s) => s,
        None => {
            eprintln!("  DHCPREQUEST from {} but no subnet assigned", mac);
            return Ok(None);
        }
    };

    let info = subnet::compute_subnet(sid).context("subnet_id out of range")?;
    let assigned_ip: Ipv4Addr = info.device_ip.parse()?;

    // Verify requested IP matches (from option 50 or ciaddr)
    let requested_ip = match request.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };
    let ciaddr = request.ciaddr();

    let client_ip = requested_ip.unwrap_or(ciaddr);
    if client_ip != assigned_ip && client_ip != Ipv4Addr::UNSPECIFIED {
        eprintln!(
            "  DHCPREQUEST from {} requested {} but assigned {}, sending NAK",
            mac, client_ip, assigned_ip
        );
        let mut nak = Message::default();
        nak.set_opcode(Opcode::BootReply);
        nak.set_xid(request.xid());
        nak.set_chaddr(request.chaddr());
        nak.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Nak));
        nak.opts_mut()
            .insert(DhcpOption::ServerIdentifier(SERVER_IP));
        return Ok(Some(nak));
    }

    // Drop db lock before running nftables commands
    drop(db_guard);

    let mut resp = build_response(request, MessageType::Ack, assigned_ip);

    if !upstream_dns.is_empty() {
        resp.opts_mut()
            .insert(DhcpOption::DomainNameServer(upstream_dns.to_vec()));
    }

    resp.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(
        info.netmask_octets[0],
        info.netmask_octets[1],
        info.netmask_octets[2],
        info.netmask_octets[3],
    )));

    let gw = Ipv4Addr::new(
        info.gateway_octets[0],
        info.gateway_octets[1],
        info.gateway_octets[2],
        info.gateway_octets[3],
    );
    resp.opts_mut().insert(DhcpOption::Router(vec![gw]));

    // After ACK: set up gateway address and nftables rule
    println!(
        "  DHCPACK {} -> {}, setting up gateway {}",
        mac, info.device_ip, info.gateway
    );

    // Add gateway IP to LAN interface
    if let Err(e) = add_gateway_address(&info.gateway) {
        eprintln!("  Failed to add gateway address {}: {}", info.gateway, e);
    }

    // Add nftables counter for the device
    if let Err(e) = nftables::add_device_counter(&info.device_ip) {
        eprintln!("  Failed to add counter for {}: {}", info.device_ip, e);
    }

    // Add nftables forward rule (quarantine for new devices)
    if let Err(e) = nftables::add_device_forward_rule(&info.device_ip, "quarantine") {
        eprintln!("  Failed to add forward rule for {}: {}", info.device_ip, e);
    }

    Ok(Some(resp))
}

/// Add a /30 gateway address to the LAN interface using `ip addr add`.
fn add_gateway_address(gateway: &str) -> Result<()> {
    let addr_cidr = format!("{}/30", gateway);
    let status = std::process::Command::new("ip")
        .args(["addr", "add", &addr_cidr, "dev", "eth2"])
        .status()
        .context("failed to run ip addr add")?;

    // Exit code 2 means address already exists, which is fine
    if status.success() || status.code() == Some(2) {
        Ok(())
    } else {
        anyhow::bail!("ip addr add {} failed with {:?}", addr_cidr, status.code())
    }
}

use anyhow::{Context, Result};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable};
use hermitshell_common::subnet;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEASE_TIME: u32 = 3600; // 1 hour
const AGENT_SOCKET: &str = "/run/hermitshell/dhcp.sock";

fn main() -> Result<()> {
    let lan_iface = std::env::args()
        .nth(1)
        .context("usage: hermitshell-dhcp <lan_iface>")?;

    // Wait up to 10s for agent socket
    for i in 0..20 {
        if std::path::Path::new(AGENT_SOCKET).exists() {
            break;
        }
        if i == 19 {
            anyhow::bail!("agent socket {} not found after 10s", AGENT_SOCKET);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;

    bind_to_device(&sock, &lan_iface)?;

    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67).into())?;

    println!("hermitshell-dhcp listening on 0.0.0.0:67 ({})", lan_iface);

    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    let mut discover_times: HashMap<String, Instant> = HashMap::new();

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

        let msg = match Message::decode(&mut dhcproto::decoder::Decoder::new(&data)) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("DHCP decode error: {}", e);
                continue;
            }
        };

        if msg.opcode() != Opcode::BootRequest {
            continue;
        }

        let mac = format_mac(msg.chaddr());

        if !is_valid_mac(msg.chaddr()) {
            eprintln!("DHCP packet from invalid MAC {}, dropping", mac);
            continue;
        }

        let msg_type = match msg.opts().get(dhcproto::v4::OptionCode::MessageType) {
            Some(DhcpOption::MessageType(mt)) => *mt,
            _ => {
                eprintln!("DHCP packet from {} missing message type", mac);
                continue;
            }
        };

        let response = match msg_type {
            MessageType::Discover => {
                if let Some(last) = discover_times.get(&mac) {
                    if last.elapsed().as_secs() < 10 {
                        eprintln!("DHCPDISCOVER from {} rate-limited", mac);
                        continue;
                    }
                }
                discover_times.insert(mac.clone(), Instant::now());
                println!("DHCPDISCOVER from {}", mac);
                match handle_discover(&msg, &mac) {
                    Ok(resp) => resp,
                    Err(e) => {
                        eprintln!("Error handling DISCOVER from {}: {}", mac, e);
                        continue;
                    }
                }
            }
            MessageType::Request => {
                println!("DHCPREQUEST from {}", mac);
                match handle_request(&msg, &mac) {
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

        let dest = socket2::SockAddr::from(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
        if let Err(e) = sock.send_to(&enc_buf, &dest) {
            eprintln!("DHCP send error: {}", e);
        }
    }
}

fn agent_request(req: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(AGENT_SOCKET)
        .context("failed to connect to agent DHCP socket")?;

    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    stream.write_all(json.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    serde_json::from_str(&response).context("failed to parse agent response")
}

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

fn format_mac(chaddr: &[u8]) -> String {
    if chaddr.len() < 6 {
        return "??:??:??:??:??:??".to_string();
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]
    )
}

fn is_valid_mac(chaddr: &[u8]) -> bool {
    if chaddr.len() < 6 {
        return false;
    }
    let mac = &chaddr[..6];
    if mac == [0, 0, 0, 0, 0, 0] {
        return false;
    }
    if mac == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] {
        return false;
    }
    if mac[0] & 0x01 != 0 {
        return false;
    }
    true
}

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

/// Handle DHCPDISCOVER: IPC to agent for subnet allocation, respond with DHCPOFFER.
fn handle_discover(request: &Message, mac: &str) -> Result<Message> {
    let resp = agent_request(&serde_json::json!({
        "method": "dhcp_discover",
        "mac": mac,
    }))?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error");
        anyhow::bail!("agent dhcp_discover failed: {}", err);
    }

    let sid = resp.get("subnet_id")
        .and_then(|v| v.as_i64())
        .context("missing subnet_id in response")?;
    let device_ip_str = resp.get("device_ip")
        .and_then(|v| v.as_str())
        .context("missing device_ip in response")?;
    let is_new = resp.get("is_new")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let info = subnet::compute_subnet(sid).context("subnet_id out of range")?;
    let device_ip: Ipv4Addr = device_ip_str.parse()?;

    if is_new {
        println!("  New device {}, allocated subnet {} -> {}", mac, sid, device_ip_str);
    } else {
        println!("  Known device {}, offering existing {}", mac, device_ip_str);
    }

    let mut msg = build_response(request, MessageType::Offer, device_ip);

    msg.opts_mut()
        .insert(DhcpOption::DomainNameServer(vec![SERVER_IP]));

    msg.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(
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
    msg.opts_mut().insert(DhcpOption::Router(vec![gw]));

    Ok(msg)
}

/// Handle DHCPREQUEST: verify requested IP, respond with DHCPACK, fire-and-forget provision.
fn handle_request(request: &Message, mac: &str) -> Result<Option<Message>> {
    // Look up device via IPC (same as discover — returns existing assignment)
    let resp = agent_request(&serde_json::json!({
        "method": "dhcp_discover",
        "mac": mac,
    }))?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error");
        eprintln!("  DHCPREQUEST from {} but agent lookup failed: {}", mac, err);
        return Ok(None);
    }

    let sid = resp.get("subnet_id")
        .and_then(|v| v.as_i64())
        .context("missing subnet_id in response")?;
    let device_ip_str = resp.get("device_ip")
        .and_then(|v| v.as_str())
        .context("missing device_ip in response")?;

    let info = subnet::compute_subnet(sid).context("subnet_id out of range")?;
    let assigned_ip: Ipv4Addr = device_ip_str.parse()?;

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

    let mut msg = build_response(request, MessageType::Ack, assigned_ip);

    msg.opts_mut()
        .insert(DhcpOption::DomainNameServer(vec![SERVER_IP]));

    msg.opts_mut().insert(DhcpOption::SubnetMask(Ipv4Addr::new(
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
    msg.opts_mut().insert(DhcpOption::Router(vec![gw]));

    println!(
        "  DHCPACK {} -> {}, provisioning gateway {}",
        mac, info.device_ip, info.gateway
    );

    // Fire-and-forget: provision nftables rules via agent
    if let Err(e) = agent_request(&serde_json::json!({
        "method": "dhcp_provision",
        "mac": mac,
        "subnet_id": sid,
    })) {
        eprintln!("  Failed to provision {}: {}", mac, e);
    }

    Ok(Some(msg))
}

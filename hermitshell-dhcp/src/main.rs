use anyhow::{Context, Result};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Encodable};
use hermitshell_common::subnet;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::net::UnixStream;
use std::time::Instant;
use tracing::{debug, error, info, warn};

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LEASE_TIME: u32 = 3600; // 1 hour
const AGENT_SOCKET: &str = "/run/hermitshell/dhcp.sock";

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

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

    sock.bind_device(Some(lan_iface.as_bytes()))?;

    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67).into())?;

    let udp: UdpSocket = sock.into();

    info!(iface = %lan_iface, "hermitshell-dhcp listening on 0.0.0.0:67");

    let mut buf = [0u8; 1500];
    let mut discover_times: HashMap<String, Instant> = HashMap::new();

    loop {
        let (len, _addr) = match udp.recv_from(&mut buf) {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
                error!(error = %e, "DHCP recv error");
                continue;
            }
        };

        let data = &buf[..len];

        let msg = match Message::decode(&mut dhcproto::decoder::Decoder::new(&data)) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "DHCP decode error");
                continue;
            }
        };

        if msg.opcode() != Opcode::BootRequest {
            continue;
        }

        let mac = format_mac(msg.chaddr());

        if !is_valid_mac(msg.chaddr()) {
            warn!(mac = %mac, "DHCP packet from invalid MAC, dropping");
            continue;
        }

        let msg_type = match msg.opts().get(dhcproto::v4::OptionCode::MessageType) {
            Some(DhcpOption::MessageType(mt)) => *mt,
            _ => {
                warn!(mac = %mac, "DHCP packet missing message type");
                continue;
            }
        };

        let response = match msg_type {
            MessageType::Discover => {
                if let Some(last) = discover_times.get(&mac) {
                    if last.elapsed().as_secs() < 10 {
                        warn!(mac = %mac, "DHCPDISCOVER rate-limited");
                        continue;
                    }
                }
                discover_times.insert(mac.clone(), Instant::now());
                info!(mac = %mac, "DHCPDISCOVER");
                match handle_discover(&msg, &mac) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling DISCOVER");
                        continue;
                    }
                }
            }
            MessageType::Request => {
                info!(mac = %mac, "DHCPREQUEST");
                match handle_request(&msg, &mac) {
                    Ok(Some(resp)) => resp,
                    Ok(None) => continue,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling REQUEST");
                        continue;
                    }
                }
            }
            other => {
                debug!(mac = %mac, msg_type = ?other, "DHCP message ignored");
                continue;
            }
        };

        // Encode and send response
        let mut enc_buf = Vec::new();
        let mut encoder = dhcproto::encoder::Encoder::new(&mut enc_buf);
        if let Err(e) = response.encode(&mut encoder) {
            error!(error = %e, "DHCP encode error");
            continue;
        }

        let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, 68);
        if let Err(e) = udp.send_to(&enc_buf, dest) {
            error!(error = %e, "DHCP send error");
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
        info!(mac = %mac, subnet_id = sid, ip = %device_ip_str, "new device allocated");
    } else {
        info!(mac = %mac, ip = %device_ip_str, "known device, offering existing");
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
        error!(mac = %mac, error = %err, "DHCPREQUEST agent lookup failed");
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
        warn!(
            mac = %mac, requested = %client_ip, assigned = %assigned_ip,
            "DHCPREQUEST IP mismatch, sending NAK"
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

    info!(
        mac = %mac, ip = %info.device_ip, gateway = %info.gateway,
        "DHCPACK, provisioning"
    );

    // Fire-and-forget: provision nftables rules via agent
    if let Err(e) = agent_request(&serde_json::json!({
        "method": "dhcp_provision",
        "mac": mac,
        "subnet_id": sid,
    })) {
        error!(mac = %mac, error = %e, "failed to provision");
    }

    Ok(Some(msg))
}

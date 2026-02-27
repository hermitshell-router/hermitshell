use anyhow::{Context, Result};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::v6::{
    self, DhcpOption as DhcpOption6, IAAddr, IANA, MessageType as MessageType6,
    Message as Message6, OptionCode as OptionCode6, Status, StatusCode,
};
use dhcproto::{Decodable, Encodable};
use ipnet::Ipv4Net;
use socket2::{Domain, Protocol, Socket, Type};
use lru::LruCache;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::num::NonZeroUsize;
use std::os::unix::net::UnixStream;
use std::time::Instant;
use hermitshell_common::sanitize_hostname;
use tracing::{debug, error, info, warn};

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_IPV6_ULA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const LEASE_TIME: u32 = 3600; // 1 hour
const AGENT_SOCKET: &str = "/run/hermitshell/dhcp.sock";

/// Server DUID (DUID-LL with Ethernet hardware type and a fixed identifier).
/// Type=3 (DUID-LL), HType=1 (Ethernet), then 6-byte link-layer address.
const SERVER_DUID: &[u8] = &[
    0x00, 0x03, // DUID-LL
    0x00, 0x01, // hardware type: Ethernet
    0x48, 0x65, 0x72, 0x6d, 0x69, 0x74, // "Hermit" as pseudo-MAC
];

struct AgentConn {
    stream: Option<(UnixStream, BufReader<UnixStream>)>,
}

impl AgentConn {
    fn new() -> Self {
        Self { stream: None }
    }

    fn connect(&mut self) -> Result<()> {
        let stream = UnixStream::connect(AGENT_SOCKET)
            .context("failed to connect to agent DHCP socket")?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let reader = BufReader::new(stream.try_clone()?);
        self.stream = Some((stream, reader));
        Ok(())
    }

    fn request(&mut self, req: &serde_json::Value) -> Result<serde_json::Value> {
        for attempt in 0..2 {
            if self.stream.is_none() {
                self.connect()?;
            }
            let (stream, reader) = self.stream.as_mut().unwrap();
            let mut json = serde_json::to_string(req)?;
            json.push('\n');
            match stream.write_all(json.as_bytes()) {
                Ok(()) => {}
                Err(e) => {
                    if attempt == 0 {
                        warn!(error = %e, "IPC write failed, reconnecting");
                        self.stream = None;
                        continue;
                    }
                    return Err(e.into());
                }
            }
            let mut response = String::new();
            match reader.read_line(&mut response) {
                Ok(0) if attempt == 0 => {
                    warn!("IPC read EOF, reconnecting");
                    self.stream = None;
                    continue;
                }
                Ok(0) => anyhow::bail!("agent closed connection"),
                Ok(_) => return serde_json::from_str(&response).context("failed to parse agent response"),
                Err(e) if attempt == 0 => {
                    warn!(error = %e, "IPC read failed, reconnecting");
                    self.stream = None;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("agent request failed after retry")
    }
}

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

    let mut agent = AgentConn::new();

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;

    sock.bind_device(Some(lan_iface.as_bytes()))?;

    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67).into())?;

    let udp: UdpSocket = sock.into();

    info!(iface = %lan_iface, "hermitshell-dhcp listening on 0.0.0.0:67");

    // Spawn DHCPv6 server thread
    let v6_iface = lan_iface.clone();
    std::thread::Builder::new()
        .name("dhcpv6".into())
        .spawn(move || {
            if let Err(e) = run_dhcpv6_server(&v6_iface) {
                error!(error = %e, "DHCPv6 server thread exited with error");
            }
        })
        .context("failed to spawn DHCPv6 thread")?;

    let mut buf = [0u8; 1500];
    let mut discover_times: LruCache<String, Instant> = LruCache::new(NonZeroUsize::new(10_000).expect("nonzero constant"));

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
                discover_times.put(mac.clone(), Instant::now());
                info!(mac = %mac, "DHCPDISCOVER");
                match handle_discover(&mut agent, &msg, &mac) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling DISCOVER");
                        continue;
                    }
                }
            }
            MessageType::Request => {
                info!(mac = %mac, "DHCPREQUEST");
                match handle_request(&mut agent, &msg, &mac) {
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
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 255)));
    resp.opts_mut()
        .insert(DhcpOption::Router(vec![SERVER_IP]));
    resp
}

/// Handle DHCPDISCOVER: IPC to agent for subnet allocation, respond with DHCPOFFER.
fn handle_discover(agent: &mut AgentConn, request: &Message, mac: &str) -> Result<Message> {
    let hostname = match request.opts().get(dhcproto::v4::OptionCode::Hostname) {
        Some(DhcpOption::Hostname(h)) => {
            let clean = sanitize_hostname(h);
            if clean.is_empty() { None } else { Some(clean) }
        }
        _ => None,
    };
    // Extract DHCP fingerprint (Option 55: Parameter Request List)
    let fingerprint = match request.opts().get(dhcproto::v4::OptionCode::ParameterRequestList) {
        Some(DhcpOption::ParameterRequestList(codes)) => {
            let code_strs: Vec<String> = codes.iter().map(|c| {
                let n: u8 = (*c).into();
                n.to_string()
            }).collect();
            Some(code_strs.join(","))
        }
        _ => None,
    };
    let mut req = serde_json::json!({
        "method": "dhcp_discover",
        "mac": mac,
    });
    if let Some(ref h) = hostname {
        req["hostname"] = serde_json::Value::String(h.clone());
    }
    if let Some(ref fp) = fingerprint {
        req["dhcp_fingerprint"] = serde_json::Value::String(fp.clone());
    }
    let resp = agent.request(&req)?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error");
        anyhow::bail!("agent dhcp_discover failed: {}", err);
    }

    let device_ip_str = resp.get("device_ipv4")
        .and_then(|v| v.as_str())
        .context("missing device_ipv4 in response")?;
    let is_new = resp.get("is_new")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let device_ip: Ipv4Addr = device_ip_str.parse()?;

    if is_new {
        info!(mac = %mac, ip = %device_ip_str, "new device allocated");
    } else {
        info!(mac = %mac, ip = %device_ip_str, "known device, offering existing");
    }

    let mut msg = build_response(request, MessageType::Offer, device_ip);

    msg.opts_mut()
        .insert(DhcpOption::DomainNameServer(vec![SERVER_IP]));

    // Option 121: classless static routes for /32 point-to-point addressing
    msg.opts_mut().insert(DhcpOption::ClasslessStaticRoute(vec![
        // On-link route to gateway: 10.0.0.1/32 via 0.0.0.0
        (Ipv4Net::new(SERVER_IP, 32).unwrap(), Ipv4Addr::UNSPECIFIED),
        // Default route: 0.0.0.0/0 via 10.0.0.1
        (Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(), SERVER_IP),
    ]));

    Ok(msg)
}

/// Handle DHCPREQUEST (v4): verify requested IP, respond with DHCPACK, fire-and-forget provision.
fn handle_request(agent: &mut AgentConn, request: &Message, mac: &str) -> Result<Option<Message>> {
    // Look up device via IPC (same as discover — returns existing assignment)
    let hostname = match request.opts().get(dhcproto::v4::OptionCode::Hostname) {
        Some(DhcpOption::Hostname(h)) => {
            let clean = sanitize_hostname(h);
            if clean.is_empty() { None } else { Some(clean) }
        }
        _ => None,
    };
    // Extract DHCP fingerprint (Option 55: Parameter Request List)
    let fingerprint = match request.opts().get(dhcproto::v4::OptionCode::ParameterRequestList) {
        Some(DhcpOption::ParameterRequestList(codes)) => {
            let code_strs: Vec<String> = codes.iter().map(|c| {
                let n: u8 = (*c).into();
                n.to_string()
            }).collect();
            Some(code_strs.join(","))
        }
        _ => None,
    };
    let mut req = serde_json::json!({
        "method": "dhcp_discover",
        "mac": mac,
    });
    if let Some(ref h) = hostname {
        req["hostname"] = serde_json::Value::String(h.clone());
    }
    if let Some(ref fp) = fingerprint {
        req["dhcp_fingerprint"] = serde_json::Value::String(fp.clone());
    }
    let resp = agent.request(&req)?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error");
        error!(mac = %mac, error = %err, "DHCPREQUEST agent lookup failed");
        return Ok(None);
    }

    let sid = resp.get("subnet_id")
        .and_then(|v| v.as_i64())
        .context("missing subnet_id in response")?;
    let device_ip_str = resp.get("device_ipv4")
        .and_then(|v| v.as_str())
        .context("missing device_ipv4 in response")?;

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

    // Option 121: classless static routes for /32 point-to-point addressing
    msg.opts_mut().insert(DhcpOption::ClasslessStaticRoute(vec![
        // On-link route to gateway: 10.0.0.1/32 via 0.0.0.0
        (Ipv4Net::new(SERVER_IP, 32).unwrap(), Ipv4Addr::UNSPECIFIED),
        // Default route: 0.0.0.0/0 via 10.0.0.1
        (Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(), SERVER_IP),
    ]));

    info!(
        mac = %mac, ip = %assigned_ip,
        "DHCPACK, provisioning"
    );

    // Fire-and-forget: provision nftables rules via agent
    if let Err(e) = agent.request(&serde_json::json!({
        "method": "dhcp_provision",
        "mac": mac,
        "subnet_id": sid,
    })) {
        error!(mac = %mac, error = %e, "failed to provision");
    }

    Ok(Some(msg))
}

// ---------------------------------------------------------------------------
// DHCPv6 server
// ---------------------------------------------------------------------------

/// Extract a MAC address from a DHCPv6 Client Identifier (DUID) option.
///
/// Supports DUID-LLT (type 1) and DUID-LL (type 3) which both contain an
/// Ethernet hardware type (1) followed by a 6-byte link-layer address.
fn extract_mac_from_duid(duid: &[u8]) -> Option<String> {
    if duid.len() < 4 {
        return None;
    }
    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    let hw_type = u16::from_be_bytes([duid[2], duid[3]]);

    // Only Ethernet (hw_type=1) DUIDs contain a usable MAC
    if hw_type != 1 {
        return None;
    }

    match duid_type {
        1 => {
            // DUID-LLT: type(2) + hw(2) + time(4) + link-layer(6) = 14 bytes
            if duid.len() < 14 {
                return None;
            }
            let mac = &duid[8..14];
            Some(format_mac(mac))
        }
        3 => {
            // DUID-LL: type(2) + hw(2) + link-layer(6) = 10 bytes
            if duid.len() < 10 {
                return None;
            }
            let mac = &duid[4..10];
            Some(format_mac(mac))
        }
        _ => None,
    }
}

/// Run the DHCPv6 server on UDP port 547.
fn run_dhcpv6_server(lan_iface: &str) -> Result<()> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_only_v6(true)?;

    sock.bind_device(Some(lan_iface.as_bytes()))?;

    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 547, 0, 0).into())?;

    let udp: UdpSocket = sock.into();

    info!(iface = %lan_iface, "hermitshell-dhcpv6 listening on [::]:547");

    let mut agent = AgentConn::new();
    let mut buf = [0u8; 1500];
    let mut solicit_times: LruCache<String, Instant> = LruCache::new(NonZeroUsize::new(10_000).expect("nonzero constant"));

    loop {
        let (len, src_addr) = match udp.recv_from(&mut buf) {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
                error!(error = %e, "DHCPv6 recv error");
                continue;
            }
        };

        let data = &buf[..len];

        let msg = match Message6::decode(&mut dhcproto::decoder::Decoder::new(data)) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "DHCPv6 decode error");
                continue;
            }
        };

        // Extract client DUID and MAC
        let client_id = match msg.opts().get(OptionCode6::ClientId) {
            Some(DhcpOption6::ClientId(duid)) => duid.clone(),
            _ => {
                warn!("DHCPv6 packet missing Client ID option");
                continue;
            }
        };

        let mac = match extract_mac_from_duid(&client_id) {
            Some(m) => m,
            None => {
                warn!("DHCPv6 could not extract MAC from DUID");
                continue;
            }
        };

        if !is_valid_mac_str(&mac) {
            warn!(mac = %mac, "DHCPv6 packet from invalid MAC, dropping");
            continue;
        }

        // Extract IA_NA IAID from client request (use 0 as fallback)
        let client_iaid = match msg.opts().get(OptionCode6::IANA) {
            Some(DhcpOption6::IANA(iana)) => iana.id,
            _ => 0,
        };

        let response = match msg.msg_type() {
            MessageType6::Solicit => {
                if let Some(last) = solicit_times.get(&mac) {
                    if last.elapsed().as_secs() < 10 {
                        warn!(mac = %mac, "DHCPv6 SOLICIT rate-limited");
                        continue;
                    }
                }
                solicit_times.put(mac.clone(), Instant::now());
                info!(mac = %mac, "DHCPv6 SOLICIT");
                match handle_solicit6(&mut agent, &msg, &mac, &client_id, client_iaid) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling SOLICIT");
                        continue;
                    }
                }
            }
            MessageType6::Request => {
                info!(mac = %mac, "DHCPv6 REQUEST");
                match handle_request6(&mut agent, &msg, &mac, &client_id, client_iaid) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling DHCPv6 REQUEST");
                        continue;
                    }
                }
            }
            MessageType6::Renew | MessageType6::Rebind => {
                info!(mac = %mac, msg_type = ?msg.msg_type(), "DHCPv6 RENEW/REBIND");
                match handle_request6(&mut agent, &msg, &mac, &client_id, client_iaid) {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(mac = %mac, error = %e, "error handling DHCPv6 RENEW/REBIND");
                        continue;
                    }
                }
            }
            other => {
                debug!(mac = %mac, msg_type = ?other, "DHCPv6 message ignored");
                continue;
            }
        };

        // Encode and send response
        let mut enc_buf = Vec::new();
        let mut encoder = dhcproto::encoder::Encoder::new(&mut enc_buf);
        if let Err(e) = response.encode(&mut encoder) {
            error!(error = %e, "DHCPv6 encode error");
            continue;
        }

        // Reply to client's source address on port 546
        let dest = std::net::SocketAddr::new(src_addr.ip(), v6::CLIENT_PORT);
        if let Err(e) = udp.send_to(&enc_buf, dest) {
            error!(error = %e, "DHCPv6 send error");
        }
    }
}

/// Validate MAC from string format (used by DHCPv6 path after DUID extraction).
fn is_valid_mac_str(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    let bytes: Vec<u8> = parts
        .iter()
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    if bytes.len() != 6 {
        return false;
    }
    is_valid_mac(&bytes)
}

/// Build a DHCPv6 response with common options (server ID, client ID, status).
fn build_v6_response(
    request: &Message6,
    msg_type: MessageType6,
    client_id: &[u8],
    device_ipv6: Ipv6Addr,
    iaid: u32,
) -> Message6 {
    let mut resp = Message6::new_with_id(msg_type, request.xid());

    resp.opts_mut()
        .insert(DhcpOption6::ClientId(client_id.to_vec()));
    resp.opts_mut()
        .insert(DhcpOption6::ServerId(SERVER_DUID.to_vec()));

    // IA_NA with IA_ADDR sub-option
    let mut ia_opts = v6::DhcpOptions::new();
    ia_opts.insert(DhcpOption6::IAAddr(IAAddr {
        addr: device_ipv6,
        preferred_life: LEASE_TIME,
        valid_life: LEASE_TIME,
        opts: v6::DhcpOptions::new(),
    }));

    resp.opts_mut().insert(DhcpOption6::IANA(IANA {
        id: iaid,
        t1: LEASE_TIME / 2,  // renew at half lifetime
        t2: (LEASE_TIME * 4) / 5,  // rebind at 80%
        opts: ia_opts,
    }));

    // DNS Recursive Name Server (option 23): fd00::1
    resp.opts_mut()
        .insert(DhcpOption6::DomainNameServers(vec![SERVER_IPV6_ULA]));

    // Status code: Success
    resp.opts_mut()
        .insert(DhcpOption6::StatusCode(StatusCode {
            status: Status::Success,
            msg: "success".to_string(),
        }));

    resp
}

/// Handle DHCPv6 SOLICIT: IPC to agent, respond with ADVERTISE.
fn handle_solicit6(
    agent: &mut AgentConn,
    request: &Message6,
    mac: &str,
    client_id: &[u8],
    iaid: u32,
) -> Result<Message6> {
    let req = serde_json::json!({
        "method": "dhcp6_discover",
        "mac": mac,
    });
    let resp = agent.request(&req)?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("agent dhcp6_discover failed: {}", err);
    }

    let device_ipv6_str = resp
        .get("device_ipv6_ula")
        .and_then(|v| v.as_str())
        .context("missing device_ipv6_ula in response")?;
    let is_new = resp.get("is_new").and_then(|v| v.as_bool()).unwrap_or(false);

    let device_ipv6: Ipv6Addr = device_ipv6_str.parse()?;

    if is_new {
        info!(mac = %mac, ipv6 = %device_ipv6_str, "DHCPv6 new device allocated");
    } else {
        info!(mac = %mac, ipv6 = %device_ipv6_str, "DHCPv6 known device, advertising existing");
    }

    Ok(build_v6_response(
        request,
        MessageType6::Advertise,
        client_id,
        device_ipv6,
        iaid,
    ))
}

/// Handle DHCPv6 REQUEST/RENEW/REBIND: IPC to agent, provision, respond with REPLY.
fn handle_request6(
    agent: &mut AgentConn,
    request: &Message6,
    mac: &str,
    client_id: &[u8],
    iaid: u32,
) -> Result<Message6> {
    // Look up device (same IPC as discover -- returns existing assignment)
    let req = serde_json::json!({
        "method": "dhcp6_discover",
        "mac": mac,
    });
    let resp = agent.request(&req)?;

    if resp.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let err = resp
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("agent dhcp6_discover failed: {}", err);
    }

    let sid = resp
        .get("subnet_id")
        .and_then(|v| v.as_i64())
        .context("missing subnet_id in response")?;
    let device_ipv6_str = resp
        .get("device_ipv6_ula")
        .and_then(|v| v.as_str())
        .context("missing device_ipv6_ula in response")?;

    let device_ipv6: Ipv6Addr = device_ipv6_str.parse()?;

    info!(mac = %mac, ipv6 = %device_ipv6, "DHCPv6 REPLY, provisioning");

    // Fire-and-forget: provision nftables rules via agent
    if let Err(e) = agent.request(&serde_json::json!({
        "method": "dhcp6_provision",
        "mac": mac,
        "subnet_id": sid,
    })) {
        error!(mac = %mac, error = %e, "failed to provision DHCPv6");
    }

    Ok(build_v6_response(
        request,
        MessageType6::Reply,
        client_id,
        device_ipv6,
        iaid,
    ))
}

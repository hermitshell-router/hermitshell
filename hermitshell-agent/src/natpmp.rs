use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::{debug, error, info, warn};

use crate::db::Db;

const NATPMP_PORT: u16 = 5351;

// NAT-PMP result codes (RFC 6886)
const RESULT_SUCCESS: u16 = 0;
const RESULT_UNSUPPORTED_VERSION: u16 = 1;
const RESULT_NOT_AUTHORIZED: u16 = 2;
const RESULT_NETWORK_FAILURE: u16 = 3;
const RESULT_OUT_OF_RESOURCES: u16 = 4;
const RESULT_UNSUPP_OPCODE: u16 = 5;

// PCP result codes (RFC 6887 §7.4)
const PCP_SUCCESS: u8 = 0;
const PCP_UNSUPP_VERSION: u8 = 1;
const PCP_NOT_AUTHORIZED: u8 = 2;
const PCP_MALFORMED_REQUEST: u8 = 3;
const PCP_UNSUPP_OPCODE: u8 = 4;
const PCP_NETWORK_FAILURE: u8 = 7;
const PCP_NO_RESOURCES: u8 = 8;
const PCP_UNSUPP_PROTOCOL: u8 = 9;
const PCP_ADDRESS_MISMATCH: u8 = 12;

/// Create a UDP socket bound to 0.0.0.0:5351 on the LAN interface.
fn create_socket(lan_iface: &str) -> anyhow::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = format!("0.0.0.0:{}", NATPMP_PORT).parse()?;
    socket.bind(&addr.into())?;
    socket.bind_device(Some(lan_iface.as_bytes()))?;

    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

/// Query the WAN IPv4 address by parsing `ip -4 -o addr show <iface>`.
fn query_wan_ipv4(iface: &str) -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", iface])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(inet_pos) = line.find("inet ") {
            let addr_str = &line[inet_pos + 5..];
            if let Some(slash) = addr_str.find('/') {
                return addr_str[..slash].parse().ok();
            }
        }
    }
    None
}

/// Cached WAN IP lookup — refreshes via subprocess at most every 30 seconds.
fn get_wan_ipv4(iface: &str) -> Option<Ipv4Addr> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(Instant, Option<Ipv4Addr>)>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    if let Some((ts, ip)) = *guard
        && ts.elapsed().as_secs() < 30 {
            return ip;
        }
    let ip = query_wan_ipv4(iface);
    *guard = Some((Instant::now(), ip));
    ip
}

/// Check whether `ip` belongs to a device in the "trusted" group.
fn is_trusted(db: &Db, ip: &str) -> bool {
    let devices = match db.list_assigned_devices() {
        Ok(d) => d,
        Err(_) => return false,
    };
    devices
        .iter()
        .any(|d| d.ipv4.as_deref() == Some(ip) && d.device_group == "trusted")
}

/// Seconds since the given epoch instant (for SSSOE field).
fn epoch_secs(epoch: &Instant) -> u32 {
    epoch.elapsed().as_secs() as u32
}

// ---------------------------------------------------------------------------
// NAT-PMP handlers
// ---------------------------------------------------------------------------

/// Handle a NAT-PMP request (version byte == 0).
/// Returns Some(response_bytes) or None if the packet should be ignored.
fn handle_natpmp(
    data: &[u8],
    src: &SocketAddr,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    wan_iface: &str,
    epoch: &Instant,
) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }

    let opcode = data[1];
    match opcode {
        0 => handle_natpmp_external_address(wan_iface, epoch),
        1 | 2 => handle_natpmp_mapping(data, opcode, src, db, portmap, wan_iface, epoch),
        _ => {
            debug!(opcode = opcode, "unknown NAT-PMP opcode");
            let sssoe = epoch_secs(epoch);
            Some(natpmp_mapping_response(
                opcode | 0x80,
                RESULT_UNSUPP_OPCODE,
                sssoe,
                0,
                0,
                0,
            ))
        }
    }
}

/// Opcode 0: External Address Request.
/// Response: [version=0, opcode=128, result(2), epoch(4), external_ip(4)]
fn handle_natpmp_external_address(wan_iface: &str, epoch: &Instant) -> Option<Vec<u8>> {
    let wan_ip = get_wan_ipv4(wan_iface).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let sssoe = epoch_secs(epoch);

    let mut resp = Vec::with_capacity(12);
    resp.push(0); // version
    resp.push(128); // opcode (0 + 128)
    resp.extend_from_slice(&RESULT_SUCCESS.to_be_bytes()); // result
    resp.extend_from_slice(&sssoe.to_be_bytes()); // epoch
    resp.extend_from_slice(&wan_ip.octets()); // external IP
    Some(resp)
}

/// Opcode 1 (UDP) / 2 (TCP): Mapping Request.
/// Request: [version=0, opcode, reserved(2), internal_port(2), external_port(2), lifetime(4)]
/// Response: [version=0, opcode+128, result(2), epoch(4), internal_port(2), mapped_ext_port(2), mapped_lifetime(4)]
fn handle_natpmp_mapping(
    data: &[u8],
    opcode: u8,
    src: &SocketAddr,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    _wan_iface: &str,
    epoch: &Instant,
) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }

    let internal_port = u16::from_be_bytes([data[4], data[5]]);
    let external_port = u16::from_be_bytes([data[6], data[7]]);
    let lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let protocol = if opcode == 1 { "udp" } else { "tcp" };

    let src_ip = match src {
        SocketAddr::V4(addr) => *addr.ip(),
        _ => return None,
    };
    let src_ip_str = src_ip.to_string();

    let sssoe = epoch_secs(epoch);
    let resp_opcode = opcode + 128;

    // Check trust
    {
        let db_guard = db.lock().unwrap();
        if !is_trusted(&db_guard, &src_ip_str) {
            debug!(ip = %src_ip, "NAT-PMP request from non-trusted device");
            return Some(natpmp_mapping_response(
                resp_opcode,
                RESULT_NOT_AUTHORIZED,
                sssoe,
                internal_port,
                0,
                0,
            ));
        }
    }

    // When external_port is 0, use internal_port as external
    let ext_port = if external_port == 0 {
        internal_port
    } else {
        external_port
    };

    // lifetime=0 means delete
    if lifetime == 0 {
        // M4: Bulk delete when internal_port=0 && external_port=0
        if internal_port == 0 && external_port == 0 {
            if let Err(e) = portmap.remove_all_by_source(protocol, &src_ip_str) {
                warn!(error = %e, "NAT-PMP bulk delete failed");
            } else {
                info!(protocol = %protocol, from = %src_ip, "NAT-PMP bulk delete");
            }
            return Some(natpmp_mapping_response(
                resp_opcode,
                RESULT_SUCCESS,
                sssoe,
                0,
                0,
                0,
            ));
        }

        match portmap.remove_mapping(protocol, ext_port, &src_ip_str) {
            Ok(()) => {
                info!(
                    protocol = %protocol,
                    external_port = ext_port,
                    from = %src_ip,
                    "NAT-PMP mapping removed"
                );
                return Some(natpmp_mapping_response(
                    resp_opcode,
                    RESULT_SUCCESS,
                    sssoe,
                    internal_port,
                    0, // M2: deletion response must have external_port=0
                    0,
                ));
            }
            Err(e) => {
                warn!(error = %e, "NAT-PMP remove mapping failed");
                return Some(natpmp_mapping_response(
                    resp_opcode,
                    RESULT_NETWORK_FAILURE,
                    sssoe,
                    internal_port,
                    ext_port,
                    0,
                ));
            }
        }
    }

    // Create mapping
    let req = crate::portmap::MappingRequest {
        protocol: protocol.to_string(),
        external_port: ext_port,
        internal_ip: src_ip_str.clone(),
        internal_port,
        description: format!("NAT-PMP {}", protocol.to_uppercase()),
        source: "natpmp".to_string(),
        requesting_ip: src_ip_str,
        lease_secs: lifetime,
    };

    match portmap.add_mapping(&req) {
        Ok(resp) => {
            info!(
                protocol = %protocol,
                external_port = resp.external_port,
                internal_port = internal_port,
                from = %src_ip,
                lifetime = resp.lifetime,
                "NAT-PMP mapping added"
            );
            Some(natpmp_mapping_response(
                resp_opcode,
                RESULT_SUCCESS,
                sssoe,
                internal_port,
                resp.external_port,
                resp.lifetime,
            ))
        }
        Err(e) => {
            let result_code = match e {
                crate::portmap::MappingError::NotTrusted => RESULT_NOT_AUTHORIZED,
                crate::portmap::MappingError::PerIpLimit | crate::portmap::MappingError::GlobalLimit => {
                    RESULT_OUT_OF_RESOURCES
                }
                _ => RESULT_NETWORK_FAILURE,
            };
            warn!(error = %e, "NAT-PMP add mapping failed");
            Some(natpmp_mapping_response(
                resp_opcode,
                result_code,
                sssoe,
                internal_port,
                ext_port,
                0,
            ))
        }
    }
}

/// Build a NAT-PMP mapping response (16 bytes).
fn natpmp_mapping_response(
    opcode: u8,
    result: u16,
    sssoe: u32,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(16);
    resp.push(0); // version
    resp.push(opcode);
    resp.extend_from_slice(&result.to_be_bytes());
    resp.extend_from_slice(&sssoe.to_be_bytes());
    resp.extend_from_slice(&internal_port.to_be_bytes());
    resp.extend_from_slice(&external_port.to_be_bytes());
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp
}

// ---------------------------------------------------------------------------
// PCP handlers
// ---------------------------------------------------------------------------

/// Handle a PCP request (version byte == 2).
/// Returns Some(response_bytes) or None if the packet should be ignored.
fn handle_pcp(
    data: &[u8],
    src: &SocketAddr,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    wan_iface: &str,
    epoch: &Instant,
) -> Option<Vec<u8>> {
    // PCP common header is 24 bytes minimum
    if data.len() < 24 {
        return None;
    }

    // M6: PCP packets must be a multiple of 4 octets
    if !data.len().is_multiple_of(4) {
        let sssoe = epoch_secs(epoch);
        return Some(pcp_error_response(0, PCP_MALFORMED_REQUEST, sssoe));
    }

    let opcode_r = data[1];
    // Bit 7 is R flag; should be 0 for requests
    if opcode_r & 0x80 != 0 {
        return None; // This is a response, not a request
    }
    let opcode = opcode_r & 0x7F;

    let lifetime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    // Client IP is bytes 8..24 (IPv4-mapped IPv6)
    let client_ipv4 = extract_ipv4_from_mapped(&data[8..24]);

    let sssoe = epoch_secs(epoch);

    match opcode {
        0 => handle_pcp_announce(sssoe),
        1 => handle_pcp_map(data, client_ipv4, lifetime, src, db, portmap, wan_iface, sssoe),
        _ => {
            debug!(opcode = opcode, "unknown PCP opcode");
            Some(pcp_error_response(opcode, PCP_UNSUPP_OPCODE, sssoe))
        }
    }
}

/// Extract an IPv4 address from an IPv4-mapped IPv6 address (16 bytes).
/// IPv4-mapped: ::ffff:a.b.c.d -> bytes [0..10]=0, [10,11]=0xff, [12..16]=IPv4
/// Also handles plain IPv4-compatible: ::a.b.c.d -> bytes [0..12]=0, [12..16]=IPv4
fn extract_ipv4_from_mapped(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() < 16 {
        return None;
    }
    // Last 4 bytes are the IPv4 address for both mapped and compatible forms
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

/// Opcode 0: ANNOUNCE. Response is just the common header with epoch.
fn handle_pcp_announce(sssoe: u32) -> Option<Vec<u8>> {
    Some(pcp_common_response(0, PCP_SUCCESS, 0, sssoe))
}

/// Opcode 1: MAP.
/// Request has 36 additional bytes after the 24-byte header:
///   nonce(12), protocol(1), reserved(3), internal_port(2),
///   suggested_external_port(2), suggested_external_ip(16)
#[allow(clippy::too_many_arguments)]
fn handle_pcp_map(
    data: &[u8],
    client_ipv4: Option<Ipv4Addr>,
    lifetime: u32,
    src: &SocketAddr,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    wan_iface: &str,
    sssoe: u32,
) -> Option<Vec<u8>> {
    // Need at least 24 (header) + 36 (MAP payload) = 60 bytes
    if data.len() < 60 {
        return None;
    }

    let nonce = &data[24..36];
    let protocol_byte = data[36];
    let internal_port = u16::from_be_bytes([data[40], data[41]]);
    let suggested_ext_port = u16::from_be_bytes([data[42], data[43]]);
    // suggested_external_ip at data[44..60] -- not used, we assign our WAN IP

    // M1: Validate client IP matches UDP source
    let src_ipv4 = match src {
        SocketAddr::V4(addr) => *addr.ip(),
        _ => return None,
    };
    if let Some(client_ip) = client_ipv4
        && client_ip != Ipv4Addr::UNSPECIFIED && client_ip != src_ipv4 {
            return Some(pcp_error_response(1, PCP_ADDRESS_MISMATCH, sssoe));
        }
    let client_ip_str = src_ipv4.to_string();

    let protocol = match protocol_byte {
        6 => "tcp",
        17 => "udp",
        _ => {
            debug!(protocol = protocol_byte, "PCP MAP unsupported protocol");
            return Some(pcp_map_error_response(
                PCP_UNSUPP_PROTOCOL,
                sssoe,
                nonce,
                protocol_byte,
                internal_port,
            ));
        }
    };

    // Check trust
    {
        let db_guard = db.lock().unwrap();
        if !is_trusted(&db_guard, &client_ip_str) {
            debug!(ip = %src_ipv4, "PCP request from non-trusted device");
            return Some(pcp_map_error_response(
                PCP_NOT_AUTHORIZED,
                sssoe,
                nonce,
                protocol_byte,
                internal_port,
            ));
        }
    }

    // Pick external port: if suggested is 0, use internal_port
    let ext_port = if suggested_ext_port == 0 {
        internal_port
    } else {
        suggested_ext_port
    };

    // lifetime=0 means delete
    if lifetime == 0 {
        match portmap.remove_mapping(protocol, ext_port, &client_ip_str) {
            Ok(()) => {
                info!(
                    protocol = %protocol,
                    external_port = ext_port,
                    from = %src_ipv4,
                    "PCP mapping removed"
                );
                let wan_ip = get_wan_ipv4(wan_iface).unwrap_or(Ipv4Addr::UNSPECIFIED);
                return Some(pcp_map_response(
                    PCP_SUCCESS, 0, sssoe, nonce, protocol_byte, internal_port, ext_port, wan_ip,
                ));
            }
            Err(e) => {
                warn!(error = %e, "PCP remove mapping failed");
                return Some(pcp_map_error_response(
                    PCP_NETWORK_FAILURE,
                    sssoe,
                    nonce,
                    protocol_byte,
                    internal_port,
                ));
            }
        }
    }

    // Create mapping
    let req = crate::portmap::MappingRequest {
        protocol: protocol.to_string(),
        external_port: ext_port,
        internal_ip: client_ip_str.clone(),
        internal_port,
        description: format!("PCP {}", protocol.to_uppercase()),
        source: "pcp".to_string(),
        requesting_ip: client_ip_str,
        lease_secs: lifetime,
    };

    match portmap.add_mapping(&req) {
        Ok(resp) => {
            let wan_ip = get_wan_ipv4(wan_iface).unwrap_or(Ipv4Addr::UNSPECIFIED);
            info!(
                protocol = %protocol,
                external_port = resp.external_port,
                internal_port = internal_port,
                from = %src_ipv4,
                lifetime = resp.lifetime,
                "PCP mapping added"
            );
            Some(pcp_map_response(
                PCP_SUCCESS,
                resp.lifetime,
                sssoe,
                nonce,
                protocol_byte,
                internal_port,
                resp.external_port,
                wan_ip,
            ))
        }
        Err(e) => {
            let result_code = match e {
                crate::portmap::MappingError::NotTrusted => PCP_NOT_AUTHORIZED,
                crate::portmap::MappingError::PerIpLimit
                | crate::portmap::MappingError::GlobalLimit => PCP_NO_RESOURCES,
                _ => PCP_NETWORK_FAILURE,
            };
            warn!(error = %e, "PCP add mapping failed");
            Some(pcp_map_error_response(
                result_code,
                sssoe,
                nonce,
                protocol_byte,
                internal_port,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// PCP response builders
// ---------------------------------------------------------------------------

/// Build the 24-byte PCP common response header.
/// [version(1), opcode|R(1), reserved(1), result(1), lifetime(4), epoch(4), reserved(12)]
fn pcp_common_response(opcode: u8, result: u8, lifetime: u32, sssoe: u32) -> Vec<u8> {
    let mut resp = Vec::with_capacity(24);
    resp.push(2); // version
    resp.push(opcode | 0x80); // opcode with R=1 (response)
    resp.push(0); // reserved
    resp.push(result);
    resp.extend_from_slice(&lifetime.to_be_bytes());
    resp.extend_from_slice(&sssoe.to_be_bytes());
    resp.extend_from_slice(&[0u8; 12]); // reserved
    resp
}

/// Build a PCP error response (header only, no opcode-specific payload).
fn pcp_error_response(opcode: u8, result: u8, sssoe: u32) -> Vec<u8> {
    pcp_common_response(opcode, result, 0, sssoe)
}

/// Build a PCP MAP success response: common header (24) + MAP payload (36) = 60 bytes.
#[allow(clippy::too_many_arguments)]
fn pcp_map_response(
    result: u8,
    lifetime: u32,
    sssoe: u32,
    nonce: &[u8],
    protocol: u8,
    internal_port: u16,
    external_port: u16,
    external_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut resp = pcp_common_response(1, result, lifetime, sssoe);
    // MAP payload: nonce(12)
    resp.extend_from_slice(nonce);
    // protocol(1), reserved(3)
    resp.push(protocol);
    resp.extend_from_slice(&[0u8; 3]);
    // internal_port(2)
    resp.extend_from_slice(&internal_port.to_be_bytes());
    // assigned_external_port(2)
    resp.extend_from_slice(&external_port.to_be_bytes());
    // assigned_external_ip(16) as IPv4-mapped IPv6
    resp.extend_from_slice(&[0u8; 10]);
    resp.extend_from_slice(&[0xFF, 0xFF]);
    resp.extend_from_slice(&external_ip.octets());
    resp
}

/// Build a PCP MAP error response (same structure, zero ports/IP).
fn pcp_map_error_response(
    result: u8,
    sssoe: u32,
    nonce: &[u8],
    protocol: u8,
    internal_port: u16,
) -> Vec<u8> {
    pcp_map_response(
        result,
        0,
        sssoe,
        nonce,
        protocol,
        internal_port,
        0,
        Ipv4Addr::UNSPECIFIED,
    )
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build a gratuitous NAT-PMP external address response for announcement.
fn build_announcement(wan_ip: Ipv4Addr, epoch: &Instant) -> Vec<u8> {
    let sssoe = epoch_secs(epoch);
    let mut resp = Vec::with_capacity(12);
    resp.push(0); // version
    resp.push(128); // opcode (0 + 128)
    resp.extend_from_slice(&RESULT_SUCCESS.to_be_bytes()); // result
    resp.extend_from_slice(&sssoe.to_be_bytes()); // epoch
    resp.extend_from_slice(&wan_ip.octets()); // external IP
    resp
}

pub async fn run(
    db: Arc<Mutex<Db>>,
    portmap: crate::portmap::SharedRegistry,
    lan_iface: String,
    wan_iface: String,
) {
    info!(iface = %lan_iface, "starting NAT-PMP/PCP listener");

    let socket = match create_socket(&lan_iface) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(error = %e, "failed to create NAT-PMP socket");
            return;
        }
    };

    let epoch = Instant::now();

    // M5: Monitor WAN IP and send gratuitous announcements on change
    {
        let announce_socket = Arc::clone(&socket);
        let announce_wan = wan_iface.clone();
        let announce_epoch = epoch;
        tokio::spawn(async move {
            let multicast_dest: SocketAddr = "224.0.0.1:5350".parse().unwrap();
            let mut last_wan_ip = query_wan_ipv4(&announce_wan);

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let current_ip = query_wan_ipv4(&announce_wan);
                if current_ip != last_wan_ip {
                    let ip = current_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
                    info!(new_ip = %ip, "WAN IP changed, sending gratuitous announcements");
                    let resp = build_announcement(ip, &announce_epoch);
                    // Send 10 announcements with exponential backoff starting at 250ms
                    let mut delay = std::time::Duration::from_millis(250);
                    for _ in 0..10 {
                        if let Err(e) = announce_socket.send_to(&resp, multicast_dest).await {
                            debug!(error = %e, "gratuitous announcement send failed");
                        }
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                    last_wan_ip = current_ip;
                }
            }
        });
    }

    let mut buf = [0u8; 1100]; // PCP max payload

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "NAT-PMP recv error");
                continue;
            }
        };

        let data = &buf[..len];
        if data.is_empty() {
            continue;
        }

        let response = match data[0] {
            0 => handle_natpmp(data, &src, &db, &portmap, &wan_iface, &epoch),
            2 => handle_pcp(data, &src, &db, &portmap, &wan_iface, &epoch),
            v => {
                debug!(version = v, "unknown NAT-PMP/PCP version");
                // For NAT-PMP, return unsupported version error
                if v < 2 {
                    if data.len() >= 2 {
                        let sssoe = epoch_secs(&epoch);
                        Some(natpmp_mapping_response(
                            data[1] + 128,
                            RESULT_UNSUPPORTED_VERSION,
                            sssoe,
                            0,
                            0,
                            0,
                        ))
                    } else {
                        None
                    }
                } else {
                    // PCP version mismatch
                    let sssoe = epoch_secs(&epoch);
                    Some(pcp_error_response(0, PCP_UNSUPP_VERSION, sssoe))
                }
            }
        };

        if let Some(resp_bytes) = response
            && let Err(e) = socket.send_to(&resp_bytes, src).await {
                debug!(error = %e, dest = %src, "NAT-PMP/PCP response send failed");
            }
    }
}

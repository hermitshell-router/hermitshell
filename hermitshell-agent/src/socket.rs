use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::blocky::BlockyManager;
use crate::db::Db;
use crate::nftables;
use hermitshell_common::subnet;

fn sanitize_hostname(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_')
        .take(63)
        .collect()
}

#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    mac: Option<String>,
    group: Option<String>,
    enabled: Option<bool>,
    subnet_id: Option<i64>,
    name: Option<String>,
    public_key: Option<String>,
    hostname: Option<String>,
    id: Option<i64>,
    protocol: Option<String>,
    external_port_start: Option<u16>,
    external_port_end: Option<u16>,
    internal_ip: Option<String>,
    internal_port: Option<u16>,
    description: Option<String>,
    key: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<crate::db::Device>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<crate::db::Device>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ad_blocking_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subnet_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_new: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wireguard: Option<WireguardInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dhcp_reservations: Option<Vec<crate::db::DhcpReservation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_forwards: Option<Vec<crate::db::PortForward>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmz_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_value: Option<String>,
}

#[derive(Debug, Serialize)]
struct Status {
    uptime_secs: u64,
    device_count: usize,
    ad_blocking_enabled: bool,
}

#[derive(Debug, Serialize)]
struct WireguardInfo {
    enabled: bool,
    public_key: Option<String>,
    listen_port: u16,
    peers: Vec<WgPeerInfo>,
}

#[derive(Debug, Serialize)]
struct WgPeerInfo {
    public_key: String,
    name: String,
    ip: String,
    device_group: String,
    enabled: bool,
}

impl Response {
    fn ok() -> Self {
        Self { ok: true, error: None, devices: None, device: None, status: None, ad_blocking_enabled: None, subnet_id: None, device_ip: None, is_new: None, wireguard: None, dhcp_reservations: None, port_forwards: None, dmz_ip: None, config_value: None }
    }
    fn err(msg: &str) -> Self {
        Self { ok: false, error: Some(msg.to_string()), devices: None, device: None, status: None, ad_blocking_enabled: None, subnet_id: None, device_ip: None, is_new: None, wireguard: None, dhcp_reservations: None, port_forwards: None, dmz_ip: None, config_value: None }
    }
}

pub async fn run_server(socket_path: &str, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String) -> Result<()> {
    // Remove old socket if exists
    let _ = std::fs::remove_file(socket_path);

    // Create socket directory
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set permissions so container can access
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!(path = socket_path, "socket server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();
        let start = start_time;
        let blocky = blocky.clone();
        let wan = wan_iface.clone();
        let lan = lan_iface.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, db, start, blocky, wan, lan).await {
                warn!(error = %e, "client error");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(req, &db, start_time, &blocky, &wan_iface, &lan_iface),
            Err(e) => Response::err(&format!("Invalid JSON: {}", e)),
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

fn handle_request(req: Request, db: &Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: &Arc<Mutex<BlockyManager>>, wan_iface: &str, lan_iface: &str) -> Response {
    // Validate MAC early if provided (before any DB lookups)
    if let Some(ref mac) = req.mac {
        if let Err(e) = nftables::validate_mac(mac) {
            return Response::err(&e.to_string());
        }
    }
    match req.method.as_str() {
        "list_devices" => {
            let db = db.lock().unwrap();
            match db.list_devices() {
                Ok(devices) => {
                    let mut resp = Response::ok();
                    resp.devices = Some(devices);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            match db.get_device(&mac) {
                Ok(Some(device)) => {
                    let mut resp = Response::ok();
                    resp.device = Some(device);
                    resp
                }
                Ok(None) => Response::err("device not found"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_status" => {
            let db = db.lock().unwrap();
            let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
            let ad_blocking = db
                .get_config("ad_blocking_enabled")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(true);
            let mut resp = Response::ok();
            resp.status = Some(Status {
                uptime_secs: start_time.elapsed().as_secs(),
                device_count,
                ad_blocking_enabled: ad_blocking,
            });
            resp
        }
        "set_device_group" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let Some(group) = req.group else {
                return Response::err("group required");
            };
            match group.as_str() {
                "quarantine" | "trusted" | "iot" | "guest" | "servers" => {}
                _ => return Response::err("invalid group: must be quarantine, trusted, iot, guest, or servers"),
            }
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            let Some(subnet_id) = device.subnet_id else {
                return Response::err("device has no subnet assignment");
            };
            let Some(info) = subnet::compute_subnet(subnet_id) else {
                return Response::err("invalid subnet_id");
            };
            let ip = &info.device_ip;
            if let Err(e) = nftables::remove_device_forward_rule(ip) {
                return Response::err(&format!("failed to remove old rule: {}", e));
            }
            if let Err(e) = db.set_device_group(&mac, &group) {
                return Response::err(&format!("failed to update group: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(ip, &group) {
                return Response::err(&format!("failed to add new rule: {}", e));
            }
            match db.get_device(&mac) {
                Ok(Some(device)) => {
                    let mut resp = Response::ok();
                    resp.device = Some(device);
                    resp
                }
                Ok(None) => Response::err("device not found after update"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "block_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Some(ref ip) = device.ip {
                if let Err(e) = nftables::remove_device_forward_rule(ip) {
                    return Response::err(&format!("failed to remove forward rule: {}", e));
                }
                if let Err(e) = nftables::add_device_forward_rule(ip, "blocked") {
                    return Response::err(&format!("failed to add blocked rule: {}", e));
                }
            }
            if let Err(e) = db.block_device(&mac) {
                return Response::err(&format!("failed to block device: {}", e));
            }
            Response::ok()
        }
        "unblock_device" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Err(e) = db.unblock_device(&mac) {
                return Response::err(&format!("failed to unblock device: {}", e));
            }
            if let Some(ref ip) = device.ip {
                if let Err(e) = nftables::remove_device_forward_rule(ip) {
                    return Response::err(&format!("failed to remove blocked rule: {}", e));
                }
                if let Err(e) = nftables::add_device_forward_rule(ip, "quarantine") {
                    return Response::err(&format!("failed to add forward rule: {}", e));
                }
            }
            Response::ok()
        }
        "get_ad_blocking" => {
            let db = db.lock().unwrap();
            let enabled = db
                .get_config("ad_blocking_enabled")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(true);
            let mut resp = Response::ok();
            resp.ad_blocking_enabled = Some(enabled);
            resp
        }
        "set_ad_blocking" => {
            let Some(enabled) = req.enabled else {
                return Response::err("enabled required");
            };
            let db = db.lock().unwrap();
            if let Err(e) = db.set_config("ad_blocking_enabled", if enabled { "true" } else { "false" }) {
                return Response::err(&format!("failed to update config: {}", e));
            }
            drop(db);
            let mgr = blocky.lock().unwrap();
            if let Err(e) = mgr.set_blocking_enabled(enabled) {
                return Response::err(&format!("failed to update blocky: {}", e));
            }
            let mut resp = Response::ok();
            resp.ad_blocking_enabled = Some(enabled);
            resp
        }
        "get_wireguard" => {
            let db = db.lock().unwrap();
            let enabled = db.get_config("wg_enabled")
                .ok().flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            let public_key = if enabled {
                db.get_config("wg_private_key").ok().flatten().and_then(|privkey| {
                    crate::wireguard::pubkey_from_private(&privkey).ok()
                })
            } else {
                None
            };
            let listen_port: u16 = db.get_config("wg_listen_port")
                .ok().flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(51820);
            let peers = db.list_wg_peers().unwrap_or_default();
            let peer_infos: Vec<WgPeerInfo> = peers.iter().filter_map(|p| {
                let info = subnet::compute_subnet(p.subnet_id)?;
                Some(WgPeerInfo {
                    public_key: p.public_key.clone(),
                    name: p.name.clone(),
                    ip: info.device_ip,
                    device_group: p.device_group.clone(),
                    enabled: p.enabled,
                })
            }).collect();
            let mut resp = Response::ok();
            resp.wireguard = Some(WireguardInfo {
                enabled,
                public_key,
                listen_port,
                peers: peer_infos,
            });
            resp
        }
        "set_wireguard_enabled" => {
            let Some(enabled) = req.enabled else {
                return Response::err("enabled required");
            };
            let db = db.lock().unwrap();
            if enabled {
                let private_key = match db.get_config("wg_private_key").ok().flatten() {
                    Some(key) => key,
                    None => {
                        let (privkey, _pubkey) = match crate::wireguard::generate_keypair() {
                            Ok(kp) => kp,
                            Err(e) => return Response::err(&format!("keygen failed: {}", e)),
                        };
                        if let Err(e) = db.set_config("wg_private_key", &privkey) {
                            return Response::err(&format!("failed to store key: {}", e));
                        }
                        privkey
                    }
                };
                let listen_port: u16 = db.get_config("wg_listen_port")
                    .ok().flatten()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(51820);
                if let Err(e) = crate::wireguard::create_interface(&private_key, listen_port) {
                    return Response::err(&format!("failed to create wg0: {}", e));
                }
                if let Err(e) = crate::wireguard::open_listen_port(listen_port) {
                    return Response::err(&format!("failed to open port: {}", e));
                }
                let peers = db.list_wg_peers().unwrap_or_default();
                for peer in &peers {
                    if !peer.enabled { continue; }
                    if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                        let _ = crate::wireguard::add_peer(&peer.public_key, &info.device_ip);
                        let _ = nftables::add_device_counter(&info.device_ip);
                        let _ = nftables::add_device_forward_rule(&info.device_ip, &peer.device_group);
                    }
                }
                if let Err(e) = db.set_config("wg_enabled", "true") {
                    return Response::err(&format!("failed to save config: {}", e));
                }
            } else {
                let peers = db.list_wg_peers().unwrap_or_default();
                for peer in &peers {
                    if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                        let _ = nftables::remove_device_forward_rule(&info.device_ip);
                        let _ = crate::wireguard::remove_peer(&peer.public_key, &info.device_ip);
                    }
                }
                let _ = crate::wireguard::close_listen_port();
                let _ = crate::wireguard::destroy_interface();
                if let Err(e) = db.set_config("wg_enabled", "false") {
                    return Response::err(&format!("failed to save config: {}", e));
                }
            }
            Response::ok()
        }
        "add_wg_peer" => {
            let Some(name) = req.name else {
                return Response::err("name required");
            };
            let Some(public_key) = req.public_key else {
                return Response::err("public_key required");
            };
            let group = req.group.as_deref().unwrap_or("quarantine");
            match group {
                "quarantine" | "trusted" | "iot" | "guest" | "servers" => {}
                _ => return Response::err("invalid group"),
            }
            let db = db.lock().unwrap();
            let wg_enabled = db.get_config("wg_enabled")
                .ok().flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            if !wg_enabled {
                return Response::err("WireGuard is not enabled");
            }
            if let Ok(Some(_)) = db.get_wg_peer(&public_key) {
                return Response::err("peer already exists");
            }
            let subnet_id = match db.allocate_subnet_id() {
                Ok(s) => s,
                Err(e) => return Response::err(&format!("subnet allocation failed: {}", e)),
            };
            let Some(info) = subnet::compute_subnet(subnet_id) else {
                return Response::err("subnet address space exhausted");
            };
            if let Err(e) = crate::wireguard::add_peer(&public_key, &info.device_ip) {
                return Response::err(&format!("failed to add peer: {}", e));
            }
            if let Err(e) = nftables::add_device_counter(&info.device_ip) {
                return Response::err(&format!("failed to add counter: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(&info.device_ip, group) {
                return Response::err(&format!("failed to add forward rule: {}", e));
            }
            if let Err(e) = db.insert_wg_peer(&public_key, &name, subnet_id, group) {
                return Response::err(&format!("failed to save peer: {}", e));
            }
            let server_pubkey = db.get_config("wg_private_key")
                .ok().flatten()
                .and_then(|k| crate::wireguard::pubkey_from_private(&k).ok())
                .unwrap_or_default();
            let listen_port: u16 = db.get_config("wg_listen_port")
                .ok().flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(51820);
            let mut resp = Response::ok();
            resp.device_ip = Some(info.device_ip);
            resp.wireguard = Some(WireguardInfo {
                enabled: true,
                public_key: Some(server_pubkey),
                listen_port,
                peers: vec![],
            });
            resp
        }
        "remove_wg_peer" => {
            let Some(public_key) = req.public_key else {
                return Response::err("public_key required");
            };
            let db = db.lock().unwrap();
            let peer = match db.get_wg_peer(&public_key) {
                Ok(Some(p)) => p,
                Ok(None) => return Response::err("peer not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                let _ = nftables::remove_device_forward_rule(&info.device_ip);
                let _ = crate::wireguard::remove_peer(&public_key, &info.device_ip);
            }
            if let Err(e) = db.remove_wg_peer(&public_key) {
                return Response::err(&format!("failed to remove peer: {}", e));
            }
            Response::ok()
        }
        "set_wg_peer_group" => {
            let Some(public_key) = req.public_key else {
                return Response::err("public_key required");
            };
            let Some(group) = req.group else {
                return Response::err("group required");
            };
            match group.as_str() {
                "quarantine" | "trusted" | "iot" | "guest" | "servers" => {}
                _ => return Response::err("invalid group"),
            }
            let db = db.lock().unwrap();
            let peer = match db.get_wg_peer(&public_key) {
                Ok(Some(p)) => p,
                Ok(None) => return Response::err("peer not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            let Some(info) = subnet::compute_subnet(peer.subnet_id) else {
                return Response::err("invalid subnet_id");
            };
            if let Err(e) = nftables::remove_device_forward_rule(&info.device_ip) {
                return Response::err(&format!("failed to remove old rule: {}", e));
            }
            if let Err(e) = db.set_wg_peer_group(&public_key, &group) {
                return Response::err(&format!("failed to update group: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(&info.device_ip, &group) {
                return Response::err(&format!("failed to add new rule: {}", e));
            }
            Response::ok()
        }
        "list_dhcp_reservations" => {
            let db = db.lock().unwrap();
            match db.list_dhcp_reservations() {
                Ok(reservations) => {
                    let mut resp = Response::ok();
                    resp.dhcp_reservations = Some(reservations);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "set_dhcp_reservation" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            let subnet_id = match req.subnet_id {
                Some(sid) => sid,
                None => {
                    match db.get_device(&mac) {
                        Ok(Some(dev)) if dev.subnet_id.is_some() => dev.subnet_id.unwrap(),
                        Ok(_) => return Response::err("device has no subnet assignment; provide subnet_id"),
                        Err(e) => return Response::err(&e.to_string()),
                    }
                }
            };
            if subnet::compute_subnet(subnet_id).is_none() {
                return Response::err("subnet_id out of range");
            }
            if let Err(e) = db.set_dhcp_reservation(&mac, subnet_id) {
                return Response::err(&format!("failed to set reservation: {}", e));
            }
            Response::ok()
        }
        "remove_dhcp_reservation" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();
            if let Err(e) = db.remove_dhcp_reservation(&mac) {
                return Response::err(&format!("failed to remove reservation: {}", e));
            }
            Response::ok()
        }
        "get_config" => {
            let Some(key) = req.key else { return Response::err("key required"); };
            match key.as_str() {
                "admin_password_hash" | "session_secret" | "wg_private_key" =>
                    return Response::err("access denied"),
                _ => {}
            }
            let db = db.lock().unwrap();
            match db.get_config(&key) {
                Ok(val) => {
                    let mut resp = Response::ok();
                    resp.config_value = val;
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "set_config" => {
            let Some(key) = req.key else { return Response::err("key required"); };
            let Some(value) = req.value else { return Response::err("value required"); };
            let db = db.lock().unwrap();
            match db.set_config(&key, &value) {
                Ok(()) => Response::ok(),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "list_port_forwards" => {
            let db = db.lock().unwrap();
            match db.list_port_forwards() {
                Ok(forwards) => {
                    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
                    let mut resp = Response::ok();
                    resp.port_forwards = Some(forwards);
                    resp.dmz_ip = Some(dmz);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "add_port_forward" => {
            let Some(protocol) = req.protocol else { return Response::err("protocol required"); };
            let Some(ext_start) = req.external_port_start else { return Response::err("external_port_start required"); };
            let Some(ext_end) = req.external_port_end else { return Response::err("external_port_end required"); };
            let Some(internal_ip) = req.internal_ip else { return Response::err("internal_ip required"); };
            let Some(int_port) = req.internal_port else { return Response::err("internal_port required"); };
            let desc = req.description.as_deref().unwrap_or("");
            match protocol.as_str() {
                "tcp" | "udp" | "both" => {}
                _ => return Response::err("protocol must be tcp, udp, or both"),
            }
            if ext_start == 0 || ext_end == 0 || int_port == 0 {
                return Response::err("ports must be 1-65535");
            }
            if ext_end < ext_start {
                return Response::err("external_port_end must be >= external_port_start");
            }
            if let Err(e) = nftables::validate_ip_pub(&internal_ip) {
                return Response::err(&e.to_string());
            }
            let db = db.lock().unwrap();
            match db.add_port_forward(&protocol, ext_start, ext_end, &internal_ip, int_port, desc) {
                Ok(_id) => {
                    let forwards = db.list_enabled_port_forwards().unwrap_or_default();
                    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
                    let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
                    if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                        return Response::err(&format!("failed to apply rules: {}", e));
                    }
                    Response::ok()
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "remove_port_forward" => {
            let Some(id) = req.id else { return Response::err("id required"); };
            let db = db.lock().unwrap();
            if let Err(e) = db.remove_port_forward(id) {
                return Response::err(&e.to_string());
            }
            let forwards = db.list_enabled_port_forwards().unwrap_or_default();
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
            if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                return Response::err(&format!("failed to apply rules: {}", e));
            }
            Response::ok()
        }
        "set_port_forward_enabled" => {
            let Some(id) = req.id else { return Response::err("id required"); };
            let Some(enabled) = req.enabled else { return Response::err("enabled required"); };
            let db = db.lock().unwrap();
            if let Err(e) = db.set_port_forward_enabled(id, enabled) {
                return Response::err(&e.to_string());
            }
            let forwards = db.list_enabled_port_forwards().unwrap_or_default();
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
            if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                return Response::err(&format!("failed to apply rules: {}", e));
            }
            Response::ok()
        }
        "get_dmz" => {
            let db = db.lock().unwrap();
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let mut resp = Response::ok();
            resp.dmz_ip = Some(dmz);
            resp
        }
        "set_dmz" => {
            let Some(ip) = req.internal_ip else { return Response::err("internal_ip required (empty string to clear)"); };
            if !ip.is_empty() {
                if let Err(e) = nftables::validate_ip_pub(&ip) {
                    return Response::err(&e.to_string());
                }
            }
            let db = db.lock().unwrap();
            if let Err(e) = db.set_config("dmz_host_ip", &ip) {
                return Response::err(&e.to_string());
            }
            let forwards = db.list_enabled_port_forwards().unwrap_or_default();
            let dmz_ref = if ip.is_empty() { None } else { Some(ip.as_str()) };
            if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                return Response::err(&format!("failed to apply rules: {}", e));
            }
            Response::ok()
        }
        _ => Response::err("unknown method"),
    }
}

pub async fn run_dhcp_socket(socket_path: &str, db: Arc<Mutex<Db>>, lan_iface: String) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);

    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }

    info!(path = socket_path, "DHCP IPC socket listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();
        let lan_iface = lan_iface.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_dhcp_client(stream, db, lan_iface).await {
                warn!(error = %e, "DHCP IPC client error");
            }
        });
    }
}

async fn handle_dhcp_client(stream: UnixStream, db: Arc<Mutex<Db>>, lan_iface: String) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_dhcp_request(req, &db, &lan_iface),
            Err(e) => Response::err(&format!("Invalid JSON: {}", e)),
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

fn handle_dhcp_request(req: Request, db: &Arc<Mutex<Db>>, lan_iface: &str) -> Response {
    // Validate MAC early if provided
    if let Some(ref mac) = req.mac {
        if let Err(e) = nftables::validate_mac(mac) {
            return Response::err(&e.to_string());
        }
    }
    match req.method.as_str() {
        "dhcp_discover" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();

            // Store hostname if provided
            if let Some(ref hostname) = req.hostname {
                let clean = sanitize_hostname(hostname);
                if !clean.is_empty() {
                    let _ = db.set_device_hostname(&mac, &clean);
                }
            }

            // Check reservation first
            let reserved_sid = db.get_dhcp_reservation(&mac).ok().flatten().map(|r| r.subnet_id);

            match db.get_device(&mac) {
                Ok(Some(dev)) if dev.subnet_id.is_some() => {
                    let sid = reserved_sid.unwrap_or_else(|| dev.subnet_id.unwrap());
                    let Some(info) = subnet::compute_subnet(sid) else {
                        return Response::err("subnet_id out of range");
                    };
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ip = Some(info.device_ip);
                    resp.is_new = Some(false);
                    resp
                }
                Ok(_) => {
                    let sid = match reserved_sid {
                        Some(sid) => sid,
                        None => match db.allocate_subnet_id() {
                            Ok(s) => s,
                            Err(e) => return Response::err(&e.to_string()),
                        },
                    };
                    let Some(info) = subnet::compute_subnet(sid) else {
                        return Response::err("subnet address space exhausted");
                    };
                    if let Err(e) = db.insert_new_device(&mac, sid, &info.device_ip) {
                        return Response::err(&e.to_string());
                    }
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ip = Some(info.device_ip);
                    resp.is_new = Some(true);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "dhcp_provision" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let Some(sid) = req.subnet_id else {
                return Response::err("subnet_id required");
            };
            let Some(info) = subnet::compute_subnet(sid) else {
                return Response::err("invalid subnet_id");
            };

            info!(mac = %mac, ip = %info.device_ip, gateway = %info.gateway, "DHCP provision");

            if let Err(e) = nftables::add_gateway_address(&info.gateway, lan_iface) {
                error!(gateway = %info.gateway, error = %e, "failed to add gateway address");
            }
            if let Err(e) = nftables::add_device_counter(&info.device_ip) {
                error!(ip = %info.device_ip, error = %e, "failed to add device counter");
            }
            if let Err(e) = nftables::add_device_forward_rule(&info.device_ip, "quarantine") {
                error!(ip = %info.device_ip, error = %e, "failed to add forward rule");
            }

            Response::ok()
        }
        _ => Response::err("unknown method"),
    }
}

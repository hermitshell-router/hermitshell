use anyhow::Result;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

use crate::blocky::BlockyManager;
use crate::db::Db;
use crate::log_export::LogEvent;
use crate::nftables;
use hermitshell_common::subnet;

fn sanitize_hostname(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_')
        .take(63)
        .collect()
}

const BLOCKED_CONFIG_KEYS: &[&str] = &[
    "admin_password_hash",
    "session_secret",
    "wg_private_key",
    "tls_key_pem",
    "tls_cert_pem",
    "runzero_token",
];

fn is_blocked_config_key(key: &str) -> bool {
    BLOCKED_CONFIG_KEYS.contains(&key)
}

type LoginRateLimit = Arc<Mutex<(u32, Option<std::time::Instant>)>>;

/// Check if login is currently rate-limited. Returns error message if blocked.
fn check_login_rate_limit(rate_limit: &LoginRateLimit) -> Option<String> {
    let state = rate_limit.lock().unwrap();
    let (failures, last_failure) = &*state;
    if *failures == 0 {
        return None;
    }
    let Some(last) = last_failure else {
        return None;
    };
    let shift = std::cmp::min(*failures - 1, 63);
    let backoff_secs = std::cmp::min(1u64 << shift, 60);
    let elapsed = last.elapsed().as_secs();
    if elapsed < backoff_secs {
        let remaining = backoff_secs - elapsed;
        Some(format!("Too many attempts. Try again in {}s.", remaining))
    } else {
        None
    }
}

/// Record a failed login attempt.
fn record_login_failure(rate_limit: &LoginRateLimit) {
    let mut state = rate_limit.lock().unwrap();
    state.0 = state.0.saturating_add(1);
    state.1 = Some(std::time::Instant::now());
}

/// Reset login rate limit on success.
fn reset_login_rate_limit(rate_limit: &LoginRateLimit) {
    let mut state = rate_limit.lock().unwrap();
    state.0 = 0;
    state.1 = None;
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
    port_start: Option<u16>,
    port_end: Option<u16>,
    external_port_start: Option<u16>,
    external_port_end: Option<u16>,
    internal_ip: Option<String>,
    internal_port: Option<u16>,
    description: Option<String>,
    key: Option<String>,
    value: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    rule: Option<String>,
    severity: Option<String>,
    acknowledged: Option<bool>,
    upload_mbps: Option<u32>,
    download_mbps: Option<u32>,
    url: Option<String>,
    nickname: Option<String>,
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
    device_ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_ipv6_ula: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_logs: Option<Vec<crate::db::ConnectionLog>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_logs: Option<Vec<crate::db::DnsLogEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_pinholes: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_cert_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_key_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runzero_config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<Vec<crate::db::Alert>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alert: Option<crate::db::Alert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analyzer_status: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qos_config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_logs: Option<Vec<crate::db::AuditEntry>>,
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
    ipv4: String,
    ipv6_ula: String,
    device_group: String,
    enabled: bool,
}

impl Response {
    fn ok() -> Self {
        Self { ok: true, error: None, devices: None, device: None, status: None, ad_blocking_enabled: None, subnet_id: None, device_ipv4: None, device_ipv6_ula: None, is_new: None, wireguard: None, dhcp_reservations: None, port_forwards: None, dmz_ip: None, config_value: None, connection_logs: None, dns_logs: None, log_config: None, ipv6_pinholes: None, tls_cert_pem: None, tls_key_pem: None, runzero_config: None, alerts: None, alert: None, analyzer_status: None, qos_config: None, audit_logs: None }
    }
    fn err(msg: &str) -> Self {
        Self { ok: false, error: Some(msg.to_string()), devices: None, device: None, status: None, ad_blocking_enabled: None, subnet_id: None, device_ipv4: None, device_ipv6_ula: None, is_new: None, wireguard: None, dhcp_reservations: None, port_forwards: None, dmz_ip: None, config_value: None, connection_logs: None, dns_logs: None, log_config: None, ipv6_pinholes: None, tls_cert_pem: None, tls_key_pem: None, runzero_config: None, alerts: None, alert: None, analyzer_status: None, qos_config: None, audit_logs: None }
    }
}

pub async fn run_server(socket_path: &str, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String, log_tx: tokio::sync::mpsc::UnboundedSender<LogEvent>) -> Result<()> {
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

    let login_rate_limit: LoginRateLimit = Arc::new(Mutex::new((0, None)));

    loop {
        let (stream, _) = listener.accept().await?;
        let db = db.clone();
        let start = start_time;
        let blocky = blocky.clone();
        let wan = wan_iface.clone();
        let lan = lan_iface.clone();
        let ltx = log_tx.clone();
        let lrl = login_rate_limit.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, db, start, blocky, wan, lan, ltx, lrl).await {
                warn!(error = %e, "client error");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String, log_tx: tokio::sync::mpsc::UnboundedSender<LogEvent>, login_rate_limit: LoginRateLimit) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(req, &db, start_time, &blocky, &wan_iface, &lan_iface, &log_tx, &login_rate_limit),
            Err(e) => Response::err(&format!("Invalid JSON: {}", e)),
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}

fn handle_request(req: Request, db: &Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: &Arc<Mutex<BlockyManager>>, wan_iface: &str, lan_iface: &str, log_tx: &tokio::sync::mpsc::UnboundedSender<LogEvent>, login_rate_limit: &LoginRateLimit) -> Response {
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
            let ipv4 = info.device_ipv4.to_string();
            let ipv6 = info.device_ipv6_ula.to_string();
            if let Err(e) = nftables::remove_device_forward_rule(&ipv4) {
                return Response::err(&format!("failed to remove old rule: {}", e));
            }
            let _ = nftables::remove_device_forward_rule_v6(&ipv6);
            if let Err(e) = db.set_device_group(&mac, &group) {
                return Response::err(&format!("failed to update group: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(&ipv4, &group) {
                return Response::err(&format!("failed to add new rule: {}", e));
            }
            let _ = nftables::add_device_forward_rule_v6(&ipv6, &group);
            // Update QoS DSCP rules if QoS is enabled
            let qos_enabled = db.get_config("qos_enabled")
                .ok().flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            if qos_enabled {
                let assigned = db.list_assigned_devices().unwrap_or_default();
                let devices: Vec<(String, String)> = assigned.iter()
                    .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                    .collect();
                let _ = crate::qos::apply_dscp_rules(&devices);
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
            if let Some(ref ip) = device.ipv4 {
                if let Err(e) = nftables::remove_device_forward_rule(ip) {
                    return Response::err(&format!("failed to remove forward rule: {}", e));
                }
                if let Err(e) = nftables::add_device_forward_rule(ip, "blocked") {
                    return Response::err(&format!("failed to add blocked rule: {}", e));
                }
            }
            if let Some(ref ipv6) = device.ipv6_ula {
                let _ = nftables::remove_device_forward_rule_v6(ipv6);
                let _ = nftables::add_device_forward_rule_v6(ipv6, "blocked");
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
            if let Some(ref ip) = device.ipv4 {
                if let Err(e) = nftables::remove_device_forward_rule(ip) {
                    return Response::err(&format!("failed to remove blocked rule: {}", e));
                }
                if let Err(e) = nftables::add_device_forward_rule(ip, "quarantine") {
                    return Response::err(&format!("failed to add forward rule: {}", e));
                }
            }
            if let Some(ref ipv6) = device.ipv6_ula {
                let _ = nftables::remove_device_forward_rule_v6(ipv6);
                let _ = nftables::add_device_forward_rule_v6(ipv6, "quarantine");
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
                    ipv4: info.device_ipv4.to_string(),
                    ipv6_ula: info.device_ipv6_ula.to_string(),
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
                        let ipv4 = info.device_ipv4.to_string();
                        let ipv6 = info.device_ipv6_ula.to_string();
                        let _ = crate::wireguard::add_peer(&peer.public_key, &ipv4, &ipv6);
                        let _ = nftables::add_device_counter(&ipv4);
                        let _ = nftables::add_device_counter_v6(&ipv6);
                        let _ = nftables::add_device_forward_rule(&ipv4, &peer.device_group);
                        let _ = nftables::add_device_forward_rule_v6(&ipv6, &peer.device_group);
                    }
                }
                if let Err(e) = db.set_config("wg_enabled", "true") {
                    return Response::err(&format!("failed to save config: {}", e));
                }
            } else {
                let peers = db.list_wg_peers().unwrap_or_default();
                for peer in &peers {
                    if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                        let ipv4 = info.device_ipv4.to_string();
                        let ipv6 = info.device_ipv6_ula.to_string();
                        let _ = nftables::remove_device_forward_rule(&ipv4);
                        let _ = nftables::remove_device_forward_rule_v6(&ipv6);
                        let _ = crate::wireguard::remove_peer(&peer.public_key, &ipv4, &ipv6);
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
            let ipv4 = info.device_ipv4.to_string();
            let ipv6 = info.device_ipv6_ula.to_string();
            if let Err(e) = crate::wireguard::add_peer(&public_key, &ipv4, &ipv6) {
                return Response::err(&format!("failed to add peer: {}", e));
            }
            if let Err(e) = nftables::add_device_counter(&ipv4) {
                return Response::err(&format!("failed to add counter: {}", e));
            }
            let _ = nftables::add_device_counter_v6(&ipv6);
            if let Err(e) = nftables::add_device_forward_rule(&ipv4, group) {
                return Response::err(&format!("failed to add forward rule: {}", e));
            }
            let _ = nftables::add_device_forward_rule_v6(&ipv6, group);
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
            resp.device_ipv4 = Some(ipv4);
            resp.device_ipv6_ula = Some(ipv6);
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
                let ipv4 = info.device_ipv4.to_string();
                let ipv6 = info.device_ipv6_ula.to_string();
                let _ = nftables::remove_device_forward_rule(&ipv4);
                let _ = nftables::remove_device_forward_rule_v6(&ipv6);
                let _ = crate::wireguard::remove_peer(&public_key, &ipv4, &ipv6);
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
            let ipv4 = info.device_ipv4.to_string();
            let ipv6 = info.device_ipv6_ula.to_string();
            if let Err(e) = nftables::remove_device_forward_rule(&ipv4) {
                return Response::err(&format!("failed to remove old rule: {}", e));
            }
            let _ = nftables::remove_device_forward_rule_v6(&ipv6);
            if let Err(e) = db.set_wg_peer_group(&public_key, &group) {
                return Response::err(&format!("failed to update group: {}", e));
            }
            if let Err(e) = nftables::add_device_forward_rule(&ipv4, &group) {
                return Response::err(&format!("failed to add new rule: {}", e));
            }
            let _ = nftables::add_device_forward_rule_v6(&ipv6, &group);
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
            if is_blocked_config_key(&key) {
                warn!(key = %key, "blocked config key read attempt");
                return Response::err("access denied");
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
            if is_blocked_config_key(&key) {
                warn!(key = %key, "blocked config key write attempt");
                return Response::err("access denied");
            }
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
        "export_config" => {
            let db = db.lock().unwrap();
            let devices = db.list_devices().unwrap_or_default();
            let reservations = db.list_dhcp_reservations().unwrap_or_default();
            let forwards = db.list_port_forwards().unwrap_or_default();
            let peers = db.list_wg_peers().unwrap_or_default();
            let pinholes = db.list_ipv6_pinholes().unwrap_or_default();

            let config_keys = ["ad_blocking_enabled", "wg_listen_port", "dmz_host_ip", "log_format", "syslog_target", "webhook_url", "log_retention_days", "runzero_url", "runzero_sync_interval", "runzero_enabled", "qos_enabled", "qos_upload_mbps", "qos_download_mbps", "qos_test_url"];
            let mut config_map = serde_json::Map::new();
            for key in &config_keys {
                if let Ok(Some(val)) = db.get_config(key) {
                    config_map.insert(key.to_string(), serde_json::Value::String(val));
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

            let export = serde_json::json!({
                "version": 1,
                "exported_at": now,
                "devices": devices.iter().map(|d| serde_json::json!({
                    "mac": d.mac, "hostname": d.hostname, "device_group": d.device_group, "subnet_id": d.subnet_id
                })).collect::<Vec<_>>(),
                "dhcp_reservations": reservations,
                "port_forwards": forwards,
                "wg_peers": peers.iter().map(|p| serde_json::json!({
                    "public_key": p.public_key, "name": p.name, "subnet_id": p.subnet_id, "device_group": p.device_group
                })).collect::<Vec<_>>(),
                "ipv6_pinholes": pinholes,
                "config": config_map,
            });

            let mut resp = Response::ok();
            resp.config_value = Some(export.to_string());
            resp
        }
        "import_config" => {
            let Some(data) = req.value else { return Response::err("value required (JSON config)"); };
            let parsed: serde_json::Value = match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
            };
            if parsed.get("version").and_then(|v| v.as_i64()) != Some(1) {
                return Response::err("unsupported config version");
            }

            let db = db.lock().unwrap();

            // Import devices (upsert groups and hostnames)
            if let Some(devices) = parsed.get("devices").and_then(|v| v.as_array()) {
                for dev in devices {
                    let mac = dev.get("mac").and_then(|v| v.as_str()).unwrap_or("");
                    let group = dev.get("device_group").and_then(|v| v.as_str()).unwrap_or("quarantine");
                    if !mac.is_empty() {
                        let _ = db.set_device_group(mac, group);
                        if let Some(hostname) = dev.get("hostname").and_then(|v| v.as_str()) {
                            let _ = db.set_device_hostname(mac, hostname);
                        }
                    }
                }
            }

            // Import DHCP reservations (replace all)
            let _ = db.conn_exec("DELETE FROM dhcp_reservations");
            if let Some(reservations) = parsed.get("dhcp_reservations").and_then(|v| v.as_array()) {
                for r in reservations {
                    let mac = r.get("mac").and_then(|v| v.as_str()).unwrap_or("");
                    let sid = r.get("subnet_id").and_then(|v| v.as_i64()).unwrap_or(-1);
                    if !mac.is_empty() && sid >= 0 {
                        let _ = db.set_dhcp_reservation(mac, sid);
                    }
                }
            }

            // Import port forwards (replace all)
            let _ = db.conn_exec("DELETE FROM port_forwards");
            if let Some(forwards) = parsed.get("port_forwards").and_then(|v| v.as_array()) {
                for f in forwards {
                    let protocol = f.get("protocol").and_then(|v| v.as_str()).unwrap_or("both");
                    let ext_start = f.get("external_port_start").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let ext_end = f.get("external_port_end").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let internal_ip = f.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("");
                    let int_port = f.get("internal_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    if ext_start > 0 && !internal_ip.is_empty() {
                        let _ = db.add_port_forward(protocol, ext_start, ext_end, internal_ip, int_port, desc);
                    }
                }
            }

            // Import IPv6 pinholes (replace all)
            let _ = db.conn_exec("DELETE FROM ipv6_pinholes");
            if let Some(pinholes) = parsed.get("ipv6_pinholes").and_then(|v| v.as_array()) {
                for p in pinholes {
                    let mac = p.get("device_mac").and_then(|v| v.as_str()).unwrap_or("");
                    let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
                    let port_start = p.get("port_start").and_then(|v| v.as_i64()).unwrap_or(0);
                    let port_end = p.get("port_end").and_then(|v| v.as_i64()).unwrap_or(0);
                    let desc = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    if !mac.is_empty() && !protocol.is_empty() && port_start > 0 {
                        let _ = db.add_ipv6_pinhole(mac, protocol, port_start, port_end, desc);
                    }
                }
            }

            // Import config (merge non-secret keys only)
            if let Some(config) = parsed.get("config").and_then(|v| v.as_object()) {
                for (key, val) in config {
                    match key.as_str() {
                        "ad_blocking_enabled" | "wg_listen_port" | "dmz_host_ip" | "log_format" | "syslog_target" | "webhook_url" | "log_retention_days" | "runzero_url" | "runzero_sync_interval" | "runzero_enabled" | "qos_enabled" | "qos_upload_mbps" | "qos_download_mbps" | "qos_test_url" => {
                            if let Some(v) = val.as_str() {
                                let _ = db.set_config(key, v);
                            }
                        }
                        _ => {} // skip unknown/secret keys
                    }
                }
            }

            // Reapply port forward rules
            let forwards = db.list_enabled_port_forwards().unwrap_or_default();
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };

            // Read QoS config before dropping the lock
            let qos_enabled = db.get_config("qos_enabled")
                .ok().flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            let qos_upload: u32 = db.get_config("qos_upload_mbps")
                .ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
            let qos_download: u32 = db.get_config("qos_download_mbps")
                .ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
            let qos_devices: Vec<(String, String)> = if qos_enabled {
                let assigned = db.list_assigned_devices().unwrap_or_default();
                assigned.iter()
                    .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                    .collect()
            } else {
                Vec::new()
            };

            drop(db);
            let _ = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref);

            // Apply QoS if enabled in imported config
            if qos_enabled {
                if qos_upload > 0 && qos_download > 0 {
                    let _ = crate::qos::enable(wan_iface, qos_upload, qos_download);
                    let _ = crate::qos::apply_dscp_rules(&qos_devices);
                }
            } else {
                let _ = crate::qos::disable(wan_iface);
                let _ = crate::qos::remove_dscp_rules();
            }

            Response::ok()
        }
        "backup_database" => {
            let db = db.lock().unwrap();
            let backup_path = "/data/hermitshell/hermitshell-backup.db";
            let _ = std::fs::remove_file(backup_path);
            match db.vacuum_into(backup_path) {
                Ok(()) => {
                    let mut resp = Response::ok();
                    resp.config_value = Some(backup_path.to_string());
                    resp
                }
                Err(e) => Response::err(&format!("backup failed: {}", e)),
            }
        }
        "list_connection_logs" => {
            let limit = req.limit.unwrap_or(100).min(1000);
            let offset = req.offset.unwrap_or(0);
            let device_ip = req.internal_ip.as_deref();
            let db = db.lock().unwrap();
            match db.list_connection_logs(device_ip, limit, offset) {
                Ok(logs) => {
                    let mut resp = Response::ok();
                    resp.connection_logs = Some(logs);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "list_dns_logs" => {
            let limit = req.limit.unwrap_or(100).min(1000);
            let offset = req.offset.unwrap_or(0);
            let device_ip = req.internal_ip.as_deref();
            let db = db.lock().unwrap();
            match db.list_dns_logs(device_ip, limit, offset) {
                Ok(logs) => {
                    let mut resp = Response::ok();
                    resp.dns_logs = Some(logs);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_log_config" => {
            let db = db.lock().unwrap();
            let config = serde_json::json!({
                "log_format": db.get_config("log_format").ok().flatten().unwrap_or_else(|| "text".to_string()),
                "syslog_target": db.get_config("syslog_target").ok().flatten().unwrap_or_default(),
                "webhook_url": db.get_config("webhook_url").ok().flatten().unwrap_or_default(),
                "log_retention_days": db.get_config("log_retention_days").ok().flatten().unwrap_or_else(|| "7".to_string()),
            });
            let mut resp = Response::ok();
            resp.log_config = Some(config);
            resp
        }
        "set_log_config" => {
            let Some(value) = req.value else {
                return Response::err("value required (JSON object)");
            };
            let parsed: serde_json::Value = match serde_json::from_str(&value) {
                Ok(v) => v,
                Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
            };
            let db = db.lock().unwrap();
            let allowed_keys = ["log_format", "syslog_target", "webhook_url", "webhook_secret", "log_retention_days"];
            if let Some(obj) = parsed.as_object() {
                for (key, val) in obj {
                    if allowed_keys.contains(&key.as_str()) {
                        if let Some(v) = val.as_str() {
                            let _ = db.set_config(key, v);
                        }
                    }
                }
            }
            Response::ok()
        }
        "add_ipv6_pinhole" => {
            let Some(mac) = req.mac else { return Response::err("mac required"); };
            let Some(protocol) = req.protocol else { return Response::err("protocol required"); };
            let Some(port_start) = req.port_start else { return Response::err("port_start required"); };
            let Some(port_end) = req.port_end else { return Response::err("port_end required"); };
            let desc = req.description.as_deref().unwrap_or("");
            match protocol.as_str() {
                "tcp" | "udp" => {}
                _ => return Response::err("protocol must be tcp or udp"),
            }
            if port_start == 0 || port_end == 0 {
                return Response::err("ports must be 1-65535");
            }
            if port_end < port_start {
                return Response::err("port_end must be >= port_start");
            }
            let db = db.lock().unwrap();
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            let Some(ref ipv6_global) = device.ipv6_global else {
                return Response::err("device has no global IPv6 address (no prefix delegation)");
            };
            if let Err(e) = nftables::add_ipv6_pinhole(ipv6_global, &protocol, port_start, port_end) {
                return Response::err(&format!("failed to add nftables rule: {}", e));
            }
            match db.add_ipv6_pinhole(&mac, &protocol, port_start as i64, port_end as i64, desc) {
                Ok(id) => {
                    let mut resp = Response::ok();
                    resp.config_value = Some(id.to_string());
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "remove_ipv6_pinhole" => {
            let Some(id) = req.id else { return Response::err("id required"); };
            let db = db.lock().unwrap();
            let pinhole = match db.get_ipv6_pinhole(id) {
                Ok(Some(p)) => p,
                Ok(None) => return Response::err("pinhole not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            let (mac, protocol, port_start, port_end) = pinhole;
            let device = match db.get_device(&mac) {
                Ok(Some(d)) => d,
                Ok(None) => return Response::err("device not found"),
                Err(e) => return Response::err(&e.to_string()),
            };
            if let Some(ref ipv6_global) = device.ipv6_global {
                if let Err(e) = nftables::remove_ipv6_pinhole(ipv6_global, &protocol, port_start as u16, port_end as u16) {
                    return Response::err(&format!("failed to remove nftables rule: {}", e));
                }
            }
            match db.remove_ipv6_pinhole(id) {
                Ok(true) => Response::ok(),
                Ok(false) => Response::err("pinhole not found"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "list_ipv6_pinholes" => {
            let db = db.lock().unwrap();
            match db.list_ipv6_pinholes() {
                Ok(pinholes) => {
                    let mut resp = Response::ok();
                    resp.ipv6_pinholes = Some(pinholes);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "has_password" => {
            let db = db.lock().unwrap();
            let has = db
                .get_config("admin_password_hash")
                .ok()
                .flatten()
                .is_some();
            let mut resp = Response::ok();
            resp.config_value = Some(if has { "true" } else { "false" }.to_string());
            resp
        }
        "verify_password" => {
            let Some(value) = req.value else {
                return Response::err("value required");
            };
            if value.len() > 128 {
                return Response::err("password too long");
            }
            if let Some(msg) = check_login_rate_limit(login_rate_limit) {
                warn!("verify_password rate-limited");
                return Response::err(&msg);
            }
            let db = db.lock().unwrap();
            let hash_str = match db.get_config("admin_password_hash").ok().flatten() {
                Some(h) => h,
                None => {
                    warn!("password verification failed");
                    record_login_failure(login_rate_limit);
                    let mut resp = Response::ok();
                    resp.config_value = Some("false".to_string());
                    return resp;
                }
            };
            let parsed_hash = match PasswordHash::new(&hash_str) {
                Ok(h) => h,
                Err(_) => {
                    warn!("password verification failed");
                    record_login_failure(login_rate_limit);
                    let mut resp = Response::ok();
                    resp.config_value = Some("false".to_string());
                    return resp;
                }
            };
            let valid = Argon2::default()
                .verify_password(value.as_bytes(), &parsed_hash)
                .is_ok();
            if !valid {
                warn!("password verification failed");
                record_login_failure(login_rate_limit);
            } else {
                reset_login_rate_limit(login_rate_limit);
            }
            let mut resp = Response::ok();
            resp.config_value = Some(if valid { "true" } else { "false" }.to_string());
            resp
        }
        "setup_password" => {
            let Some(value) = req.value else {
                return Response::err("value required");
            };
            if value.len() < 8 {
                return Response::err("password too short (minimum 8 characters)");
            }
            if value.len() > 128 {
                return Response::err("password too long (maximum 128 characters)");
            }
            let db = db.lock().unwrap();
            let existing_hash = db.get_config("admin_password_hash").ok().flatten();
            if let Some(ref hash_str) = existing_hash {
                // Current password required to change
                let Some(current) = req.key else {
                    return Response::err("key required (current password)");
                };
                if let Some(msg) = check_login_rate_limit(login_rate_limit) {
                    warn!("setup_password rate-limited");
                    return Response::err(&msg);
                }
                let parsed_hash = match PasswordHash::new(hash_str) {
                    Ok(h) => h,
                    Err(_) => return Response::err("stored hash corrupt"),
                };
                if Argon2::default()
                    .verify_password(current.as_bytes(), &parsed_hash)
                    .is_err()
                {
                    warn!("setup_password rejected: wrong current password");
                    record_login_failure(login_rate_limit);
                    return Response::err("wrong current password");
                }
                reset_login_rate_limit(login_rate_limit);
            }
            let salt = SaltString::generate(&mut rand::rngs::OsRng);
            let new_hash = match Argon2::default().hash_password(value.as_bytes(), &salt) {
                Ok(h) => h.to_string(),
                Err(e) => return Response::err(&format!("hashing failed: {}", e)),
            };
            match db.set_config("admin_password_hash", &new_hash) {
                Ok(()) => Response::ok(),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "create_session" => {
            let db = db.lock().unwrap();
            let secret = match db.get_config("session_secret").ok().flatten() {
                Some(s) => s,
                None => {
                    let s = hex::encode(rand::Rng::r#gen::<[u8; 32]>(&mut rand::thread_rng()));
                    if let Err(e) = db.set_config("session_secret", &s) {
                        return Response::err(&format!("failed to store secret: {}", e));
                    }
                    s
                }
            };
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let payload = format!("admin:{}:{}", timestamp, timestamp);
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(payload.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            let cookie = format!("{}.{}", payload, sig);
            let mut resp = Response::ok();
            resp.config_value = Some(cookie);
            resp
        }
        "verify_session" => {
            let Some(value) = req.value else {
                return Response::err("value required");
            };
            let db = db.lock().unwrap();
            let secret = match db.get_config("session_secret").ok().flatten() {
                Some(s) => s,
                None => {
                    let mut resp = Response::ok();
                    resp.config_value = Some("false".to_string());
                    return resp;
                }
            };
            // Cookie format: "admin:TIMESTAMP.SIGNATURE"
            let valid = if let Some(dot_pos) = value.rfind('.') {
                let payload = &value[..dot_pos];
                let sig = &value[dot_pos + 1..];
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(payload.as_bytes());
                let expected = hex::encode(mac.finalize().into_bytes());
                sig == expected
            } else {
                false
            };
            let mut resp = Response::ok();
            resp.config_value = Some(if valid { "true" } else { "false" }.to_string());
            resp
        }
        "get_tls_config" => {
            let db = db.lock().unwrap();
            let cert = db.get_config("tls_cert_pem").ok().flatten();
            let key = db.get_config("tls_key_pem").ok().flatten();
            match (cert, key) {
                (Some(c), Some(k)) => {
                    let mut resp = Response::ok();
                    resp.tls_cert_pem = Some(c);
                    resp.tls_key_pem = Some(k);
                    resp
                }
                _ => Response::err("TLS not yet configured"),
            }
        }
        "get_runzero_config" => {
            let db = db.lock().unwrap();
            let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
            let sync_interval = db.get_config("runzero_sync_interval").ok().flatten().unwrap_or_else(|| "3600".to_string());
            let enabled = db.get_config("runzero_enabled").ok().flatten().map(|v| v == "true").unwrap_or(false);
            let has_token = db.get_config("runzero_token").ok().flatten().map(|t| !t.is_empty()).unwrap_or(false);
            let mut resp = Response::ok();
            resp.runzero_config = Some(serde_json::json!({
                "runzero_url": url,
                "runzero_sync_interval": sync_interval,
                "enabled": enabled,
                "has_token": has_token,
            }));
            resp
        }
        "set_runzero_config" => {
            let Some(value) = req.value else {
                return Response::err("value required (JSON object)");
            };
            let parsed: serde_json::Value = match serde_json::from_str(&value) {
                Ok(v) => v,
                Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
            };
            let db = db.lock().unwrap();
            if let Some(url) = parsed.get("runzero_url").and_then(|v| v.as_str()) {
                if !url.is_empty() && !url.starts_with("https://") {
                    return Response::err("runzero_url must start with https://");
                }
                let _ = db.set_config("runzero_url", url);
            }
            if let Some(token) = parsed.get("runzero_token").and_then(|v| v.as_str()) {
                let _ = db.set_config("runzero_token", token);
            }
            if let Some(interval_str) = parsed.get("runzero_sync_interval").and_then(|v| v.as_str()) {
                if let Ok(secs) = interval_str.parse::<u64>() {
                    if secs >= 60 {
                        let _ = db.set_config("runzero_sync_interval", interval_str);
                    } else {
                        return Response::err("sync interval must be >= 60 seconds");
                    }
                }
            }
            if let Some(enabled) = parsed.get("runzero_enabled").and_then(|v| v.as_str()) {
                let _ = db.set_config("runzero_enabled", enabled);
            }
            Response::ok()
        }
        "sync_runzero" => {
            let (url, token) = {
                let db = db.lock().unwrap();
                let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
                let token = db.get_config("runzero_token").ok().flatten().unwrap_or_default();
                (url, token)
            };
            if url.is_empty() || token.is_empty() {
                return Response::err("runzero_url and runzero_token must be configured");
            }
            let db_clone = db.clone();
            tokio::task::spawn(async move {
                match crate::runzero::sync_once(&db_clone, &url, &token).await {
                    Ok(n) => info!(matched = n, "manual runZero sync complete"),
                    Err(e) => warn!(error = %e, "manual runZero sync failed"),
                }
            });
            let mut resp = Response::ok();
            resp.config_value = Some("sync started".to_string());
            resp
        }
        "list_alerts" => {
            let limit = req.limit.unwrap_or(100).min(1000);
            let offset = req.offset.unwrap_or(0);
            let device_mac = req.mac.as_deref();
            let rule = req.rule.as_deref();
            let severity = req.severity.as_deref();
            let acknowledged = req.acknowledged;
            let db = db.lock().unwrap();
            match db.list_alerts(device_mac, rule, severity, acknowledged, limit, offset) {
                Ok(alerts) => {
                    let mut resp = Response::ok();
                    resp.alerts = Some(alerts);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_alert" => {
            let id = match req.id {
                Some(id) => id,
                None => return Response::err("id required"),
            };
            let db = db.lock().unwrap();
            match db.get_alert(id) {
                Ok(Some(alert)) => {
                    let mut resp = Response::ok();
                    resp.alert = Some(alert);
                    resp
                }
                Ok(None) => Response::err("alert not found"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "acknowledge_alert" => {
            let id = match req.id {
                Some(id) => id,
                None => return Response::err("id required"),
            };
            let db = db.lock().unwrap();
            match db.acknowledge_alert(id) {
                Ok(true) => Response::ok(),
                Ok(false) => Response::err("alert not found"),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "acknowledge_all_alerts" => {
            let db = db.lock().unwrap();
            match db.acknowledge_all_alerts(req.mac.as_deref()) {
                Ok(count) => {
                    let mut resp = Response::ok();
                    resp.config_value = Some(count.to_string());
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "get_analyzer_status" => {
            let db = db.lock().unwrap();
            let enabled = db.get_config("analyzer_enabled")
                .ok().flatten().unwrap_or_else(|| "true".to_string());
            let rules = ["dns_beaconing", "dns_volume_spike", "new_dest_spike", "suspicious_ports", "bandwidth_spike"];
            let rule_status: serde_json::Value = rules.iter().map(|r| {
                let key = format!("alert_rule_{r}");
                let val = db.get_config(&key).ok().flatten().unwrap_or_else(|| "enabled".to_string());
                (r.to_string(), serde_json::Value::String(val))
            }).collect::<serde_json::Map<String, serde_json::Value>>().into();

            let (high, medium, low) = db.alert_counts_by_severity().unwrap_or((0, 0, 0));

            let status = serde_json::json!({
                "enabled": enabled,
                "rules": rule_status,
                "unacknowledged_alerts": {
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
            });
            let mut resp = Response::ok();
            resp.analyzer_status = Some(status);
            resp
        }
        "get_qos_config" => {
            let db = db.lock().unwrap();
            let enabled = db.get_config("qos_enabled")
                .ok().flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            let upload = db.get_config("qos_upload_mbps").ok().flatten().unwrap_or_default();
            let download = db.get_config("qos_download_mbps").ok().flatten().unwrap_or_default();
            let test_url = db.get_config("qos_test_url").ok().flatten().unwrap_or_default();
            let mut resp = Response::ok();
            resp.qos_config = Some(serde_json::json!({
                "enabled": enabled,
                "upload_mbps": upload,
                "download_mbps": download,
                "test_url": test_url,
            }));
            resp
        }
        "set_qos_config" => {
            let Some(enabled) = req.enabled else {
                return Response::err("enabled required");
            };
            let db = db.lock().unwrap();

            if enabled {
                let Some(upload) = req.upload_mbps else {
                    return Response::err("upload_mbps required when enabling");
                };
                let Some(download) = req.download_mbps else {
                    return Response::err("download_mbps required when enabling");
                };
                if let Err(e) = crate::qos::validate_bandwidth(upload) {
                    return Response::err(&e.to_string());
                }
                if let Err(e) = crate::qos::validate_bandwidth(download) {
                    return Response::err(&e.to_string());
                }

                let _ = db.set_config("qos_upload_mbps", &upload.to_string());
                let _ = db.set_config("qos_download_mbps", &download.to_string());
                let _ = db.set_config("qos_enabled", "true");

                if let Err(e) = crate::qos::enable(wan_iface, upload, download) {
                    return Response::err(&format!("failed to enable QoS: {}", e));
                }

                // Apply DSCP rules for all assigned devices
                let assigned = db.list_assigned_devices().unwrap_or_default();
                let devices: Vec<(String, String)> = assigned.iter()
                    .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                    .collect();
                if let Err(e) = crate::qos::apply_dscp_rules(&devices) {
                    return Response::err(&format!("failed to apply DSCP rules: {}", e));
                }
            } else {
                let _ = db.set_config("qos_enabled", "false");
                let _ = crate::qos::disable(wan_iface);
                let _ = crate::qos::remove_dscp_rules();
            }

            Response::ok()
        }
        "set_qos_test_url" => {
            let Some(url) = req.url else {
                return Response::err("url required");
            };
            match reqwest::Url::parse(&url) {
                Ok(parsed) => {
                    let scheme = parsed.scheme();
                    if scheme != "http" && scheme != "https" {
                        return Response::err("url must be http or https");
                    }
                    if let Some(host) = parsed.host_str() {
                        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
                            if !crate::qos::is_public_ip(&addr) {
                                return Response::err("url must not point to private/loopback address");
                            }
                        }
                    }
                }
                Err(_) => return Response::err("invalid url"),
            }
            let db = db.lock().unwrap();
            let _ = db.set_config("qos_test_url", &url);
            Response::ok()
        }
        "run_speed_test" => {
            let db = db.lock().unwrap();
            let url = match db.get_config("qos_test_url") {
                Ok(Some(u)) if !u.is_empty() => u,
                _ => return Response::err("no speed test URL configured; set it first via set_qos_test_url"),
            };
            drop(db);

            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(crate::qos::run_speed_test(&url))
            });
            match result {
                Ok(mbps) => {
                    let mut resp = Response::ok();
                    resp.qos_config = Some(serde_json::json!({
                        "download_mbps": mbps,
                    }));
                    resp
                }
                Err(e) => Response::err(&format!("speed test failed: {}", e)),
            }
        }
        "log_audit" => {
            let Some(ref action) = req.value else {
                return Response::err("value required (action name)");
            };
            let detail = req.key.as_deref().unwrap_or("");
            let db = db.lock().unwrap();
            match db.log_audit(action, detail) {
                Ok(()) => Response::ok(),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "list_audit_logs" => {
            let limit = req.limit.unwrap_or(200).min(1000);
            let db = db.lock().unwrap();
            match db.list_audit_logs(limit) {
                Ok(entries) => {
                    let mut resp = Response::ok();
                    resp.audit_logs = Some(entries);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "set_device_nickname" => {
            let Some(ref mac) = req.mac else {
                return Response::err("mac required");
            };
            let nickname = req.nickname.as_deref().unwrap_or("");
            let db = db.lock().unwrap();
            match db.set_device_nickname(mac, nickname) {
                Ok(()) => Response::ok(),
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "ingest_dns_logs" => {
            crate::dns_log::ingest_once(db, log_tx);
            Response::ok()
        }
        "run_analysis" => {
            crate::analyzer::run_analysis_cycle(db, log_tx);
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
                    resp.device_ipv4 = Some(info.device_ipv4.to_string());
                    resp.device_ipv6_ula = Some(info.device_ipv6_ula.to_string());
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
                    let ipv4 = info.device_ipv4.to_string();
                    let ipv6 = info.device_ipv6_ula.to_string();
                    if let Err(e) = db.insert_new_device(&mac, sid, &ipv4, &ipv6) {
                        return Response::err(&e.to_string());
                    }
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ipv4 = Some(ipv4);
                    resp.device_ipv6_ula = Some(ipv6);
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

            let ipv4 = info.device_ipv4.to_string();
            let ipv6 = info.device_ipv6_ula.to_string();

            info!(mac = %mac, ipv4 = %ipv4, ipv6 = %ipv6, "DHCP provision");

            if let Err(e) = nftables::add_device_route(&ipv4, lan_iface) {
                error!(ip = %ipv4, error = %e, "failed to add device route");
            }
            if let Err(e) = nftables::add_device_route_v6(&ipv6, lan_iface) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 route");
            }
            if let Err(e) = nftables::add_device_counter(&ipv4) {
                error!(ip = %ipv4, error = %e, "failed to add device counter");
            }
            let _ = nftables::add_device_counter_v6(&ipv6);
            if let Err(e) = nftables::add_device_forward_rule(&ipv4, "quarantine") {
                error!(ip = %ipv4, error = %e, "failed to add forward rule");
            }
            let _ = nftables::add_device_forward_rule_v6(&ipv6, "quarantine");

            // Update QoS DSCP rules if QoS is enabled
            let qos_enabled = {
                let db = db.lock().unwrap();
                db.get_config("qos_enabled")
                    .ok().flatten()
                    .map(|v| v == "true")
                    .unwrap_or(false)
            };
            if qos_enabled {
                let db = db.lock().unwrap();
                let assigned = db.list_assigned_devices().unwrap_or_default();
                let devices: Vec<(String, String)> = assigned.iter()
                    .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                    .collect();
                let _ = crate::qos::apply_dscp_rules(&devices);
            }

            Response::ok()
        }
        "dhcp6_discover" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let db = db.lock().unwrap();

            match db.get_device(&mac) {
                Ok(Some(dev)) if dev.subnet_id.is_some() => {
                    let sid = dev.subnet_id.unwrap();
                    let Some(info) = subnet::compute_subnet(sid) else {
                        return Response::err("subnet_id out of range");
                    };
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ipv4 = Some(info.device_ipv4.to_string());
                    resp.device_ipv6_ula = Some(info.device_ipv6_ula.to_string());
                    resp.is_new = Some(false);
                    resp
                }
                Ok(_) => {
                    // Device not yet known -- allocate a new subnet_id
                    let sid = match db.allocate_subnet_id() {
                        Ok(s) => s,
                        Err(e) => return Response::err(&e.to_string()),
                    };
                    let Some(info) = subnet::compute_subnet(sid) else {
                        return Response::err("subnet address space exhausted");
                    };
                    let ipv4 = info.device_ipv4.to_string();
                    let ipv6 = info.device_ipv6_ula.to_string();
                    if let Err(e) = db.insert_new_device(&mac, sid, &ipv4, &ipv6) {
                        return Response::err(&e.to_string());
                    }
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ipv4 = Some(ipv4);
                    resp.device_ipv6_ula = Some(ipv6);
                    resp.is_new = Some(true);
                    resp
                }
                Err(e) => Response::err(&e.to_string()),
            }
        }
        "dhcp6_provision" => {
            let Some(mac) = req.mac else {
                return Response::err("mac required");
            };
            let Some(sid) = req.subnet_id else {
                return Response::err("subnet_id required");
            };
            let Some(info) = subnet::compute_subnet(sid) else {
                return Response::err("invalid subnet_id");
            };

            let ipv6 = info.device_ipv6_ula.to_string();

            info!(mac = %mac, ipv6 = %ipv6, "DHCPv6 provision");

            if let Err(e) = nftables::add_device_route_v6(&ipv6, lan_iface) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 route");
            }
            if let Err(e) = nftables::add_device_counter_v6(&ipv6) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 counter");
            }
            if let Err(e) = nftables::add_device_forward_rule_v6(&ipv6, "quarantine") {
                error!(ip = %ipv6, error = %e, "failed to add v6 forward rule");
            }

            Response::ok()
        }
        _ => Response::err("unknown method"),
    }
}

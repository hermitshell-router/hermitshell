mod auth;
mod config;
mod devices;
mod logs;
mod network;
mod wireguard;
mod wifi;
mod setup;

use anyhow::Result;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::blocky::BlockyManager;
use crate::db::Db;
use crate::log_export::LogEvent;
use crate::nftables;
use hermitshell_common::{sanitize_hostname, subnet};

const BLOCKED_CONFIG_KEYS: &[&str] = &[
    "admin_password_hash",
    "session_secret",
    "wg_private_key",
    "tls_key_pem",
    "tls_cert_pem",
    "runzero_token",
    "runzero_ca_cert",
    "acme_cf_api_token",
    "acme_account_key",
    "webhook_secret",
    "update_latest_version",
    "update_installed_version",
];

fn is_blocked_config_key(key: &str) -> bool {
    BLOCKED_CONFIG_KEYS.contains(&key)
}

/// Groups assignable via the set_device_group API.
/// "blocked" is excluded -- use block_device/unblock_device instead.
const USER_ASSIGNABLE_GROUPS: &[&str] = &["quarantine", "trusted", "iot", "guest", "servers"];

const SESSION_IDLE_TIMEOUT_SECS: u64 = 1800;     // 30 minutes
const SESSION_ABSOLUTE_TIMEOUT_SECS: u64 = 28800; // 8 hours

/// Global login rate limit: (failure_count, last_failure_time).
/// Per-source rate limiting for HTTP clients is handled in the web UI middleware.
type LoginRateLimit = Arc<Mutex<(u32, Option<std::time::Instant>)>>;
type PasswordLock = Arc<Mutex<()>>;

/// Shared state for async speed test: (running, result_mbps, error)
pub type SpeedTestState = Arc<Mutex<(bool, Option<u32>, Option<String>)>>;

/// In-memory real-time bandwidth map: IP -> (prev_rx, prev_tx, curr_rx, curr_tx, poll_time)
pub type BandwidthRealtimeMap = Arc<Mutex<std::collections::HashMap<String, (i64, i64, i64, i64, std::time::Instant)>>>;

/// Check if login is currently rate-limited. Returns error message if blocked.
fn check_login_rate_limit(rate_limit: &LoginRateLimit) -> Option<String> {
    let state = rate_limit.lock().unwrap();
    let (failures, last) = &*state;
    if *failures == 0 {
        return None;
    }
    let last = match last {
        Some(t) => t,
        None => return None,
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

/// JSON request received over the Unix socket. The `method` field selects the handler.
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
    tls_cert_pem: Option<String>,
    tls_key_pem: Option<String>,
    ssid_name: Option<String>,
    band: Option<String>,
    hidden: Option<bool>,
    security: Option<String>,
    channel: Option<String>,
    channel_width: Option<String>,
    tx_power: Option<String>,
    include_secrets: Option<bool>,
    passphrase: Option<String>,
    ca_cert: Option<String>,
    period: Option<String>,
    device_mac: Option<String>,
    dhcp_fingerprint: Option<String>,
    provider_id: Option<String>,
    site: Option<String>,
    api_key: Option<String>,
}

/// JSON response envelope. `ok` indicates success; `error` carries failure details.
#[derive(Debug, Default, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_status: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_aps: Option<Vec<crate::db::WifiAp>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_providers: Option<Vec<hermitshell_common::WifiProviderInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_clients: Option<Vec<crate::db::WifiClient>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_ssids: Option<Vec<hermitshell_common::WifiSsidConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_radios: Option<Vec<hermitshell_common::WifiRadioConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interfaces: Option<Vec<hermitshell_common::NetworkInterface>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth_history: Option<Vec<crate::db::BandwidthPoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth_realtime: Option<Vec<crate::db::BandwidthRealtime>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_destinations: Option<Vec<crate::db::TopDestination>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mdns_services: Option<Vec<hermitshell_common::MdnsService>>,
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
        Self { ok: true, ..Default::default() }
    }
    fn err(msg: &str) -> Self {
        Self { error: Some(msg.to_string()), ..Default::default() }
    }
}

/// Start the main Unix socket API server that handles all agent commands.
pub async fn run_server(socket_path: &str, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String, log_tx: tokio::sync::mpsc::UnboundedSender<LogEvent>, bandwidth_rt: BandwidthRealtimeMap, speed_test_state: SpeedTestState, mdns_registry: crate::mdns::SharedRegistry, portmap: crate::portmap::SharedRegistry) -> Result<()> {
    // Remove stale socket from previous run (ignore: may not exist)
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
    info!(path = socket_path, "socket server listening");
    let login_rate_limit: LoginRateLimit = Arc::new(Mutex::new((0, None)));
    let password_lock: PasswordLock = Arc::new(Mutex::new(()));
    let conn_limit = Arc::new(Semaphore::new(100));
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("connection limit reached, rejecting client");
                let mut s = stream;
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut s,
                    b"{\"ok\":false,\"error\":\"too many connections\"}\n",
                ).await;
                continue;
            }
        };
        let db = db.clone();
        let start = start_time;
        let blocky = blocky.clone();
        let wan = wan_iface.clone();
        let lan = lan_iface.clone();
        let ltx = log_tx.clone();
        let lrl = login_rate_limit.clone();
        let pwl = password_lock.clone();
        let brt = bandwidth_rt.clone();
        let sts = speed_test_state.clone();
        let mreg = mdns_registry.clone();
        let pm = portmap.clone();
        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            if let Err(e) = handle_client(stream, db, start, blocky, wan, lan, ltx, lrl, pwl, brt, sts, mreg, pm).await {
                warn!(error = %e, "client error");
            }
        });
    }
}

async fn handle_client(stream: UnixStream, db: Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: Arc<Mutex<BlockyManager>>, wan_iface: String, lan_iface: String, log_tx: tokio::sync::mpsc::UnboundedSender<LogEvent>, login_rate_limit: LoginRateLimit, password_lock: PasswordLock, bandwidth_rt: BandwidthRealtimeMap, speed_test_state: SpeedTestState, mdns_registry: crate::mdns::SharedRegistry, portmap: crate::portmap::SharedRegistry) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        if line.len() > 65_536 {
            warn!("request exceeds 64KB limit, closing connection");
            return Ok(());
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                if let Some(ref mac) = req.mac {
                    if let Err(e) = nftables::validate_mac(mac) {
                        Response::err(&e.to_string())
                    } else {
                        match req.method.as_str() {
                            "wifi_get_ssids" | "wifi_set_ssid" | "wifi_delete_ssid"
                            | "wifi_get_radios" | "wifi_set_radio" => {
                                wifi::handle_wifi_async(&req, &db).await
                            }
                            "apply_update" => {
                                config::handle_apply_update(&req, &db).await
                            }
                            _ => handle_request(req, &db, start_time, &blocky, &wan_iface, &lan_iface, &log_tx, &login_rate_limit, &password_lock, &bandwidth_rt, &speed_test_state, &mdns_registry, &portmap),
                        }
                    }
                } else {
                    match req.method.as_str() {
                        "wifi_get_ssids" | "wifi_set_ssid" | "wifi_delete_ssid"
                        | "wifi_get_radios" | "wifi_set_radio" => {
                            wifi::handle_wifi_async(&req, &db).await
                        }
                        "apply_update" => {
                            config::handle_apply_update(&req, &db).await
                        }
                        _ => handle_request(req, &db, start_time, &blocky, &wan_iface, &lan_iface, &log_tx, &login_rate_limit, &password_lock, &bandwidth_rt, &speed_test_state, &mdns_registry, &portmap),
                    }
                }
            }
            Err(e) => Response::err(&format!("Invalid JSON: {}", e)),
        };
        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        line.clear();
    }
    Ok(())
}

fn handle_request(req: Request, db: &Arc<Mutex<Db>>, start_time: std::time::Instant, blocky: &Arc<Mutex<BlockyManager>>, wan_iface: &str, lan_iface: &str, log_tx: &tokio::sync::mpsc::UnboundedSender<LogEvent>, login_rate_limit: &LoginRateLimit, password_lock: &PasswordLock, bandwidth_rt: &BandwidthRealtimeMap, speed_test_state: &SpeedTestState, mdns_registry: &crate::mdns::SharedRegistry, portmap: &crate::portmap::SharedRegistry) -> Response {
    if let Some(ref mac) = req.mac {
        if let Err(e) = nftables::validate_mac(mac) {
            return Response::err(&e.to_string());
        }
    }
    match req.method.as_str() {
        "list_devices" => devices::handle_list_devices(&req, db),
        "get_device" => devices::handle_get_device(&req, db),
        "get_status" => devices::handle_get_status(&req, db, start_time),
        "set_device_group" => devices::handle_set_device_group(&req, db),
        "block_device" => devices::handle_block_device(&req, db),
        "unblock_device" => devices::handle_unblock_device(&req, db),
        "set_device_nickname" => devices::handle_set_device_nickname(&req, db),
        "list_dhcp_reservations" => devices::handle_list_dhcp_reservations(&req, db),
        "set_dhcp_reservation" => devices::handle_set_dhcp_reservation(&req, db),
        "remove_dhcp_reservation" => devices::handle_remove_dhcp_reservation(&req, db),
        "has_password" => auth::handle_has_password(&req, db),
        "verify_password" => auth::handle_verify_password(&req, db, login_rate_limit, password_lock),
        "setup_password" => auth::handle_setup_password(&req, db, login_rate_limit, password_lock),
        "create_session" => auth::handle_create_session(&req, db),
        "verify_session" => auth::handle_verify_session(&req, db),
        "refresh_session" => auth::handle_refresh_session(&req, db),
        "get_tls_config" => auth::handle_get_tls_config(&req, db),
        "get_tls_status" => auth::handle_get_tls_status(&req, db),
        "set_tls_cert" => auth::handle_set_tls_cert(&req, db),
        "set_tls_mode" => auth::handle_set_tls_mode(&req, db),
        "set_acme_config" => auth::handle_set_acme_config(&req, db),
        "get_wireguard" => wireguard::handle_get_wireguard(&req, db),
        "set_wireguard_enabled" => wireguard::handle_set_wireguard_enabled(&req, db),
        "add_wg_peer" => wireguard::handle_add_wg_peer(&req, db),
        "remove_wg_peer" => wireguard::handle_remove_wg_peer(&req, db),
        "set_wg_peer_group" => wireguard::handle_set_wg_peer_group(&req, db),
        "list_port_forwards" => network::handle_list_port_forwards(&req, db),
        "add_port_forward" => network::handle_add_port_forward(&req, db, portmap),
        "remove_port_forward" => network::handle_remove_port_forward(&req, db, portmap),
        "set_port_forward_enabled" => network::handle_set_port_forward_enabled(&req, db, portmap),
        "get_dmz" => network::handle_get_dmz(&req, db),
        "set_dmz" => network::handle_set_dmz(&req, db, portmap),
        "add_ipv6_pinhole" => network::handle_add_ipv6_pinhole(&req, db),
        "remove_ipv6_pinhole" => network::handle_remove_ipv6_pinhole(&req, db),
        "list_ipv6_pinholes" => network::handle_list_ipv6_pinholes(&req, db),
        "get_upnp_config" => network::handle_get_upnp_config(&req, db),
        "set_upnp_config" => network::handle_set_upnp_config(&req, db, portmap),
        "get_config" => config::handle_get_config(&req, db),
        "set_config" => config::handle_set_config(&req, db),
        "get_ad_blocking" => config::handle_get_ad_blocking(&req, db),
        "set_ad_blocking" => config::handle_set_ad_blocking(&req, db, blocky),
        "export_config" => config::handle_export_config(&req, db),
        "import_config" => config::handle_import_config(&req, db, portmap),
        "backup_database" => config::handle_backup_database(&req, db),
        "get_log_config" => config::handle_get_log_config(&req, db),
        "set_log_config" => config::handle_set_log_config(&req, db),
        "get_runzero_config" => config::handle_get_runzero_config(&req, db),
        "set_runzero_config" => config::handle_set_runzero_config(&req, db),
        "sync_runzero" => config::handle_sync_runzero(&req, db),
        "get_analyzer_status" => config::handle_get_analyzer_status(&req, db),
        "get_qos_config" => config::handle_get_qos_config(&req, db),
        "set_qos_config" => config::handle_set_qos_config(&req, db, wan_iface),
        "set_qos_test_url" => config::handle_set_qos_test_url(&req, db),
        "run_speed_test" => config::handle_run_speed_test(&req, db, speed_test_state),
        "get_speed_test_result" => config::handle_get_speed_test_result(&req, speed_test_state),
        "list_connection_logs" => logs::handle_list_connection_logs(&req, db),
        "list_dns_logs" => logs::handle_list_dns_logs(&req, db),
        "list_alerts" => logs::handle_list_alerts(&req, db),
        "get_alert" => logs::handle_get_alert(&req, db),
        "acknowledge_alert" => logs::handle_acknowledge_alert(&req, db),
        "acknowledge_all_alerts" => logs::handle_acknowledge_all_alerts(&req, db),
        "log_audit" => logs::handle_log_audit(&req, db),
        "list_audit_logs" => logs::handle_list_audit_logs(&req, db),
        "ingest_dns_logs" => logs::handle_ingest_dns_logs(&req, db, log_tx),
        "run_analysis" => logs::handle_run_analysis(&req, db, log_tx),
        "wifi_list_aps" => wifi::handle_wifi_list_aps(&req, db),
        "wifi_list_providers" => wifi::handle_wifi_list_providers(&req, db),
        "wifi_add_provider" => wifi::handle_wifi_add_provider(&req, db),
        "wifi_remove_provider" => wifi::handle_wifi_remove_provider(&req, db),
        "wifi_set_provider_ca_cert" => wifi::handle_wifi_set_provider_ca_cert(&req, db),
        "wifi_get_clients" => wifi::handle_wifi_get_clients(&req, db),
        "check_update" => config::handle_check_update(&req, db),
        "setup_wan_config" => setup::handle_setup_wan_config(&req, db),
        "list_interfaces" => setup::handle_list_interfaces(&req, db),
        "set_interfaces" => setup::handle_set_interfaces(&req, db),
        "get_bandwidth_history" => logs::handle_get_bandwidth_history(&req, db),
        "get_bandwidth_realtime" => logs::handle_get_bandwidth_realtime(&req, db, bandwidth_rt),
        "get_top_destinations" => logs::handle_get_top_destinations(&req, db),
        "run_bandwidth_rollup" => logs::handle_run_bandwidth_rollup(&req, db),
        "list_mdns_services" => devices::handle_list_mdns_services(&req, db, mdns_registry),
        _ => Response::err("unknown method"),
    }
}

/// Start the DHCP IPC socket that the hermitshell-dhcp process uses to register devices.
pub async fn run_dhcp_socket(socket_path: &str, db: Arc<Mutex<Db>>, lan_iface: String) -> Result<()> {
    // Remove stale socket from previous run (ignore: may not exist)
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
    let conn_limit = Arc::new(Semaphore::new(100));
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!("DHCP IPC connection limit reached");
                continue;
            }
        };
        let db = db.clone();
        let lan_iface = lan_iface.clone();
        tokio::spawn(async move {
            let _permit = permit;
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
        if line.len() > 65_536 {
            warn!("request exceeds 64KB limit, closing connection");
            return Ok(());
        }
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
            // best-effort: hostname is informational, failure should not block DHCP
            if let Some(ref hostname) = req.hostname {
                let clean = sanitize_hostname(hostname);
                if !clean.is_empty() {
                    let _ = db.set_device_hostname(&mac, &clean);
                }
            }
            if let Some(ref fp) = req.dhcp_fingerprint {
                let _ = db.set_device_dhcp_fingerprint(&mac, fp);
            }
            let reserved_sid = db.get_dhcp_reservation(&mac).ok().flatten().map(|r| r.subnet_id);
            let (dev_base, dev_max) = nftables::device_range();
            match db.get_device(&mac) {
                Ok(Some(dev)) if dev.subnet_id.is_some() => {
                    let current_sid = dev.subnet_id.unwrap();
                    // If a reservation overrides the subnet_id, compute the new IP
                    let (sid, ipv4, ipv6) = if let Some(rsid) = reserved_sid {
                        if rsid != current_sid {
                            let Some(info) = subnet::compute_subnet(rsid, dev_base, dev_max) else {
                                return Response::err("reserved subnet_id out of range");
                            };
                            (rsid, info.device_ipv4.to_string(), info.device_ipv6_ula.to_string())
                        } else {
                            (current_sid, dev.ipv4.unwrap_or_default(), dev.ipv6_ula.unwrap_or_default())
                        }
                    } else {
                        (current_sid, dev.ipv4.unwrap_or_default(), dev.ipv6_ula.unwrap_or_default())
                    };
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ipv4 = Some(ipv4);
                    resp.device_ipv6_ula = Some(ipv6);
                    resp.is_new = Some(false);
                    resp
                }
                Ok(_) => {
                    let sid = match reserved_sid {
                        Some(sid) => sid,
                        None => match db.allocate_subnet_id(dev_max + 1) {
                            Ok(s) => s,
                            Err(e) => return Response::err(&e.to_string()),
                        },
                    };
                    let Some(info) = subnet::compute_subnet(sid, dev_base, dev_max) else {
                        return Response::err("subnet address space exhausted");
                    };
                    let ipv4 = info.device_ipv4.to_string();
                    let ipv6 = info.device_ipv6_ula.to_string();
                    if let Err(e) = db.insert_new_device(&mac, sid, &ipv4, &ipv6) {
                        return Response::err(&e.to_string());
                    }
                    // Auto-classify if enabled and device has runZero data
                    let auto_classify = db.get_config("auto_classify_devices")
                        .ok().flatten().map(|v| v == "true").unwrap_or(false);
                    if auto_classify {
                        if let Ok(Some(device)) = db.get_device(&mac) {
                            if device.device_group == "quarantine" {
                                if let Some(suggested) = devices::suggest_group(device.runzero_device_type.as_deref()) {
                                    let _ = db.set_device_group(&mac, suggested);
                                    let _ = nftables::remove_device_forward_rule(&ipv4);
                                    let _ = nftables::add_device_forward_rule(&ipv4, suggested);
                                }
                            }
                        }
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
            let (ipv4, ipv6) = {
                let db = db.lock().unwrap();
                match db.get_device(&mac) {
                    Ok(Some(dev)) => {
                        let ipv4 = match dev.ipv4 {
                            Some(ip) => ip,
                            None => return Response::err("device has no IPv4 address"),
                        };
                        let ipv6 = dev.ipv6_ula.unwrap_or_default();
                        (ipv4, ipv6)
                    }
                    Ok(None) => return Response::err("device not found"),
                    Err(e) => return Response::err(&e.to_string()),
                }
            };
            info!(mac = %mac, ipv4 = %ipv4, ipv6 = %ipv6, "DHCP provision");
            if let Err(e) = nftables::add_device_route(&ipv4, lan_iface, &mac) {
                error!(ip = %ipv4, error = %e, "failed to add device route");
            }
            if let Err(e) = nftables::add_device_route_v6(&ipv6, lan_iface, &mac) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 route");
            }
            if let Err(e) = nftables::add_device_counter(&ipv4) {
                error!(ip = %ipv4, error = %e, "failed to add device counter");
            }
            // best-effort: IPv6 mirrors IPv4 but is not fatal
            let _ = nftables::add_device_counter_v6(&ipv6);
            if let Err(e) = nftables::add_device_forward_rule(&ipv4, "quarantine") {
                error!(ip = %ipv4, error = %e, "failed to add forward rule");
            }
            // best-effort: IPv6 mirrors IPv4 but is not fatal
            let _ = nftables::add_device_forward_rule_v6(&ipv6, "quarantine");
            // Remove existing MAC-IP rules first to avoid duplicates on DHCP renewal
            let _ = nftables::remove_mac_ip_rule(&ipv4);
            let _ = nftables::remove_mac_ip_rule(&ipv6);
            let _ = nftables::add_mac_ip_rule(&ipv4, &mac);
            let _ = nftables::add_mac_ip_rule_v6(&ipv6, &mac);
            let qos_enabled = {
                let db = db.lock().unwrap();
                db.get_config_bool("qos_enabled", false)
            };
            if qos_enabled {
                let db = db.lock().unwrap();
                let assigned = db.list_assigned_devices().unwrap_or_default();
                let devices: Vec<(String, String)> = assigned.iter()
                    .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
                    .collect();
                // best-effort: QoS failure should not block DHCP provision
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
                    let mut resp = Response::ok();
                    resp.subnet_id = Some(sid);
                    resp.device_ipv4 = dev.ipv4;
                    resp.device_ipv6_ula = dev.ipv6_ula;
                    resp.is_new = Some(false);
                    resp
                }
                Ok(_) => {
                    let (dev_base, dev_max) = nftables::device_range();
                    let sid = match db.allocate_subnet_id(dev_max + 1) {
                        Ok(s) => s,
                        Err(e) => return Response::err(&e.to_string()),
                    };
                    let Some(info) = subnet::compute_subnet(sid, dev_base, dev_max) else {
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
            let ipv6 = {
                let db = db.lock().unwrap();
                match db.get_device(&mac) {
                    Ok(Some(dev)) => match dev.ipv6_ula {
                        Some(ip) => ip,
                        None => return Response::err("device has no IPv6 ULA address"),
                    },
                    Ok(None) => return Response::err("device not found"),
                    Err(e) => return Response::err(&e.to_string()),
                }
            };
            info!(mac = %mac, ipv6 = %ipv6, "DHCPv6 provision");
            if let Err(e) = nftables::add_device_route_v6(&ipv6, lan_iface, &mac) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 route");
            }
            if let Err(e) = nftables::add_device_counter_v6(&ipv6) {
                error!(ip = %ipv6, error = %e, "failed to add device v6 counter");
            }
            if let Err(e) = nftables::add_device_forward_rule_v6(&ipv6, "quarantine") {
                error!(ip = %ipv6, error = %e, "failed to add v6 forward rule");
            }
            let _ = nftables::remove_mac_ip_rule(&ipv6);
            let _ = nftables::add_mac_ip_rule_v6(&ipv6, &mac);
            Response::ok()
        }
        _ => Response::err("unknown method"),
    }
}

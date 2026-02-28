use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use crate::types::{Device, Status};
pub use hermitshell_common::{Alert, ConnectionLog, DnsLogEntry};

const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";

#[derive(Debug, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub devices: Option<Vec<Device>>,
    pub device: Option<Device>,
    pub status: Option<Status>,
    pub ad_blocking_enabled: Option<bool>,
    pub wireguard: Option<crate::types::WireguardInfo>,
    pub device_ip: Option<String>,
    pub port_forwards: Option<Vec<crate::types::PortForward>>,
    pub dmz_ip: Option<String>,
    pub dhcp_reservations: Option<Vec<crate::types::DhcpReservation>>,
    pub config_value: Option<String>,
    pub tls_cert_pem: Option<String>,
    pub tls_key_pem: Option<String>,
    pub connection_logs: Option<Vec<ConnectionLog>>,
    pub dns_logs: Option<Vec<DnsLogEntry>>,
    pub log_config: Option<serde_json::Value>,
    pub runzero_config: Option<serde_json::Value>,
    pub alerts: Option<Vec<Alert>>,
    pub alert: Option<Alert>,
    pub analyzer_status: Option<serde_json::Value>,
    #[serde(default)]
    pub qos_config: Option<serde_json::Value>,
    pub audit_logs: Option<Vec<crate::types::AuditEntry>>,
    pub tls_status: Option<serde_json::Value>,
    pub wifi_aps: Option<Vec<hermitshell_common::WifiAp>>,
    pub wifi_providers: Option<Vec<hermitshell_common::WifiProviderInfo>>,
    pub wifi_clients: Option<Vec<hermitshell_common::WifiClient>>,
    pub wifi_ssids: Option<Vec<hermitshell_common::WifiSsidConfig>>,
    pub wifi_radios: Option<Vec<hermitshell_common::WifiRadioConfig>>,
    pub interfaces: Option<Vec<hermitshell_common::NetworkInterface>>,
    pub update_info: Option<serde_json::Value>,
    pub bandwidth_history: Option<Vec<hermitshell_common::BandwidthPoint>>,
    pub bandwidth_realtime: Option<Vec<hermitshell_common::BandwidthRealtime>>,
    pub top_destinations: Option<Vec<hermitshell_common::TopDestination>>,
    pub mdns_services: Option<Vec<hermitshell_common::MdnsService>>,
}

fn send(request: serde_json::Value) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to agent: {e}"))?;

    let line = request.to_string();
    writeln!(stream, "{line}")
        .map_err(|e| format!("Failed to send request: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)
        .map_err(|e| format!("Failed to read response: {e}"))?;

    serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response: {e}"))
}

fn ok_or_err(resp: Response) -> Result<Response, String> {
    if resp.ok {
        Ok(resp)
    } else {
        Err(resp.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

pub fn list_devices() -> Result<Vec<Device>, String> {
    let resp = ok_or_err(send(json!({"method": "list_devices"}))?)?;
    Ok(resp.devices.unwrap_or_default())
}

pub fn get_status() -> Result<Status, String> {
    let resp = ok_or_err(send(json!({"method": "get_status"}))?)?;
    resp.status.ok_or_else(|| "No status in response".to_string())
}

pub fn set_device_group(mac: &str, group: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_device_group", "mac": mac, "group": group}))?)?;
    Ok(())
}

pub fn block_device(mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "block_device", "mac": mac}))?)?;
    Ok(())
}

pub fn unblock_device(mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "unblock_device", "mac": mac}))?)?;
    Ok(())
}

pub fn get_device(mac: &str) -> Result<Device, String> {
    let resp = ok_or_err(send(json!({"method": "get_device", "mac": mac}))?)?;
    resp.device.ok_or_else(|| "No device in response".to_string())
}

pub fn list_mdns_services(mac: &str) -> Result<Vec<hermitshell_common::MdnsService>, String> {
    let resp = ok_or_err(send(json!({"method": "list_mdns_services", "mac": mac}))?)?;
    Ok(resp.mdns_services.unwrap_or_default())
}

pub fn set_device_nickname(mac: &str, nickname: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_device_nickname", "mac": mac, "nickname": nickname}))?)?;
    Ok(())
}

pub fn get_ad_blocking() -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "get_ad_blocking"}))?)?;
    Ok(resp.ad_blocking_enabled.unwrap_or(true))
}

pub fn set_ad_blocking(enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_ad_blocking", "enabled": enabled}))?)?;
    Ok(())
}

pub fn get_upnp_enabled() -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "get_upnp_config"}))?)?;
    let config_str = resp.config_value.unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&config_str).unwrap_or_default();
    Ok(parsed.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
}

pub fn set_upnp_enabled(enabled: bool) -> Result<(), String> {
    let value = if enabled { "true" } else { "false" };
    ok_or_err(send(json!({"method": "set_upnp_config", "value": value}))?)?;
    Ok(())
}

pub fn get_wireguard() -> Result<crate::types::WireguardInfo, String> {
    let resp = ok_or_err(send(json!({"method": "get_wireguard"}))?)?;
    resp.wireguard.ok_or_else(|| "No wireguard info in response".to_string())
}

pub fn set_wireguard_enabled(enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_wireguard_enabled", "enabled": enabled}))?)?;
    Ok(())
}

pub fn add_wg_peer(name: &str, public_key: &str, group: &str) -> Result<Response, String> {
    ok_or_err(send(json!({"method": "add_wg_peer", "name": name, "public_key": public_key, "group": group}))?)
}

pub fn remove_wg_peer(public_key: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "remove_wg_peer", "public_key": public_key}))?)?;
    Ok(())
}

pub fn get_config(key: &str) -> Result<Option<String>, String> {
    let resp = ok_or_err(send(json!({"method": "get_config", "key": key}))?)?;
    Ok(resp.config_value)
}

pub fn set_config(key: &str, value: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_config", "key": key, "value": value}))?)?;
    Ok(())
}

pub fn verify_password(password: &str) -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "verify_password", "value": password}))?)?;
    Ok(resp.config_value.as_deref() == Some("true"))
}

pub fn setup_password(new_password: &str, current_password: Option<&str>) -> Result<(), String> {
    let mut req = json!({"method": "setup_password", "value": new_password});
    if let Some(current) = current_password {
        req["key"] = serde_json::Value::String(current.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn has_password() -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "has_password"}))?)?;
    Ok(resp.config_value.as_deref() == Some("true"))
}

pub fn create_session() -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "create_session"}))?)?;
    resp.config_value.ok_or_else(|| "no cookie in response".to_string())
}

pub fn verify_session(cookie: &str) -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "verify_session", "value": cookie}))?)?;
    Ok(resp.config_value.as_deref() == Some("true"))
}

pub fn refresh_session(cookie: &str) -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "refresh_session", "value": cookie}))?)?;
    resp.config_value.ok_or_else(|| "no cookie in response".to_string())
}

pub fn get_tls_config() -> Result<(String, String), String> {
    let resp = ok_or_err(send(json!({"method": "get_tls_config"}))?)?;
    let cert = resp.tls_cert_pem.ok_or("no cert in response")?;
    let key = resp.tls_key_pem.ok_or("no key in response")?;
    Ok((cert, key))
}

pub fn list_port_forwards() -> Result<crate::types::PortForwardsInfo, String> {
    let resp = ok_or_err(send(json!({"method": "list_port_forwards"}))?)?;
    Ok(crate::types::PortForwardsInfo {
        port_forwards: resp.port_forwards.unwrap_or_default(),
        dmz_ip: resp.dmz_ip.unwrap_or_default(),
    })
}

pub fn add_port_forward(protocol: &str, ext_start: u16, ext_end: u16, internal_ip: &str, internal_port: u16, description: &str) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "add_port_forward",
        "protocol": protocol,
        "external_port_start": ext_start,
        "external_port_end": ext_end,
        "internal_ip": internal_ip,
        "internal_port": internal_port,
        "description": description,
    }))?)?;
    Ok(())
}

pub fn remove_port_forward(id: i64) -> Result<(), String> {
    ok_or_err(send(json!({"method": "remove_port_forward", "id": id}))?)?;
    Ok(())
}

pub fn list_dhcp_reservations() -> Result<Vec<crate::types::DhcpReservation>, String> {
    let resp = ok_or_err(send(json!({"method": "list_dhcp_reservations"}))?)?;
    Ok(resp.dhcp_reservations.unwrap_or_default())
}

pub fn set_dhcp_reservation(mac: &str, subnet_id: Option<i64>) -> Result<(), String> {
    let mut req = json!({"method": "set_dhcp_reservation", "mac": mac});
    if let Some(sid) = subnet_id {
        req["subnet_id"] = serde_json::Value::Number(sid.into());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn remove_dhcp_reservation(mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "remove_dhcp_reservation", "mac": mac}))?)?;
    Ok(())
}

pub fn export_config() -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "export_config"}))?)?;
    resp.config_value.ok_or_else(|| "No config data".to_string())
}

pub fn import_config(data: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "import_config", "value": data}))?)?;
    Ok(())
}

pub fn export_config_v2(include_secrets: bool, passphrase: Option<&str>) -> Result<String, String> {
    let mut req = json!({"method": "export_config"});
    if include_secrets {
        req["include_secrets"] = serde_json::Value::Bool(true);
    }
    if let Some(p) = passphrase {
        req["passphrase"] = serde_json::Value::String(p.to_string());
    }
    let resp = ok_or_err(send(req)?)?;
    resp.config_value.ok_or_else(|| "No config data".to_string())
}

pub fn import_config_v2(data: &str, passphrase: Option<&str>) -> Result<(), String> {
    let mut req = json!({"method": "import_config", "value": data});
    if let Some(p) = passphrase {
        req["passphrase"] = serde_json::Value::String(p.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn list_connection_logs(device_ip: Option<&str>, limit: i64) -> Result<Vec<ConnectionLog>, String> {
    let mut req = json!({"method": "list_connection_logs", "limit": limit});
    if let Some(ip) = device_ip {
        req["internal_ip"] = serde_json::Value::String(ip.to_string());
    }
    let resp = ok_or_err(send(req)?)?;
    Ok(resp.connection_logs.unwrap_or_default())
}

pub fn list_dns_logs(device_ip: Option<&str>, limit: i64) -> Result<Vec<DnsLogEntry>, String> {
    let mut req = json!({"method": "list_dns_logs", "limit": limit});
    if let Some(ip) = device_ip {
        req["internal_ip"] = serde_json::Value::String(ip.to_string());
    }
    let resp = ok_or_err(send(req)?)?;
    Ok(resp.dns_logs.unwrap_or_default())
}

pub fn get_log_config() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_log_config"}))?)?;
    resp.log_config.ok_or_else(|| "no log config".to_string())
}

pub fn set_log_config(config: &serde_json::Value) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_log_config", "value": config.to_string()}))?)?;
    Ok(())
}

pub fn get_runzero_config() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_runzero_config"}))?)?;
    resp.runzero_config.ok_or_else(|| "no runzero config".to_string())
}

pub fn set_runzero_config(config: &serde_json::Value) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_runzero_config", "value": config.to_string()}))?)?;
    Ok(())
}

pub fn sync_runzero() -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "sync_runzero"}))?)?;
    Ok(resp.config_value.unwrap_or_else(|| "sync started".to_string()))
}

pub fn list_alerts(device_mac: Option<&str>, limit: i64) -> Result<Vec<Alert>, String> {
    let mut req = json!({"method": "list_alerts", "limit": limit});
    if let Some(mac) = device_mac {
        req["mac"] = serde_json::Value::String(mac.to_string());
    }
    let resp = ok_or_err(send(req)?)?;
    Ok(resp.alerts.unwrap_or_default())
}

pub fn get_alert(id: i64) -> Result<Alert, String> {
    let resp = ok_or_err(send(json!({"method": "get_alert", "id": id}))?)?;
    resp.alert.ok_or_else(|| "No alert in response".to_string())
}

pub fn acknowledge_alert(id: i64) -> Result<(), String> {
    ok_or_err(send(json!({"method": "acknowledge_alert", "id": id}))?)?;
    Ok(())
}

pub fn acknowledge_all_alerts(device_mac: Option<&str>) -> Result<(), String> {
    let mut req = json!({"method": "acknowledge_all_alerts"});
    if let Some(mac) = device_mac {
        req["mac"] = serde_json::Value::String(mac.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn get_analyzer_status() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_analyzer_status"}))?)?;
    resp.analyzer_status.ok_or_else(|| "no analyzer status".to_string())
}

pub fn get_qos_config() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_qos_config"}))?)?;
    Ok(resp.qos_config.unwrap_or(json!({})))
}

pub fn set_qos_config(enabled: bool, upload_mbps: Option<u32>, download_mbps: Option<u32>) -> Result<(), String> {
    let mut req = json!({"method": "set_qos_config", "enabled": enabled});
    if let Some(up) = upload_mbps {
        req["upload_mbps"] = json!(up);
    }
    if let Some(down) = download_mbps {
        req["download_mbps"] = json!(down);
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn set_qos_test_url(url: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_qos_test_url", "url": url}))?)?;
    Ok(())
}

pub fn run_speed_test() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "run_speed_test"}))?)?;
    Ok(resp.qos_config.unwrap_or(json!({})))
}

pub fn get_speed_test_result() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_speed_test_result"}))?)?;
    resp.qos_config.ok_or_else(|| "no result".to_string())
}

pub fn log_audit(action: &str, detail: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "log_audit", "value": action, "key": detail}))?)?;
    Ok(())
}

pub fn list_audit_logs(limit: i64) -> Result<Vec<crate::types::AuditEntry>, String> {
    let resp = ok_or_err(send(json!({"method": "list_audit_logs", "limit": limit}))?)?;
    Ok(resp.audit_logs.unwrap_or_default())
}

pub fn get_tls_status() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "get_tls_status"}))?)?;
    resp.tls_status.ok_or_else(|| "no tls_status in response".to_string())
}

pub fn set_tls_cert(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "set_tls_cert",
        "tls_cert_pem": cert_pem,
        "tls_key_pem": key_pem,
    }))?)?;
    Ok(())
}

pub fn set_tls_mode(mode: &str, domain: Option<&str>) -> Result<(), String> {
    let mut req = json!({"method": "set_tls_mode", "value": mode});
    if let Some(d) = domain {
        req["key"] = serde_json::Value::String(d.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn set_acme_config(domain: &str, email: &str, cf_api_token: &str, cf_zone_id: &str) -> Result<(), String> {
    let config = serde_json::json!({
        "domain": domain,
        "email": email,
        "cf_api_token": cf_api_token,
        "cf_zone_id": cf_zone_id,
    });
    ok_or_err(send(json!({
        "method": "set_acme_config",
        "value": config.to_string(),
    }))?)?;
    Ok(())
}

pub fn wifi_list_aps() -> Result<Vec<hermitshell_common::WifiAp>, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_list_aps"}))?)?;
    Ok(resp.wifi_aps.unwrap_or_default())
}

pub fn wifi_list_providers() -> Result<Vec<hermitshell_common::WifiProviderInfo>, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_list_providers"}))?)?;
    Ok(resp.wifi_providers.unwrap_or_default())
}

pub fn wifi_add_provider(
    provider_type: &str,
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    mac: Option<&str>,
    site: Option<&str>,
    api_key: Option<&str>,
) -> Result<(), String> {
    let mut req = json!({
        "method": "wifi_add_provider",
        "protocol": provider_type,
        "name": name,
        "url": url,
        "key": username,
        "value": password,
    });
    if let Some(m) = mac {
        req["mac"] = serde_json::Value::String(m.to_string());
    }
    if let Some(s) = site {
        req["site"] = serde_json::Value::String(s.to_string());
    }
    if let Some(ak) = api_key {
        req["api_key"] = serde_json::Value::String(ak.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn wifi_remove_provider(id: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "wifi_remove_provider", "provider_id": id}))?)?;
    Ok(())
}

pub fn wifi_get_clients() -> Result<Vec<hermitshell_common::WifiClient>, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_get_clients"}))?)?;
    Ok(resp.wifi_clients.unwrap_or_default())
}

pub fn wifi_get_ssids(provider_id: &str) -> Result<Vec<hermitshell_common::WifiSsidConfig>, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_get_ssids", "provider_id": provider_id}))?)?;
    Ok(resp.wifi_ssids.unwrap_or_default())
}

pub fn wifi_set_ssid(provider_id: &str, ssid_name: &str, password: Option<&str>, band: &str, security: &str, hidden: bool) -> Result<(), String> {
    let mut req = json!({
        "method": "wifi_set_ssid",
        "provider_id": provider_id,
        "ssid_name": ssid_name,
        "band": band,
        "security": security,
        "hidden": hidden,
    });
    if let Some(pw) = password {
        req["value"] = serde_json::Value::String(pw.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn wifi_delete_ssid(provider_id: &str, ssid_name: &str, band: &str) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "wifi_delete_ssid",
        "provider_id": provider_id,
        "ssid_name": ssid_name,
        "band": band,
    }))?)?;
    Ok(())
}

pub fn wifi_get_radios(mac: &str) -> Result<Vec<hermitshell_common::WifiRadioConfig>, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_get_radios", "mac": mac}))?)?;
    Ok(resp.wifi_radios.unwrap_or_default())
}

pub fn wifi_set_radio(mac: &str, band: &str, channel: &str, channel_width: &str, tx_power: &str, enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "wifi_set_radio",
        "mac": mac,
        "band": band,
        "channel": channel,
        "channel_width": channel_width,
        "tx_power": tx_power,
        "enabled": enabled,
    }))?)?;
    Ok(())
}

pub fn list_interfaces() -> Result<Vec<hermitshell_common::NetworkInterface>, String> {
    let resp = ok_or_err(send(json!({"method": "list_interfaces"}))?)?;
    Ok(resp.interfaces.unwrap_or_default())
}

pub fn set_interfaces(wan: &str, lan: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_interfaces", "key": wan, "value": lan}))?)?;
    Ok(())
}

pub fn setup_wan_config(mode: &str, static_ip: Option<&str>, gateway: Option<&str>, dns: Option<&str>) -> Result<(), String> {
    let mut req = json!({"method": "setup_wan_config", "value": mode});
    if let Some(ip) = static_ip {
        req["key"] = serde_json::Value::String(ip.to_string());
    }
    if let Some(gw) = gateway {
        req["name"] = serde_json::Value::String(gw.to_string());
    }
    if let Some(d) = dns {
        req["description"] = serde_json::Value::String(d.to_string());
    }
    ok_or_err(send(req)?)?;
    Ok(())
}

pub fn set_router_hostname(hostname: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_hostname", "value": hostname}))?)?;
    Ok(())
}

pub fn set_timezone(tz: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_timezone", "value": tz}))?)?;
    Ok(())
}

pub fn setup_set_dns(upstream: &str, ad_blocking: bool) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "setup_set_dns",
        "value": upstream,
        "enabled": ad_blocking,
    }))?)?;
    Ok(())
}

pub fn setup_get_summary() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "setup_get_summary"}))?)?;
    let s = resp.config_value.unwrap_or_else(|| "{}".to_string());
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub fn finalize_setup() -> Result<(), String> {
    ok_or_err(send(json!({"method": "finalize_setup"}))?)?;
    Ok(())
}

pub fn is_setup_complete() -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "get_config", "key": "setup_complete"}))?)?;
    Ok(resp.config_value.as_deref() == Some("true"))
}

pub fn get_setup_step() -> Result<u32, String> {
    let resp = ok_or_err(send(json!({"method": "get_config", "key": "setup_step"}))?)?;
    Ok(resp.config_value.and_then(|s| s.parse().ok()).unwrap_or(1))
}

pub fn check_update() -> Result<serde_json::Value, String> {
    let resp = ok_or_err(send(json!({"method": "check_update"}))?)?;
    resp.update_info.ok_or_else(|| "no update_info in response".to_string())
}

pub fn get_bandwidth_history(device_mac: Option<&str>, period: &str) -> Result<Vec<hermitshell_common::BandwidthPoint>, String> {
    let mut req = json!({"method": "get_bandwidth_history", "period": period});
    if let Some(mac) = device_mac {
        req["device_mac"] = serde_json::Value::String(mac.to_string());
    }
    let resp = ok_or_err(send(req)?)?;
    Ok(resp.bandwidth_history.unwrap_or_default())
}

pub fn get_bandwidth_realtime() -> Result<Vec<hermitshell_common::BandwidthRealtime>, String> {
    let resp = ok_or_err(send(json!({"method": "get_bandwidth_realtime"}))?)?;
    Ok(resp.bandwidth_realtime.unwrap_or_default())
}

pub fn get_top_destinations(device_mac: &str, period: &str, limit: i64) -> Result<Vec<hermitshell_common::TopDestination>, String> {
    let resp = ok_or_err(send(json!({
        "method": "get_top_destinations",
        "device_mac": device_mac,
        "period": period,
        "limit": limit,
    }))?)?;
    Ok(resp.top_destinations.unwrap_or_default())
}

pub fn run_bandwidth_rollup() -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "run_bandwidth_rollup"}))?)?;
    Ok(resp.config_value.unwrap_or_default())
}

pub fn apply_update() -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "apply_update"}))?)?;
    resp.config_value.ok_or_else(|| "no version in response".into())
}

pub fn set_auto_update(enabled: bool) -> Result<(), String> {
    let value = if enabled { "true" } else { "false" };
    ok_or_err(send(json!({"method": "set_config", "key": "auto_update_enabled", "value": value}))?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_format_json_construction() {
        // Scan only the non-test portion of client.rs for format! usage.
        // All JSON request construction must use serde_json to prevent injection.
        let source = include_str!("client.rs");
        for (i, line) in source.lines().enumerate() {
            if line.contains("#[cfg(test)]") {
                break; // stop before test module
            }
            if line.contains("format!") && !line.contains("map_err") {
                panic!(
                    "client.rs:{}: format! outside map_err — \
                     use serde_json::json!() instead\n  {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }
}

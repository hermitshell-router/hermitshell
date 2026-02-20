use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use crate::types::{Device, Status};

const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionLog {
    pub id: i64,
    pub device_ip: String,
    pub dest_ip: String,
    pub dest_port: i64,
    pub protocol: String,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsLogEntry {
    pub id: i64,
    pub device_ip: String,
    pub domain: String,
    pub query_type: String,
    pub ts: i64,
}

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

pub fn get_ad_blocking() -> Result<bool, String> {
    let resp = ok_or_err(send(json!({"method": "get_ad_blocking"}))?)?;
    Ok(resp.ad_blocking_enabled.unwrap_or(true))
}

pub fn set_ad_blocking(enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_ad_blocking", "enabled": enabled}))?)?;
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

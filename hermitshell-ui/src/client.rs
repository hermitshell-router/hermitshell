use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use crate::types::{Device, Status};

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

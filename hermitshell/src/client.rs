use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

#[derive(Debug, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub error: Option<String>,
    pub devices: Option<Vec<Device>>,
    pub device: Option<Device>,
    pub status: Option<Status>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub uptime_secs: u64,
    pub device_count: usize,
}

fn send_request(method: &str, mac: Option<&str>) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("Failed to connect to agent: {}", e))?;

    let request = if let Some(m) = mac {
        format!(r#"{{"method":"{}","mac":"{}"}}"#, method, m)
    } else {
        format!(r#"{{"method":"{}"}}"#, method)
    };

    writeln!(stream, "{}", request)
        .map_err(|e| format!("Failed to send request: {}", e))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))
}

pub fn list_devices() -> Result<Vec<Device>, String> {
    let resp = send_request("list_devices", None)?;
    if resp.ok {
        Ok(resp.devices.unwrap_or_default())
    } else {
        Err(resp.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

pub fn get_status() -> Result<Status, String> {
    let resp = send_request("get_status", None)?;
    if resp.ok {
        resp.status.ok_or_else(|| "No status in response".to_string())
    } else {
        Err(resp.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

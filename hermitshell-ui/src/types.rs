use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub device_group: String,
    pub subnet_id: Option<i64>,
    pub nickname: Option<String>,
    pub runzero_os: Option<String>,
    pub runzero_hw: Option<String>,
    pub runzero_device_type: Option<String>,
    pub runzero_manufacturer: Option<String>,
    pub runzero_last_sync: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub uptime_secs: u64,
    pub device_count: usize,
    #[serde(default)]
    pub ad_blocking_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardInfo {
    pub enabled: bool,
    pub public_key: Option<String>,
    pub listen_port: u16,
    pub peers: Vec<WgPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerInfo {
    pub public_key: String,
    pub name: String,
    pub ip: String,
    pub device_group: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub id: i64,
    pub protocol: String,
    pub external_port_start: u16,
    pub external_port_end: u16,
    pub internal_ip: String,
    pub internal_port: u16,
    pub enabled: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservation {
    pub mac: String,
    pub subnet_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardsInfo {
    pub port_forwards: Vec<PortForward>,
    pub dmz_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub detail: String,
    pub created_at: i64,
}

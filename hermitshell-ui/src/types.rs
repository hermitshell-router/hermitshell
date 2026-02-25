use serde::{Deserialize, Serialize};

pub use hermitshell_common::{
    AuditEntry, BandwidthPoint, BandwidthRealtime, Device, DhcpReservation,
    PortForward, TopDestination,
};

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
pub struct PortForwardsInfo {
    pub port_forwards: Vec<PortForward>,
    pub dmz_ip: String,
}

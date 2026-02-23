pub mod subnet;

pub fn sanitize_hostname(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.' || *c == '_')
        .take(63)
        .collect()
}

/// A network device tracked by the agent, identified by MAC address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub mac: String,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6_ula: Option<String>,
    #[serde(default)]
    pub ipv6_global: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// Unix epoch seconds when the device was first seen on the network.
    pub first_seen: i64,
    /// Unix epoch seconds when the device was last seen (updated on DHCP renewal or traffic).
    pub last_seen: i64,
    /// Cumulative bytes received by this device, read from nftables counters.
    #[serde(default)]
    pub rx_bytes: i64,
    /// Cumulative bytes transmitted by this device, read from nftables counters.
    #[serde(default)]
    pub tx_bytes: i64,
    pub device_group: String,
    /// Unique device identifier used for /32 IPv4 and /128 IPv6 allocation.
    #[serde(default)]
    pub subnet_id: Option<i64>,
    #[serde(default)]
    pub runzero_os: Option<String>,
    #[serde(default)]
    pub runzero_hw: Option<String>,
    #[serde(default)]
    pub runzero_device_type: Option<String>,
    #[serde(default)]
    pub runzero_manufacturer: Option<String>,
    #[serde(default)]
    pub runzero_last_sync: Option<i64>,
    #[serde(default)]
    pub nickname: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    pub name: String,
    pub subnet_id: i64,
    pub device_group: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DhcpReservation {
    pub mac: String,
    pub subnet_id: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionLog {
    pub id: i64,
    pub device_ip: String,
    pub dest_ip: String,
    pub dest_port: i64,
    pub protocol: String,
    #[serde(default)]
    pub bytes_sent: i64,
    #[serde(default)]
    pub bytes_recv: i64,
    pub started_at: i64,
    #[serde(default)]
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsLogEntry {
    pub id: i64,
    pub device_ip: String,
    pub domain: String,
    pub query_type: String,
    pub ts: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Alert {
    pub id: i64,
    pub device_mac: String,
    pub rule: String,
    pub severity: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub acknowledged: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub detail: String,
    pub created_at: i64,
}

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
    #[serde(default)]
    pub wifi_ssid: Option<String>,
    #[serde(default)]
    pub wifi_band: Option<String>,
    #[serde(default)]
    pub wifi_rssi: Option<i32>,
    #[serde(default)]
    pub wifi_ap_mac: Option<String>,
    #[serde(default)]
    pub wifi_last_seen: Option<i64>,
    #[serde(default)]
    pub dhcp_fingerprint: Option<String>,
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
    #[serde(default)]
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requesting_ip: Option<String>,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BandwidthPoint {
    pub bucket: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BandwidthRealtime {
    pub mac: String,
    pub ip: String,
    pub rx_bps: i64,
    pub tx_bps: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TopDestination {
    pub dest_ip: String,
    pub dest_port: u16,
    pub total_bytes: i64,
}

/// An adopted WiFi access point managed by the agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiAp {
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub firmware: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub last_seen: Option<i64>,
    pub status: String,
    #[serde(default)]
    pub has_ca_cert: bool,
    #[serde(default)]
    pub provider_id: Option<String>,
}

/// A registered WiFi provider (controller or direct AP connection).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiProviderInfo {
    pub id: String,
    pub provider_type: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub status: String,
    #[serde(default)]
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub ap_count: u32,
    #[serde(default)]
    pub has_ca_cert: bool,
}

/// Device info returned by WifiProvider::list_devices().
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiDeviceInfo {
    pub mac: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub firmware: Option<String>,
    pub status: String,
    #[serde(default)]
    pub uptime: Option<u64>,
}

/// A WiFi client observed on an access point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiClient {
    pub mac: String,
    pub ap_mac: String,
    pub ssid: String,
    pub band: String,
    #[serde(default)]
    pub rssi: Option<i32>,
    #[serde(default)]
    pub rx_rate: Option<u32>,
    #[serde(default)]
    pub tx_rate: Option<u32>,
}

/// SSID configuration for an access point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiSsidConfig {
    pub ssid_name: String,
    #[serde(default)]
    pub password: Option<String>,
    pub band: String,
    #[serde(default)]
    pub vlan_id: Option<u16>,
    #[serde(default)]
    pub hidden: bool,
    pub enabled: bool,
    pub security: String,
}

/// Radio configuration for an access point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiRadioConfig {
    pub band: String,
    pub channel: String,
    pub channel_width: String,
    pub tx_power: String,
    pub enabled: bool,
}

/// A network interface discovered on the system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub state: String,
    pub has_carrier: bool,
}

/// An mDNS service advertised by a device on the LAN.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MdnsService {
    pub service_type: String,
    pub service_name: String,
    pub port: u16,
    #[serde(default)]
    pub txt_records: Vec<(String, String)>,
}

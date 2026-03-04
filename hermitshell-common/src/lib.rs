pub mod config_validate;
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
    #[serde(default)]
    pub switch_port: Option<String>,
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
pub struct DnsForwardZone {
    pub id: i64,
    pub domain: String,
    pub forward_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsCustomRule {
    pub id: i64,
    pub domain: String,
    pub record_type: String,
    pub value: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsBlocklist {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub tag: String,
    pub enabled: bool,
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
pub struct DashboardStats {
    pub connections_24h: i64,
    pub dns_queries_24h: i64,
    pub unacked_alerts: i64,
    pub top_talkers: Vec<TopTalker>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TopTalker {
    pub mac: String,
    pub hostname: Option<String>,
    pub total_bytes: i64,
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

/// A registered SNMP switch for MAC table polling.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnmpSwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default = "default_v2c")]
    pub version: String,
    #[serde(default)]
    pub v3_username: Option<String>,
    #[serde(default)]
    pub v3_auth_protocol: Option<String>,
    #[serde(default)]
    pub v3_cipher: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
}

fn default_v2c() -> String { "2c".to_string() }

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

// ---------------------------------------------------------------------------
// Declarative configuration types (desired-state)
// ---------------------------------------------------------------------------

/// Complete desired-state configuration for HermitShell.
/// Parsed from TOML config file, serialized as JSON over socket/REST.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HermitConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub wireguard: WireguardConfig,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
    #[serde(default)]
    pub dhcp: DhcpConfig,
    #[serde(default)]
    pub qos: QosConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub wifi: WifiConfig,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub wan_interface: Option<String>,
    #[serde(default)]
    pub lan_interface: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub upstream_dns: Vec<String>,
    #[serde(default)]
    pub wan: WanConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WanConfig {
    #[serde(default = "default_wan_mode")]
    pub mode: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
}

impl Default for WanConfig {
    fn default() -> Self {
        Self {
            mode: default_wan_mode(),
            address: None,
            gateway: None,
        }
    }
}

fn default_wan_mode() -> String { "dhcp".to_string() }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub ad_blocking: bool,
    #[serde(default)]
    pub ratelimit_per_second: Option<u32>,
    #[serde(default)]
    pub blocklists: Vec<BlocklistConfig>,
    #[serde(default)]
    pub forward_zones: Vec<ForwardZoneConfig>,
    #[serde(default)]
    pub custom_records: Vec<CustomRecordConfig>,
    #[serde(default)]
    pub bypass_allowed: Option<DnsBypassConfig>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            ad_blocking: default_true(),
            ratelimit_per_second: None,
            blocklists: Vec::new(),
            forward_zones: Vec::new(),
            custom_records: Vec::new(),
            bypass_allowed: None,
        }
    }
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsBypassConfig {
    #[serde(default)]
    pub trusted: bool,
    #[serde(default)]
    pub guest: bool,
    #[serde(default)]
    pub quarantine: bool,
    #[serde(default)]
    pub iot: bool,
    #[serde(default)]
    pub servers: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_ads_tag")]
    pub tag: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_ads_tag() -> String { "ads".to_string() }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardZoneConfig {
    pub domain: String,
    pub forward_to: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRecordConfig {
    pub domain: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FirewallConfig {
    #[serde(default)]
    pub dmz_host: Option<String>,
    #[serde(default)]
    pub port_forwards: Vec<PortForwardConfig>,
    #[serde(default)]
    pub ipv6_pinholes: Vec<Ipv6PinholeConfig>,
    #[serde(default)]
    pub upnp_enabled: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForwardConfig {
    #[serde(default = "default_both")]
    pub protocol: String,
    pub external_port: u16,
    #[serde(default)]
    pub external_port_end: Option<u16>,
    pub internal_ip: String,
    pub internal_port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

fn default_both() -> String { "both".to_string() }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv6PinholeConfig {
    pub device: String,
    pub protocol: String,
    pub port_start: u16,
    #[serde(default)]
    pub port_end: Option<u16>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WireguardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wg_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub peers: Vec<WgPeerConfig>,
}

impl Default for WireguardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: default_wg_port(),
            peers: Vec::new(),
        }
    }
}

fn default_wg_port() -> u16 { 51820 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeerConfig {
    pub name: String,
    pub public_key: String,
    #[serde(default = "default_trusted")]
    pub device_group: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_trusted() -> String { "trusted".to_string() }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    pub mac: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default = "default_quarantine")]
    pub group: String,
}

fn default_quarantine() -> String { "quarantine".to_string() }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DhcpConfig {
    #[serde(default)]
    pub reservations: Vec<DhcpReservationConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpReservationConfig {
    pub mac: String,
    pub subnet_id: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QosConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upload_mbps: u32,
    #[serde(default)]
    pub download_mbps: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_text")]
    pub format: String,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default)]
    pub syslog_target: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_text(),
            retention_days: default_retention(),
            syslog_target: None,
            webhook_url: None,
        }
    }
}

fn default_text() -> String { "text".to_string() }
fn default_retention() -> u32 { 7 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_self_signed")]
    pub mode: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: default_self_signed(),
        }
    }
}

fn default_self_signed() -> String { "self_signed".to_string() }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AnalysisConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub alert_rules: Option<AlertRulesConfig>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AlertRulesConfig {
    #[serde(default)]
    pub dns_beaconing: Option<bool>,
    #[serde(default)]
    pub dns_volume_spike: Option<bool>,
    #[serde(default)]
    pub new_dest_spike: Option<bool>,
    #[serde(default)]
    pub suspicious_ports: Option<bool>,
    #[serde(default)]
    pub bandwidth_spike: Option<bool>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WifiConfig {
    #[serde(default)]
    pub providers: Vec<WifiProviderConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WifiProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

/// Secrets config (separate file, not committed to git).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HermitSecrets {
    #[serde(default)]
    pub admin_password_hash: Option<String>,
    #[serde(default)]
    pub session_secret: Option<String>,
    #[serde(default)]
    pub wg_private_key: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsSecrets>,
    #[serde(default)]
    pub integrations: Option<IntegrationSecrets>,
    #[serde(default)]
    pub wifi: Option<WifiSecrets>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TlsSecrets {
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub acme_cf_api_token: Option<String>,
    #[serde(default)]
    pub acme_account_key: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IntegrationSecrets {
    #[serde(default)]
    pub runzero_token: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WifiSecrets {
    #[serde(default)]
    pub providers: Vec<WifiProviderSecrets>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiProviderSecrets {
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VlanGroupConfig {
    pub group_name: String,
    pub vlan_id: u16,
    pub subnet: String,
    pub gateway: String,
}

impl HermitConfig {
    /// Parse from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parse from JSON string.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl HermitSecrets {
    /// Parse from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

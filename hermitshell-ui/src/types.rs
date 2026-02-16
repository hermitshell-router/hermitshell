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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub uptime_secs: u64,
    pub device_count: usize,
    #[serde(default)]
    pub ad_blocking_enabled: bool,
}

pub mod ssh;
pub mod vendor;

use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct SwitchPort {
    pub name: String,
    pub status: PortStatus,
    pub vlan_id: Option<u16>,
    pub is_trunk: bool,
    pub macs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortStatus {
    Up,
    Down,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct MacTableEntry {
    pub mac: String,
    pub vlan_id: u16,
    pub port: String,
}

#[async_trait]
pub trait SwitchProvider: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn list_ports(&self) -> Result<Vec<SwitchPort>>;
    async fn set_port_vlan(&self, port: &str, vlan_id: u16) -> Result<()>;
    async fn get_mac_table(&self) -> Result<Vec<MacTableEntry>>;
    async fn set_trunk_port(&self, port: &str, allowed_vlans: &[u16]) -> Result<()>;
    async fn create_vlan(&self, vlan_id: u16, name: &str) -> Result<()>;
    async fn save_config(&self) -> Result<()>;
}

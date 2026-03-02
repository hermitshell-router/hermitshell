pub mod ssh;
pub mod vendor;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::db::Db;

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

/// Background polling loop — queries switches for MAC table data and
/// correlates entries with known devices.
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));

    loop {
        poll_interval.tick().await;

        // Skip if VLAN mode is not enabled
        let vlan_enabled = {
            let db = db.lock().unwrap();
            db.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled")
        };
        if !vlan_enabled {
            continue;
        }

        let providers = {
            let db = db.lock().unwrap();
            db.list_switch_providers().unwrap_or_default()
        };

        for provider_info in &providers {
            if !provider_info.enabled {
                continue;
            }

            // Get credentials from DB
            let creds = {
                let db = db.lock().unwrap();
                db.get_switch_provider_credentials(&provider_info.id).ok()
            };
            let Some((host, port, username, password_enc, vendor_profile_name, host_key)) = creds
            else {
                continue;
            };

            // Decrypt password
            let password = {
                let session_secret = {
                    let db = db.lock().unwrap();
                    db.get_config("session_secret")
                        .ok()
                        .flatten()
                        .unwrap_or_default()
                };
                if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
                    password_enc
                } else {
                    match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(switch = %provider_info.name, error = %e, "failed to decrypt password");
                            continue;
                        }
                    }
                }
            };

            // Get vendor profile (custom or built-in)
            let profile = {
                let custom = {
                    let db = db.lock().unwrap();
                    db.get_custom_vendor_profile(&vendor_profile_name)
                        .ok()
                        .flatten()
                };
                if let Some(json) = custom {
                    match serde_json::from_str(&json) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(switch = %provider_info.name, error = %e, "failed to parse custom profile");
                            continue;
                        }
                    }
                } else {
                    match vendor::built_in_profile(&vendor_profile_name) {
                        Some(p) => p,
                        None => {
                            warn!(switch = %provider_info.name, profile = %vendor_profile_name, "unknown vendor profile");
                            continue;
                        }
                    }
                }
            };

            // Create SSH provider
            let provider = ssh::SshSwitchProvider::new(
                host,
                port,
                username,
                password,
                profile,
                host_key.clone(),
            );

            // Poll MAC table
            match provider.get_mac_table().await {
                Ok(entries) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let db = db.lock().unwrap();
                    db.update_switch_provider_status(&provider_info.id, "connected", now)
                        .ok();

                    // Correlate MACs with known devices
                    for entry in &entries {
                        let mac_upper = entry.mac.to_uppercase();
                        if let Ok(Some(_dev)) = db.get_device(&mac_upper) {
                            let _ = db.update_device_switch_info(
                                &mac_upper,
                                &provider_info.id,
                                &entry.port,
                            );
                        }
                    }

                    info!(switch = %provider_info.name, mac_count = entries.len(), "switch poll complete");
                }
                Err(e) => {
                    warn!(switch = %provider_info.name, error = %e, "switch poll failed");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let db = db.lock().unwrap();
                    db.update_switch_provider_status(&provider_info.id, "error", now)
                        .ok();
                }
            }

            // Save discovered host key if TOFU
            if host_key.is_none() {
                if let Some(discovered) = provider.host_key() {
                    let db = db.lock().unwrap();
                    let _ = db.set_switch_provider_host_key(&provider_info.id, discovered);
                    info!(switch = %provider_info.name, "saved TOFU host key");
                }
            }
        }
    }
}

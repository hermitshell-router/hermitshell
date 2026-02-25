pub mod eap_standalone;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::db::Db;
use hermitshell_common::{WifiClient, WifiRadioConfig, WifiSsidConfig};

/// Status info returned by get_status.
#[derive(Debug)]
pub struct ApStatus {
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub uptime: Option<u64>,
}

/// A provider-independent session to a WiFi AP.
#[async_trait]
pub trait WifiSession: Send + Sync {
    async fn get_status(&self) -> Result<ApStatus>;
    async fn get_clients(&self) -> Result<Vec<WifiClient>>;
    async fn get_ssids(&self) -> Result<Vec<WifiSsidConfig>>;
    async fn set_ssid(&self, config: &WifiSsidConfig) -> Result<()>;
    async fn delete_ssid(&self, ssid_name: &str, band: &str) -> Result<()>;
    async fn get_radios(&self) -> Result<Vec<WifiRadioConfig>>;
    async fn set_radio(&self, config: &WifiRadioConfig) -> Result<()>;
    async fn kick_client(&self, mac: &str) -> Result<()>;
    async fn block_client(&self, mac: &str) -> Result<()>;
    async fn unblock_client(&self, mac: &str) -> Result<()>;
}

/// Creates a session for a given provider type.
pub async fn connect(
    provider: &str,
    ip: &str,
    username: &str,
    password: &str,
    ca_cert_pem: Option<&str>,
) -> Result<Box<dyn WifiSession>> {
    match provider {
        "eap_standalone" => {
            let session = eap_standalone::EapSession::login(ip, username, password, ca_cert_pem).await?;
            Ok(Box::new(session))
        }
        _ => anyhow::bail!("unknown wifi provider: {}", provider),
    }
}

/// Background polling loop — pulls client data from all enabled APs.
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));

    loop {
        poll_interval.tick().await;

        let aps = {
            let db = db.lock().unwrap();
            db.list_wifi_aps().unwrap_or_default()
        };

        for ap in &aps {
            if !ap.enabled {
                continue;
            }

            let creds = {
                let db = db.lock().unwrap();
                db.get_wifi_ap_credentials(&ap.mac).ok().flatten()
            };
            let Some((ip, username, password_enc)) = creds else {
                continue;
            };

            let ca_cert = {
                let db = db.lock().unwrap();
                db.get_wifi_ap_ca_cert(&ap.mac).ok().flatten()
            };

            let password = {
                let session_secret = {
                    let db_lock = db.lock().unwrap();
                    db_lock.get_config("session_secret").ok().flatten().unwrap_or_default()
                };
                if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
                    password_enc
                } else {
                    match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(ap = %ap.name, error = %e, "failed to decrypt AP password");
                            continue;
                        }
                    }
                }
            };

            match connect(&ap.provider, &ip, &username, &password, ca_cert.as_deref()).await {
                Ok(session) => {
                    // Update AP status
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    if let Ok(status) = session.get_status().await {
                        let db = db.lock().unwrap();
                        let _ = db.update_wifi_ap_status(&ap.mac, "online", now);
                        let _ = db.update_wifi_ap_info(
                            &ap.mac,
                            status.model.as_deref(),
                            status.firmware.as_deref(),
                        );
                    }

                    // Pull clients and enrich device records
                    if let Ok(clients) = session.get_clients().await {
                        let db = db.lock().unwrap();
                        for client in &clients {
                            let _ = db.update_device_wifi(
                                &client.mac,
                                Some(&client.ssid),
                                Some(&client.band),
                                client.rssi,
                                Some(&client.ap_mac),
                            );
                        }
                        info!(ap = %ap.name, clients = clients.len(), "wifi poll complete");
                    }
                }
                Err(e) => {
                    warn!(ap = %ap.name, error = %e, "wifi poll failed");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let db = db.lock().unwrap();
                    let _ = db.update_wifi_ap_status(&ap.mac, "error", now);
                }
            }
        }
    }
}

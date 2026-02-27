pub mod eap_standalone;
pub mod unifi;

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

/// A provider-independent session to a WiFi management endpoint.
/// For direct APs (EAP720): one provider = one AP.
/// For controllers (UniFi): one provider = N APs.
#[async_trait]
pub trait WifiProvider: Send + Sync {
    /// Physical APs managed by this provider.
    async fn list_devices(&self) -> Result<Vec<hermitshell_common::WifiDeviceInfo>>;

    /// Get an AP-scoped handle for per-device operations.
    async fn device(&self, ap_mac: &str) -> Result<Box<dyn WifiDevice>>;

    /// SSIDs managed by this provider (controller-wide for UniFi, per-AP for EAP720).
    async fn get_ssids(&self) -> Result<Vec<WifiSsidConfig>>;
    async fn set_ssid(&self, config: &WifiSsidConfig) -> Result<()>;
    async fn delete_ssid(&self, ssid_name: &str, band: &str) -> Result<()>;

    /// Client management routed through the correct AP/controller.
    async fn kick_client(&self, mac: &str) -> Result<()>;
    async fn block_client(&self, mac: &str) -> Result<()>;
    async fn unblock_client(&self, mac: &str) -> Result<()>;
}

/// Per-physical-AP operations (radio config, status, clients).
#[async_trait]
pub trait WifiDevice: Send + Sync {
    async fn get_status(&self) -> Result<ApStatus>;
    async fn get_clients(&self) -> Result<Vec<WifiClient>>;
    async fn get_radios(&self) -> Result<Vec<WifiRadioConfig>>;
    async fn set_radio(&self, config: &WifiRadioConfig) -> Result<()>;
}

/// Creates a provider session for a given provider type.
/// Returns `(provider, tofu_cert_pem)` where tofu_cert_pem is `Some` if a TOFU
/// certificate was captured (first connection without a CA cert).
pub async fn connect(
    provider_type: &str,
    url: &str,
    username: &str,
    password: &str,
    ca_cert_pem: Option<&str>,
    site: Option<&str>,
    api_key: Option<&str>,
) -> Result<(Box<dyn WifiProvider>, Option<String>)> {
    match provider_type {
        "eap_standalone" => {
            let (session, tofu_pem) =
                eap_standalone::EapSession::login(url, username, password, ca_cert_pem).await?;
            Ok((Box::new(session), tofu_pem))
        }
        "unifi" => {
            anyhow::bail!("unifi provider not yet implemented");
        }
        _ => anyhow::bail!("unknown wifi provider: {}", provider_type),
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
                Ok((session, tofu_pem)) => {
                    // Save TOFU-pinned cert if this was a first connection
                    if let Some(ref pem) = tofu_pem {
                        let db = db.lock().unwrap();
                        let _ = db.set_wifi_ap_ca_cert(&ap.mac, Some(pem));
                        info!(ap = %ap.name, "TOFU: pinned TLS certificate");
                    }

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

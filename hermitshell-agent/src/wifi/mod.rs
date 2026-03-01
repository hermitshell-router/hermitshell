pub mod eap_standalone;
pub mod unifi;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, interval};
use tracing::{info, warn};
use zeroize::Zeroizing;

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
    #[allow(dead_code)]
    async fn kick_client(&self, mac: &str) -> Result<()>;
    #[allow(dead_code)]
    async fn block_client(&self, mac: &str) -> Result<()>;
    #[allow(dead_code)]
    async fn unblock_client(&self, mac: &str) -> Result<()>;
}

/// Per-physical-AP operations (radio config, status, clients).
#[async_trait]
pub trait WifiDevice: Send + Sync {
    #[allow(dead_code)]
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
            let site = site.unwrap_or("default");
            let (session, tofu_pem) =
                unifi::UnifiSession::connect(url, username, password, ca_cert_pem, site, api_key)
                    .await?;
            Ok((Box::new(session), tofu_pem))
        }
        _ => anyhow::bail!("unknown wifi provider: {}", provider_type),
    }
}

/// Background polling loop — pulls client data from all enabled providers.
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));

    loop {
        poll_interval.tick().await;

        let providers = {
            let db = db.lock().unwrap();
            db.list_wifi_providers().unwrap_or_default()
        };

        for provider_info in &providers {
            if !provider_info.enabled {
                continue;
            }

            let creds = {
                let db = db.lock().unwrap();
                db.get_wifi_provider_credentials(&provider_info.id).ok().flatten()
            };
            let Some((provider_type, url, username, password_enc, site, api_key_enc)) = creds else {
                continue;
            };

            let ca_cert = {
                let db = db.lock().unwrap();
                db.get_wifi_provider_ca_cert(&provider_info.id).ok().flatten()
            };

            // Decrypt password
            let password: Zeroizing<String> = {
                let session_secret = Zeroizing::new({
                    let db_lock = db.lock().unwrap();
                    db_lock.get_config("session_secret").ok().flatten().unwrap_or_default()
                });
                if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
                    Zeroizing::new(password_enc)
                } else {
                    match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                        Ok(p) => Zeroizing::new(p),
                        Err(e) => {
                            warn!(provider = %provider_info.name, error = %e, "failed to decrypt provider password");
                            continue;
                        }
                    }
                }
            };

            // Decrypt API key if present
            let api_key: Option<Zeroizing<String>> = api_key_enc.and_then(|enc| {
                if enc.is_empty() { return None; }
                let session_secret = Zeroizing::new({
                    let db_lock = db.lock().unwrap();
                    db_lock.get_config("session_secret").ok().flatten().unwrap_or_default()
                });
                if session_secret.is_empty() || !crate::crypto::is_encrypted(&enc) {
                    Some(Zeroizing::new(enc))
                } else {
                    crate::crypto::decrypt_password(&enc, &session_secret).ok().map(Zeroizing::new)
                }
            });

            match connect(
                &provider_type, &url, &username, &password,
                ca_cert.as_deref(), site.as_deref(), api_key.as_ref().map(|k| k.as_str()),
            ).await {
                Ok((provider, tofu_pem)) => {
                    // Save TOFU-pinned cert
                    if let Some(ref pem) = tofu_pem {
                        let db = db.lock().unwrap();
                        let _ = db.set_wifi_provider_ca_cert(&provider_info.id, Some(pem));
                        info!(provider = %provider_info.name, "TOFU: pinned TLS certificate");
                    }

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    // Sync device list
                    match provider.list_devices().await {
                        Ok(devices) => {
                            let db = db.lock().unwrap();
                            let _ = db.sync_wifi_aps(&provider_info.id, &devices);
                            let _ = db.update_wifi_provider_status(&provider_info.id, "online", now);
                        }
                        Err(e) => {
                            warn!(provider = %provider_info.name, error = %e, "list_devices failed");
                        }
                    }

                    // Pull clients from each device and enrich device records
                    let device_macs: Vec<String> = {
                        let db = db.lock().unwrap();
                        db.list_wifi_aps().unwrap_or_default()
                            .into_iter()
                            .filter(|ap| ap.provider_id.as_deref() == Some(&provider_info.id))
                            .map(|ap| ap.mac)
                            .collect()
                    };

                    for ap_mac in &device_macs {
                        if let Ok(device) = provider.device(ap_mac).await
                            && let Ok(clients) = device.get_clients().await {
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
                            }
                    }

                    info!(provider = %provider_info.name, "wifi poll complete");
                }
                Err(e) => {
                    warn!(provider = %provider_info.name, error = %e, "wifi poll failed");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let db = db.lock().unwrap();
                    let _ = db.update_wifi_provider_status(&provider_info.id, "error", now);
                }
            }
        }
    }
}

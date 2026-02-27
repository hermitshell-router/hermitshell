use anyhow::{Context, Result};
use async_trait::async_trait;
use md5::{Digest, Md5};
use reqwest::header::{self, HeaderMap, HeaderValue};
use serde_json::Value;
use tracing::debug;

use hermitshell_common::{WifiClient, WifiRadioConfig, WifiSsidConfig};

use super::{ApStatus, WifiDevice, WifiProvider};

/// Session to a TP-Link EAP in standalone mode via its HTTPS web UI.
///
/// Auth flow (reverse-engineered from EAP720 firmware 1.0.0):
///   1. GET / to prime session
///   2. POST / with MD5-uppercase password to get JSESSIONID cookie
///   3. POST /data/login.json with operation=read to activate session
///   4. All subsequent requests include Cookie + Referer headers
#[derive(Clone)]
pub struct EapSession {
    client: reqwest::Client,
    base_url: String,
    /// AP IP address used for login
    ip: String,
    /// AP MAC in colon-separated format (XX:XX:XX:XX:XX:XX), read from status.device.json
    mac: String,
}

fn md5_upper(plaintext: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(plaintext.as_bytes());
    format!("{:X}", hasher.finalize())
}

/// Band string for a given radioID.
fn radio_id_to_band(id: u64) -> &'static str {
    match id {
        0 => "2.4GHz",
        1 => "5GHz",
        2 => "5GHz-2",
        3 => "6GHz",
        _ => "unknown",
    }
}

/// Map our band string to the EAP radioID parameter.
fn band_to_radio_id(band: &str) -> Option<u8> {
    match band {
        "2.4GHz" => Some(0),
        "5GHz" => Some(1),
        "5GHz-2" => Some(2),
        "6GHz" => Some(3),
        _ => None,
    }
}

/// Map EAP securityMode int to human-readable string.
fn security_mode_str(mode: u64) -> &'static str {
    match mode {
        0 => "none",
        1 => "wpa-psk",
        2 => "wpa-enterprise",
        _ => "unknown",
    }
}

/// Map channel width integer to string.
fn channel_width_str(w: u64) -> String {
    match w {
        2 => "20MHz".to_string(),
        3 => "40MHz".to_string(),
        5 => "80MHz".to_string(),
        6 => "Auto".to_string(),
        7 => "160MHz".to_string(),
        _ => format!("{}?", w),
    }
}

impl EapSession {
    /// Log in to the AP. Returns `(session, tofu_cert_pem)`.
    ///
    /// - If `ca_cert_pem` is `Some`, tries rustls verification first, then
    ///   falls back to native-tls with verification. Returns `None` for cert.
    /// - If `ca_cert_pem` is `None` (TOFU), grabs the leaf cert via a bare
    ///   TLS handshake, then connects with that cert as root. Returns
    ///   `Some(pem)` so the caller can save it.
    pub async fn login(
        ip: &str,
        username: &str,
        password: &str,
        ca_cert_pem: Option<&str>,
    ) -> Result<(Self, Option<String>)> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            HeaderValue::from_str(&format!("https://{}/", ip))?,
        );

        let (client, tofu_pem) = if let Some(ca_pem) = ca_cert_pem {
            // CA-verified path: try rustls first, fall back to native-tls
            let client = Self::build_verified_client(ip, ca_pem, &headers).await?;
            (client, None)
        } else {
            // TOFU path: grab leaf cert, then connect with it
            let pem = crate::tls_client::grab_leaf_cert(ip, 443)
                .await
                .context("TOFU: failed to grab AP certificate")?;
            let client = Self::build_verified_client(ip, &pem, &headers).await?;
            (client, Some(pem))
        };

        let base_url = format!("https://{}", ip);
        let password_md5 = md5_upper(password);

        // Step 1: GET / to prime session
        client
            .get(&base_url)
            .send()
            .await
            .context("EAP: failed to reach login page")?;

        // Step 2: POST / with credentials to get JSESSIONID
        let resp = client
            .post(&base_url)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Origin", &base_url)
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .header(
                header::ACCEPT,
                "application/json, text/javascript, */*; q=0.01",
            )
            .body(format!("username={}&password={}", username, password_md5))
            .send()
            .await
            .context("EAP: login POST failed")?;

        // Empty body = success; HTML body = wrong password
        let body = resp.text().await?;
        if !body.is_empty() {
            anyhow::bail!("EAP login failed: wrong credentials");
        }

        // Step 3: POST /data/login.json to activate session
        let resp = client
            .post(format!("{}/data/login.json", base_url))
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body("operation=read")
            .send()
            .await
            .context("EAP: session activation failed")?;

        let json: Value = resp.json().await.context("EAP: login.json not JSON")?;
        debug!(resp = %json, "EAP login.json response");

        // Read AP MAC from device status
        let mut session = Self {
            client,
            base_url,
            ip: ip.to_string(),
            mac: String::new(),
        };

        if let Ok(status) = session.get_data_get("status.device.json").await {
            if let Some(mac) = status.get("mac").and_then(|v| v.as_str()) {
                // Convert TP-Link format (XX-XX-XX-XX-XX-XX) to colon-separated
                session.mac = mac.replace('-', ":");
            }
        }

        Ok((session, tofu_pem))
    }

    /// Build a verified reqwest client. Tries rustls first; on TLS handshake
    /// failure, retries with native-tls (for legacy ciphers).
    async fn build_verified_client(
        ip: &str,
        ca_pem: &str,
        headers: &HeaderMap,
    ) -> Result<reqwest::Client> {
        // Try rustls first (modern TLS)
        let rustls_builder = crate::tls_client::builder_with_ca(Some(ca_pem))?
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(10))
            .default_headers(headers.clone());

        let rustls_client = rustls_builder.build()?;
        let probe_url = format!("https://{}/", ip);

        match rustls_client.get(&probe_url).send().await {
            Ok(_) => return Ok(rustls_client),
            Err(e) => {
                debug!(error = %e, "rustls handshake failed, trying native-tls");
            }
        }

        // Fall back to native-tls (legacy TLS support)
        let native_builder = crate::tls_client::builder_wifi_native_verified(ca_pem)?
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(10))
            .default_headers(headers.clone());

        native_builder.build().context("native-tls client build failed")
    }

    /// GET /data/<endpoint>?operation=read[&extra_params]
    async fn get_data_get(&self, endpoint: &str) -> Result<Value> {
        let url = format!("{}/data/{}?operation=read", self.base_url, endpoint);
        let resp = self.client.get(&url).send().await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        Ok(json.get("data").cloned().unwrap_or(Value::Null))
    }

    /// GET /data/<endpoint>?operation=read&radioID=<id>
    async fn get_data_get_radio(&self, endpoint: &str, radio_id: u8) -> Result<Value> {
        let url = format!(
            "{}/data/{}?operation=read&radioID={}",
            self.base_url, endpoint, radio_id
        );
        let resp = self.client.get(&url).send().await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        Ok(json.get("data").cloned().unwrap_or(Value::Null))
    }

    /// POST /data/<endpoint> with operation=read[&extra]
    async fn post_data_read(&self, endpoint: &str, extra: &str) -> Result<Value> {
        let url = format!("{}/data/{}", self.base_url, endpoint);
        let body = if extra.is_empty() {
            "operation=read".to_string()
        } else {
            format!("operation=read&{}", extra)
        };
        let resp = self
            .client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8")
            .body(body)
            .send()
            .await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        Ok(json.get("data").cloned().unwrap_or(Value::Null))
    }

    /// POST /data/<endpoint> with operation=write&<params>
    async fn post_data_write(&self, endpoint: &str, params: &str) -> Result<Value> {
        let url = format!("{}/data/{}", self.base_url, endpoint);
        let body = format!("operation=write&{}", params);
        let resp = self
            .client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8")
            .body(body)
            .send()
            .await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        let success = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !success {
            let err_code = json.get("error").or(json.get("errCode"));
            anyhow::bail!("EAP write failed: {:?}", err_code);
        }
        Ok(json.get("data").cloned().unwrap_or(Value::Null))
    }

    fn check_timeout(&self, json: &Value) -> Result<()> {
        let timeout = json.get("timeout");
        let is_timeout = match timeout {
            Some(Value::Bool(true)) => true,
            Some(Value::String(s)) => s == "true",
            _ => false,
        };
        if is_timeout {
            anyhow::bail!("EAP session expired");
        }
        Ok(())
    }

    /// Parse uptime string like "0 days 00:03:46" into seconds.
    fn parse_uptime(s: &str) -> Option<u64> {
        // Format: "N days HH:MM:SS"
        let parts: Vec<&str> = s.splitn(2, " days ").collect();
        if parts.len() != 2 {
            return None;
        }
        let days: u64 = parts[0].trim().parse().ok()?;
        let hms: Vec<&str> = parts[1].split(':').collect();
        if hms.len() != 3 {
            return None;
        }
        let h: u64 = hms[0].parse().ok()?;
        let m: u64 = hms[1].parse().ok()?;
        let s: u64 = hms[2].parse().ok()?;
        Some(days * 86400 + h * 3600 + m * 60 + s)
    }

    /// Get SSIDs for a single radio.
    async fn get_ssids_for_radio(&self, radio_id: u8) -> Result<Vec<WifiSsidConfig>> {
        let data = self
            .post_data_read("wireless.ssids.json", &format!("radioID={}", radio_id))
            .await?;

        let arr = match data.as_array() {
            Some(a) => a,
            None => return Ok(vec![]),
        };

        let band = radio_id_to_band(radio_id as u64).to_string();
        let mut ssids = Vec::new();

        for entry in arr {
            let ssid_name = entry
                .get("ssidname")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let security_mode = entry.get("securityMode").and_then(|v| v.as_u64()).unwrap_or(0);
            let hidden = entry.get("ssidbcast").and_then(|v| v.as_u64()).unwrap_or(1) == 0;
            let vlan_id = entry
                .get("vlanid")
                .and_then(|v| v.as_u64())
                .filter(|&v| v > 0)
                .map(|v| v as u16);
            // key=1 means enabled (it's the SSID index, 0 would be unusual)
            let enabled = entry.get("key").and_then(|v| v.as_u64()).unwrap_or(1) > 0;

            let password = if security_mode == 1 {
                // PSK mode — password not returned by API for security
                entry
                    .get("psk_key")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            } else {
                None
            };

            ssids.push(WifiSsidConfig {
                ssid_name,
                password,
                band: band.clone(),
                vlan_id,
                hidden,
                enabled,
                security: security_mode_str(security_mode).to_string(),
            });
        }

        Ok(ssids)
    }

    // --- Inherent method implementations (delegated to by trait impls) ---

    async fn get_device_status(&self) -> Result<ApStatus> {
        let data = self.get_data_get("status.device.json").await?;

        let model = data.get("deviceModel").and_then(|v| v.as_str()).map(String::from);
        let firmware = data.get("firmwareVersion").and_then(|v| v.as_str()).map(String::from);
        let uptime = data
            .get("uptime")
            .and_then(|v| v.as_str())
            .and_then(Self::parse_uptime);

        Ok(ApStatus {
            model,
            firmware,
            uptime,
        })
    }

    async fn get_clients_impl(&self) -> Result<Vec<WifiClient>> {
        // status.client.user.json returns empty body when no clients
        let resp = self
            .client
            .get(format!(
                "{}/data/status.client.user.json?operation=read",
                self.base_url
            ))
            .send()
            .await?;

        let text = resp.text().await?;
        if text.trim().is_empty() {
            return Ok(vec![]);
        }

        let json: Value = serde_json::from_str(&text).context("client list not JSON")?;
        self.check_timeout(&json)?;

        let data = match json.get("data") {
            Some(d) => d,
            None => return Ok(vec![]),
        };

        let arr = match data.as_array() {
            Some(a) => a,
            None => return Ok(vec![]),
        };

        let ap_mac = self.mac.clone();
        let mut clients = Vec::new();

        for entry in arr {
            let mac = entry
                .get("MAC")
                .or(entry.get("mac"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .replace('-', ":");
            if mac.is_empty() {
                continue;
            }
            let ssid = entry
                .get("ssid")
                .or(entry.get("SSID"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let radio_id = entry
                .get("radioId")
                .or(entry.get("radioID"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let rssi = entry
                .get("rssi")
                .or(entry.get("RSSI"))
                .and_then(|v| v.as_i64())
                .map(|v| v as i32);
            let rx_rate = entry
                .get("rxRate")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            let tx_rate = entry
                .get("txRate")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            clients.push(WifiClient {
                mac,
                ap_mac: ap_mac.clone(),
                ssid,
                band: radio_id_to_band(radio_id).to_string(),
                rssi,
                rx_rate,
                tx_rate,
            });
        }

        Ok(clients)
    }

    async fn get_ssids_impl(&self) -> Result<Vec<WifiSsidConfig>> {
        // Fetch SSIDs for both radios (2.4GHz=0, 5GHz=1)
        let mut all = self.get_ssids_for_radio(0).await.unwrap_or_default();
        all.extend(self.get_ssids_for_radio(1).await.unwrap_or_default());
        Ok(all)
    }

    async fn set_ssid_impl(&self, config: &WifiSsidConfig) -> Result<()> {
        let radio_id = band_to_radio_id(&config.band)
            .ok_or_else(|| anyhow::anyhow!("unknown band: {}", config.band))?;

        // First read current SSIDs to find the index
        let data = self
            .post_data_read("wireless.ssids.json", &format!("radioID={}", radio_id))
            .await?;

        let empty = vec![];
        let arr = data.as_array().unwrap_or(&empty);

        // Find existing SSID by name or use first empty slot
        let mut ssid_index: Option<usize> = None;
        for (i, entry) in arr.iter().enumerate() {
            if entry.get("ssidname").and_then(|v| v.as_str()) == Some(&config.ssid_name) {
                ssid_index = Some(i);
                break;
            }
        }

        // Build write parameters
        let security_mode = match config.security.as_str() {
            "none" => 0,
            "wpa-psk" => 1,
            "wpa-enterprise" => 2,
            _ => 0,
        };

        let ssidbcast = if config.hidden { 0 } else { 1 };
        let vlanid = config.vlan_id.unwrap_or(0);

        let mut params = format!(
            "radioID={}&ssidname={}&securityMode={}&ssidbcast={}&vlanid={}&guest=0&portal=0",
            radio_id,
            urlencoding::encode(&config.ssid_name),
            security_mode,
            ssidbcast,
            vlanid
        );

        // Add PSK password if WPA-PSK
        if security_mode == 1 {
            if let Some(ref pw) = config.password {
                params.push_str(&format!("&psk_version=3&psk_cipher=3&psk_key={}", urlencoding::encode(pw)));
            }
        }

        // Add old name for editing existing SSID
        if let Some(idx) = ssid_index {
            if let Some(old_name) = arr[idx].get("ssidname").and_then(|v| v.as_str()) {
                params.push_str(&format!("&old_ssidname={}", urlencoding::encode(old_name)));
            }
        }

        self.post_data_write("wireless.ssids.json", &params).await?;
        Ok(())
    }

    async fn delete_ssid_impl(&self, ssid_name: &str, band: &str) -> Result<()> {
        let radio_id =
            band_to_radio_id(band).ok_or_else(|| anyhow::anyhow!("unknown band: {}", band))?;

        // The EAP720 doesn't have a direct "delete SSID" API — the first SSID per radio
        // cannot be deleted. Additional SSIDs can be removed via operation=remove.
        let params = format!(
            "radioID={}&operation=remove&ssidname={}",
            radio_id,
            urlencoding::encode(ssid_name)
        );

        let url = format!("{}/data/wireless.ssids.json", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body(params)
            .send()
            .await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        Ok(())
    }

    async fn get_radios_impl(&self) -> Result<Vec<WifiRadioConfig>> {
        let mut radios = Vec::new();

        for radio_id in [0u8, 1] {
            let data = self
                .get_data_get_radio("wireless.basic.json", radio_id)
                .await;

            if let Ok(data) = data {
                let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("off");
                let channel_val = data.get("channel").and_then(|v| v.as_u64()).unwrap_or(0);
                let chwidth_val = data.get("chwidth").and_then(|v| v.as_u64()).unwrap_or(0);
                let txpower = data.get("txpower").and_then(|v| v.as_u64()).unwrap_or(0);

                let channel_str = if channel_val == 0 {
                    "Auto".to_string()
                } else {
                    channel_val.to_string()
                };

                radios.push(WifiRadioConfig {
                    band: radio_id_to_band(radio_id as u64).to_string(),
                    channel: channel_str,
                    channel_width: channel_width_str(chwidth_val),
                    tx_power: format!("{}dBm", txpower),
                    enabled: status == "on",
                });
            }
        }

        Ok(radios)
    }

    async fn set_radio_impl(&self, config: &WifiRadioConfig) -> Result<()> {
        let radio_id = band_to_radio_id(&config.band)
            .ok_or_else(|| anyhow::anyhow!("unknown band: {}", config.band))?;

        let status = if config.enabled { "on" } else { "off" };

        let channel: u64 = if config.channel == "Auto" || config.channel == "auto" {
            0
        } else {
            config.channel.parse().unwrap_or(0)
        };

        let chwidth: u64 = match config.channel_width.as_str() {
            "20MHz" => 2,
            "40MHz" => 3,
            "80MHz" => 5,
            "Auto" | "auto" => 6,
            "160MHz" => 7,
            _ => 6,
        };

        let txpower: u64 = config
            .tx_power
            .trim_end_matches("dBm")
            .parse()
            .unwrap_or(25);

        let params = format!(
            "radioID={}&status={}&channel={}&chwidth={}&txpower={}",
            radio_id, status, channel, chwidth, txpower
        );

        self.post_data_write("wireless.basic.json", &params).await?;
        Ok(())
    }

    async fn kick_client_impl(&self, mac: &str) -> Result<()> {
        // The EAP720 doesn't expose a direct "deauth client" API in standalone mode.
        // The closest mechanism is adding the client to the MAC filter deny list temporarily,
        // which forces disconnection. For now, we use the MAC filter approach.
        // First block, then unblock after a brief moment to just kick.
        self.block_client_impl(mac).await?;
        // Give the AP a moment to disconnect the client
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        self.unblock_client_impl(mac).await?;
        Ok(())
    }

    async fn block_client_impl(&self, mac: &str) -> Result<()> {
        // Ensure MAC filtering is enabled in deny mode
        let filter_status = self.get_data_get("macFiltering.set.json").await?;
        let current_status = filter_status
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("off");

        if current_status == "off" {
            // Enable MAC filtering
            self.post_data_write("macFiltering.set.json", "status=on")
                .await?;
        }

        // Add MAC to deny list
        // Format MAC as XX-XX-XX-XX-XX-XX (TP-Link format)
        let tp_mac = mac.replace(':', "-").to_uppercase();
        let params = format!("mac={}", urlencoding::encode(&tp_mac));
        self.post_data_write("macFiltering.maclist.json", &params)
            .await?;

        // Associate the MAC list with all SSIDs in deny mode (action=1)
        // This is handled by the macFiltering.association endpoint
        Ok(())
    }

    async fn unblock_client_impl(&self, mac: &str) -> Result<()> {
        let tp_mac = mac.replace(':', "-").to_uppercase();

        // Remove MAC from the filter list
        let url = format!("{}/data/macFiltering.maclist.json", self.base_url);
        let body = format!("operation=remove&mac={}", urlencoding::encode(&tp_mac));
        let resp = self
            .client
            .post(&url)
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .body(body)
            .send()
            .await?;
        let json: Value = resp.json().await.context("not JSON")?;
        self.check_timeout(&json)?;
        Ok(())
    }
}

#[async_trait]
impl WifiProvider for EapSession {
    async fn list_devices(&self) -> Result<Vec<hermitshell_common::WifiDeviceInfo>> {
        let status = self.get_device_status().await?;
        Ok(vec![hermitshell_common::WifiDeviceInfo {
            mac: self.mac.clone(),
            ip: Some(self.ip.clone()),
            name: None,
            model: status.model,
            firmware: status.firmware,
            status: "online".to_string(),
            uptime: status.uptime,
        }])
    }

    async fn device(&self, ap_mac: &str) -> Result<Box<dyn WifiDevice>> {
        if ap_mac != self.mac {
            anyhow::bail!("EAP standalone provider only manages AP {}", self.mac);
        }
        Ok(Box::new(self.clone()))
    }

    async fn get_ssids(&self) -> Result<Vec<WifiSsidConfig>> {
        self.get_ssids_impl().await
    }

    async fn set_ssid(&self, config: &WifiSsidConfig) -> Result<()> {
        self.set_ssid_impl(config).await
    }

    async fn delete_ssid(&self, ssid_name: &str, band: &str) -> Result<()> {
        self.delete_ssid_impl(ssid_name, band).await
    }

    async fn kick_client(&self, mac: &str) -> Result<()> {
        self.kick_client_impl(mac).await
    }

    async fn block_client(&self, mac: &str) -> Result<()> {
        self.block_client_impl(mac).await
    }

    async fn unblock_client(&self, mac: &str) -> Result<()> {
        self.unblock_client_impl(mac).await
    }
}

#[async_trait]
impl WifiDevice for EapSession {
    async fn get_status(&self) -> Result<ApStatus> {
        self.get_device_status().await
    }

    async fn get_clients(&self) -> Result<Vec<WifiClient>> {
        self.get_clients_impl().await
    }

    async fn get_radios(&self) -> Result<Vec<WifiRadioConfig>> {
        self.get_radios_impl().await
    }

    async fn set_radio(&self, config: &WifiRadioConfig) -> Result<()> {
        self.set_radio_impl(config).await
    }
}

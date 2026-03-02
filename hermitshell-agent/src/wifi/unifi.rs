//! UniFi controller WiFi provider.
//!
//! Supports both UniFi OS (e.g. UDM, UDR, Cloud Key Gen2+) and legacy
//! controllers.  Auth can be via API key or username/password.  TOFU
//! certificate pinning follows the same pattern as the EAP720 provider.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use tracing::debug;

use hermitshell_common::{WifiClient, WifiRadioConfig, WifiSsidConfig};

use super::{ApStatus, WifiDevice, WifiProvider};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Whether the controller is a UniFi OS gateway (UDM, UDR, Cloud Key Gen2+)
/// or a standalone "legacy" controller (software install, Cloud Key Gen1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerKind {
    /// UniFi OS — all `/api/s/...` paths need a `/proxy/network` prefix.
    UnifiOs,
    /// Legacy controller — no path prefix.
    Legacy,
}

/// Shared mutable state behind an `Arc` so the session is `Clone + Send + Sync`.
struct Inner {
    csrf_token: Mutex<Option<String>>,
    /// Cache of AP MAC → UniFi `_id` for device-level REST calls.
    device_ids: Mutex<HashMap<String, String>>,
}

/// Session to a UniFi controller (or UniFi OS gateway).
#[derive(Clone)]
pub struct UnifiSession {
    client: reqwest::Client,
    base_url: String,
    site: String,
    kind: ControllerKind,
    inner: Arc<Inner>,
}

/// Per-AP handle returned by [`WifiProvider::device`].
pub struct UnifiDevice {
    session: UnifiSession,
    /// UniFi REST `_id` for this AP.
    device_id: String,
    /// Colon-separated MAC of this AP (lower-case).
    mac: String,
}

// ---------------------------------------------------------------------------
// Band / security / radio helpers
// ---------------------------------------------------------------------------

fn unifi_radio_to_band(r: &str) -> &'static str {
    match r {
        "ng" => "2.4GHz",
        "na" | "ac" => "5GHz",
        "6e" | "ax" => "6GHz",
        _ => "unknown",
    }
}

fn band_to_unifi_radio(b: &str) -> &'static str {
    match b {
        "2.4GHz" => "ng",
        "5GHz" => "na",
        "6GHz" => "6e",
        _ => "ng",
    }
}

fn unifi_security_to_ours(s: &str) -> &'static str {
    match s {
        "open" => "none",
        "wpapsk" | "wpa2psk" => "wpa-psk",
        "wpaeap" | "wpa2eap" => "wpa-enterprise",
        _ => "none",
    }
}

fn our_security_to_unifi(s: &str) -> &'static str {
    match s {
        "none" => "open",
        "wpa-psk" => "wpapsk",
        "wpa-enterprise" => "wpaeap",
        _ => "open",
    }
}

fn unifi_band_to_ours(b: &str) -> &'static str {
    match b {
        "2g" => "2.4GHz",
        "5g" => "5GHz",
        "6g" => "6GHz",
        "both" => "both",
        _ => "both",
    }
}

fn our_band_to_unifi(b: &str) -> &'static str {
    match b {
        "2.4GHz" => "2g",
        "5GHz" => "5g",
        "6GHz" => "6g",
        "both" => "both",
        _ => "both",
    }
}

/// Map UniFi `state` integer to a human-readable status.
fn device_state_str(state: i64) -> &'static str {
    match state {
        0 => "offline",
        1 => "online",
        2 => "pending",
        4 => "upgrading",
        5 => "provisioning",
        6 => "heartbeat-missed",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// UnifiSession — construction & helpers
// ---------------------------------------------------------------------------

impl UnifiSession {
    /// Establish a session to a UniFi controller.
    ///
    /// Returns `(session, tofu_cert_pem)`.  When `ca_cert_pem` is `None` the
    /// leaf certificate is grabbed via a bare TLS handshake (TOFU) and
    /// returned so the caller can persist it.
    pub async fn connect(
        url: &str,
        username: &str,
        password: &str,
        ca_cert_pem: Option<&str>,
        site: &str,
        api_key: Option<&str>,
    ) -> Result<(Self, Option<String>)> {
        // ---- TLS / client setup ----
        let parsed = reqwest::Url::parse(url).context("invalid UniFi URL")?;
        let host = parsed.host_str().context("URL has no host")?;
        let port = parsed.port().unwrap_or(443);

        let (client, tofu_pem) = if let Some(pem) = ca_cert_pem {
            let builder = crate::tls_client::builder_with_ca(Some(pem))?
                .cookie_store(true)
                .timeout(std::time::Duration::from_secs(15));
            (builder.build()?, None)
        } else {
            // TOFU: grab the leaf certificate, then build a client that trusts it.
            let pem = crate::tls_client::grab_leaf_cert(host, port)
                .await
                .context("TOFU: failed to grab UniFi certificate")?;
            let builder = crate::tls_client::builder_with_ca(Some(&pem))?
                .cookie_store(true)
                .timeout(std::time::Duration::from_secs(15));
            (builder.build()?, Some(pem))
        };

        let base_url = url.trim_end_matches('/').to_string();
        let inner = Arc::new(Inner {
            csrf_token: Mutex::new(None),
            device_ids: Mutex::new(HashMap::new()),
        });

        // ---- API key auth attempt ----
        if let Some(key) = api_key
            && !key.is_empty() {
                // Build a second client with the API key as default header.
                let key_client = {
                    let mut headers = HeaderMap::new();
                    headers.insert("X-API-KEY", HeaderValue::from_str(key)?);
                    if let Some(pem) = ca_cert_pem {
                        crate::tls_client::builder_with_ca(Some(pem))?
                    } else if let Some(ref pem) = tofu_pem {
                        crate::tls_client::builder_with_ca(Some(pem))?
                    } else {
                        reqwest::Client::builder()
                    }
                    .cookie_store(true)
                    .timeout(std::time::Duration::from_secs(15))
                    .default_headers(headers)
                    .build()?
                };

                // Probe — try UniFi OS path first, then legacy.
                for kind in [ControllerKind::UnifiOs, ControllerKind::Legacy] {
                    let prefix = match kind {
                        ControllerKind::UnifiOs => "/proxy/network",
                        ControllerKind::Legacy => "",
                    };
                    let probe_url = format!(
                        "{}{}/api/s/{}/stat/device-basic",
                        base_url, prefix, site
                    );
                    if let Ok(resp) = key_client.get(&probe_url).send().await
                        && resp.status().is_success() {
                            debug!(kind = ?kind, "UniFi API key auth succeeded");
                            return Ok((
                                Self {
                                    client: key_client,
                                    base_url,
                                    site: site.to_string(),
                                    kind,
                                    inner,
                                },
                                tofu_pem,
                            ));
                        }
                }
                debug!("API key auth failed, falling back to password");
            }

        // ---- Password auth ----
        let (kind, csrf) = Self::password_login(&client, &base_url, username, password).await?;

        {
            let mut tok = inner.csrf_token.lock().unwrap();
            *tok = csrf;
        }

        Ok((
            Self {
                client,
                base_url,
                site: site.to_string(),
                kind,
                inner,
            },
            tofu_pem,
        ))
    }

    /// Try UniFi OS login first, then legacy.  Returns `(kind, csrf_token)`.
    async fn password_login(
        client: &reqwest::Client,
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<(ControllerKind, Option<String>)> {
        // --- UniFi OS: POST /api/auth/login ---
        let os_url = format!("{}/api/auth/login", base_url);
        let body = json!({
            "username": username,
            "password": password,
            "rememberMe": true,
        });

        let resp = client
            .post(&os_url)
            .json(&body)
            .send()
            .await
            .context("UniFi OS login request failed")?;

        let status = resp.status();
        if status.is_success() {
            let csrf = Self::extract_csrf(&resp);
            debug!("UniFi OS login succeeded");
            return Ok((ControllerKind::UnifiOs, csrf));
        }

        if status.as_u16() != 404 {
            // Not a 404 — might be wrong credentials on UniFi OS.
            let body_text = resp.text().await.unwrap_or_default();
            anyhow::bail!("UniFi OS login failed ({}): {}", status, body_text);
        }

        // --- Legacy: POST /api/login ---
        let legacy_url = format!("{}/api/login", base_url);
        let body = json!({
            "username": username,
            "password": password,
            "remember": true,
        });

        let resp = client
            .post(&legacy_url)
            .json(&body)
            .send()
            .await
            .context("UniFi legacy login request failed")?;

        let status = resp.status();
        if status.is_success() {
            let csrf = Self::extract_csrf(&resp);
            debug!("UniFi legacy login succeeded");
            return Ok((ControllerKind::Legacy, csrf));
        }

        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("UniFi login failed ({}): {}", status, body_text);
    }

    /// Extract CSRF token from response headers.
    fn extract_csrf(resp: &reqwest::Response) -> Option<String> {
        resp.headers()
            .get("X-Csrf-Token")
            .or_else(|| resp.headers().get("X-Updated-Csrf-Token"))
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    }

    /// Build the full API URL, handling the UniFi OS `/proxy/network` prefix.
    fn api_url(&self, path: &str) -> String {
        let prefix = match self.kind {
            ControllerKind::UnifiOs => "/proxy/network",
            ControllerKind::Legacy => "",
        };
        format!("{}{}{}", self.base_url, prefix, path)
    }

    /// Build site-scoped URL: `/api/s/{site}/...`
    fn site_url(&self, suffix: &str) -> String {
        self.api_url(&format!("/api/s/{}/{}", self.site, suffix))
    }

    /// GET request, returning parsed JSON `data` array.
    async fn api_get(&self, url: &str) -> Result<Value> {
        let resp = self.client.get(url).send().await?;
        self.handle_response(resp).await
    }

    /// POST request with JSON body.
    async fn api_post(&self, url: &str, body: &Value) -> Result<Value> {
        let mut req = self.client.post(url).json(body);
        if let Some(ref tok) = *self.inner.csrf_token.lock().unwrap() {
            req = req.header("X-Csrf-Token", tok.as_str());
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// PUT request with JSON body.
    async fn api_put(&self, url: &str, body: &Value) -> Result<Value> {
        let mut req = self.client.put(url).json(body);
        if let Some(ref tok) = *self.inner.csrf_token.lock().unwrap() {
            req = req.header("X-Csrf-Token", tok.as_str());
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// DELETE request.
    async fn api_delete(&self, url: &str) -> Result<Value> {
        let mut req = self.client.delete(url);
        if let Some(ref tok) = *self.inner.csrf_token.lock().unwrap() {
            req = req.header("X-Csrf-Token", tok.as_str());
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Parse the standard UniFi JSON envelope `{"meta":{"rc":"ok"},"data":[...]}`.
    /// Updates stored CSRF token if a new one appears in the response.
    async fn handle_response(&self, resp: reqwest::Response) -> Result<Value> {
        // Capture updated CSRF token from any response.
        if let Some(tok) = Self::extract_csrf(&resp) {
            let mut stored = self.inner.csrf_token.lock().unwrap();
            *stored = Some(tok);
        }

        let status = resp.status();
        if status.as_u16() == 401 {
            anyhow::bail!("UniFi session expired (401)");
        }

        let body: Value = resp.json().await.context("UniFi response not JSON")?;

        // Check for error envelope.
        if let Some(meta) = body.get("meta") {
            let rc = meta.get("rc").and_then(|v| v.as_str()).unwrap_or("");
            if rc == "error" {
                let msg = meta
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                anyhow::bail!("UniFi API error: {}", msg);
            }
        }

        Ok(body.get("data").cloned().unwrap_or(Value::Array(vec![])))
    }

    /// Cache device MAC → `_id` mappings from a stat/device response.
    fn cache_device_ids(&self, data: &Value) {
        if let Some(arr) = data.as_array() {
            let mut ids = self.inner.device_ids.lock().unwrap();
            for dev in arr {
                if let (Some(mac), Some(id)) = (
                    dev.get("mac").and_then(|v| v.as_str()),
                    dev.get("_id").and_then(|v| v.as_str()),
                ) {
                    ids.insert(mac.to_lowercase(), id.to_string());
                }
            }
        }
    }

    /// Look up the cached `_id` for an AP MAC.
    fn get_device_id(&self, mac: &str) -> Option<String> {
        self.inner
            .device_ids
            .lock()
            .unwrap()
            .get(&mac.to_lowercase())
            .cloned()
    }

    /// POST to `/cmd/stamgr` with a station management command.
    async fn stamgr_cmd(&self, cmd: &str, mac: &str) -> Result<()> {
        let url = self.site_url("cmd/stamgr");
        self.api_post(&url, &json!({ "cmd": cmd, "mac": mac.to_lowercase() }))
            .await?;
        Ok(())
    }

    /// Fetch raw WLAN config list (`rest/wlanconf`).
    async fn get_wlanconf_raw(&self) -> Result<Vec<Value>> {
        let url = self.site_url("rest/wlanconf");
        let data = self.api_get(&url).await?;
        Ok(data.as_array().cloned().unwrap_or_default())
    }

    /// Fetch raw device list (`stat/device`).
    async fn get_stat_device(&self) -> Result<Value> {
        let url = self.site_url("stat/device");
        self.api_get(&url).await
    }
}

// ---------------------------------------------------------------------------
// WifiProvider
// ---------------------------------------------------------------------------

#[async_trait]
impl WifiProvider for UnifiSession {
    async fn list_devices(&self) -> Result<Vec<hermitshell_common::WifiDeviceInfo>> {
        let data = self.get_stat_device().await?;
        self.cache_device_ids(&data);

        let arr = data.as_array().context("stat/device not an array")?;

        let mut devices = Vec::new();
        for dev in arr {
            // Only include UAPs (access points).
            let dev_type = dev.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if dev_type != "uap" {
                continue;
            }

            let mac = dev
                .get("mac")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let ip = dev.get("ip").and_then(|v| v.as_str()).map(String::from);
            let name = dev.get("name").and_then(|v| v.as_str()).map(String::from);
            let model = dev.get("model").and_then(|v| v.as_str()).map(String::from);
            let firmware = dev
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from);
            let state = dev.get("state").and_then(|v| v.as_i64()).unwrap_or(0);
            let uptime = dev.get("uptime").and_then(|v| v.as_u64());

            devices.push(hermitshell_common::WifiDeviceInfo {
                mac,
                ip,
                name,
                model,
                firmware,
                status: device_state_str(state).to_string(),
                uptime,
            });
        }

        Ok(devices)
    }

    async fn device(&self, ap_mac: &str) -> Result<Box<dyn WifiDevice>> {
        let mac = ap_mac.to_lowercase();

        // Ensure we have a device_id cached.
        let device_id = match self.get_device_id(&mac) {
            Some(id) => id,
            None => {
                // Fetch device list to populate cache.
                let data = self.get_stat_device().await?;
                self.cache_device_ids(&data);
                self.get_device_id(&mac)
                    .ok_or_else(|| anyhow::anyhow!("AP {} not found on this controller", mac))?
            }
        };

        Ok(Box::new(UnifiDevice {
            session: self.clone(),
            device_id,
            mac,
        }))
    }

    async fn get_ssids(&self) -> Result<Vec<WifiSsidConfig>> {
        let entries = self.get_wlanconf_raw().await?;

        let mut ssids = Vec::new();
        for entry in &entries {
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let password = entry
                .get("x_passphrase")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            let wlan_band = entry
                .get("wlan_band")
                .and_then(|v| v.as_str())
                .unwrap_or("both");
            let hidden = entry
                .get("hide_ssid")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let enabled = entry
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let security_raw = entry
                .get("security")
                .and_then(|v| v.as_str())
                .unwrap_or("open");
            let vlan_enabled = entry
                .get("vlan_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let vlan_id = if vlan_enabled {
                entry
                    .get("vlan")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u16>().ok())
                    .or_else(|| {
                        entry
                            .get("vlan")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u16)
                    })
            } else {
                None
            };

            ssids.push(WifiSsidConfig {
                ssid_name: name,
                password,
                band: unifi_band_to_ours(wlan_band).to_string(),
                vlan_id,
                hidden,
                enabled,
                security: unifi_security_to_ours(security_raw).to_string(),
            });
        }

        Ok(ssids)
    }

    async fn set_ssid(&self, config: &WifiSsidConfig) -> Result<()> {
        let entries = self.get_wlanconf_raw().await?;

        // Check if an SSID with this name already exists.
        let existing = entries.iter().find(|e| {
            e.get("name")
                .and_then(|v| v.as_str())
                .map(|n| n == config.ssid_name)
                .unwrap_or(false)
        });

        let security = our_security_to_unifi(&config.security);
        let wlan_band = our_band_to_unifi(&config.band);

        let mut body = json!({
            "name": config.ssid_name,
            "enabled": config.enabled,
            "hide_ssid": config.hidden,
            "security": security,
            "wlan_band": wlan_band,
        });

        if let Some(ref pw) = config.password {
            body["x_passphrase"] = json!(pw);
        }

        if let Some(vlan) = config.vlan_id {
            body["vlan_enabled"] = json!(true);
            body["vlan"] = json!(vlan.to_string());
        }

        if let Some(existing) = existing {
            // Update existing SSID.
            let wlan_id = existing
                .get("_id")
                .and_then(|v| v.as_str())
                .context("existing SSID has no _id")?;
            let url = self.site_url(&format!("rest/wlanconf/{}", wlan_id));
            self.api_put(&url, &body).await?;
        } else {
            // Create new SSID.
            let url = self.site_url("add/wlanconf");
            self.api_post(&url, &body).await?;
        }

        Ok(())
    }

    async fn delete_ssid(&self, ssid_name: &str, _band: &str) -> Result<()> {
        let entries = self.get_wlanconf_raw().await?;

        let entry = entries
            .iter()
            .find(|e| {
                e.get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| n == ssid_name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| anyhow::anyhow!("SSID '{}' not found", ssid_name))?;

        let wlan_id = entry
            .get("_id")
            .and_then(|v| v.as_str())
            .context("SSID entry has no _id")?;

        let url = self.site_url(&format!("rest/wlanconf/{}", wlan_id));
        self.api_delete(&url).await?;

        Ok(())
    }

    async fn kick_client(&self, mac: &str) -> Result<()> {
        self.stamgr_cmd("kick-sta", mac).await
    }

    async fn block_client(&self, mac: &str) -> Result<()> {
        self.stamgr_cmd("block-sta", mac).await
    }

    async fn unblock_client(&self, mac: &str) -> Result<()> {
        self.stamgr_cmd("unblock-sta", mac).await
    }
}

// ---------------------------------------------------------------------------
// WifiDevice (UnifiDevice)
// ---------------------------------------------------------------------------

impl UnifiDevice {
    /// Fetch this AP's full device record from stat/device.
    async fn fetch_device(&self) -> Result<Value> {
        let url = self.session.site_url(&format!("stat/device/{}", self.mac));
        let data = self.session.api_get(&url).await?;
        let arr = data.as_array().context("stat/device response not array")?;
        arr.first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("AP {} not found", self.mac))
    }
}

#[async_trait]
impl WifiDevice for UnifiDevice {
    async fn get_status(&self) -> Result<ApStatus> {
        let dev = self.fetch_device().await?;

        let model = dev.get("model").and_then(|v| v.as_str()).map(String::from);
        let firmware = dev
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);
        let uptime = dev.get("uptime").and_then(|v| v.as_u64());

        Ok(ApStatus {
            model,
            firmware,
            uptime,
        })
    }

    async fn get_clients(&self) -> Result<Vec<WifiClient>> {
        let url = self.session.site_url("stat/sta");
        let data = self.session.api_get(&url).await?;
        let arr = data.as_array().context("stat/sta not an array")?;

        let mut clients = Vec::new();
        for sta in arr {
            let ap_mac = sta
                .get("ap_mac")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if ap_mac != self.mac {
                continue;
            }

            let mac = sta
                .get("mac")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if mac.is_empty() {
                continue;
            }

            let ssid = sta
                .get("essid")
                .or_else(|| sta.get("bssid"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let radio = sta
                .get("radio")
                .and_then(|v| v.as_str())
                .unwrap_or("ng");
            let band = unifi_radio_to_band(radio).to_string();

            let rssi = sta
                .get("rssi")
                .or_else(|| sta.get("signal"))
                .and_then(|v| v.as_i64())
                .map(|v| v as i32);

            // UniFi reports rates in bps; convert to Mbps for our wire type.
            let tx_rate = sta
                .get("tx_rate")
                .and_then(|v| v.as_u64())
                .map(|v| (v / 1000) as u32);
            let rx_rate = sta
                .get("rx_rate")
                .and_then(|v| v.as_u64())
                .map(|v| (v / 1000) as u32);

            clients.push(WifiClient {
                mac,
                ap_mac: ap_mac.clone(),
                ssid,
                band,
                rssi,
                rx_rate,
                tx_rate,
            });
        }

        Ok(clients)
    }

    async fn get_radios(&self) -> Result<Vec<WifiRadioConfig>> {
        let dev = self.fetch_device().await?;
        let radio_table = dev
            .get("radio_table")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut radios = Vec::new();
        for entry in &radio_table {
            let radio = entry
                .get("radio")
                .and_then(|v| v.as_str())
                .unwrap_or("ng");
            let band = unifi_radio_to_band(radio).to_string();

            let channel = entry
                .get("channel")
                .and_then(|v| match v {
                    Value::Number(n) => n.as_u64().map(|c| {
                        if c == 0 {
                            "Auto".to_string()
                        } else {
                            c.to_string()
                        }
                    }),
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Auto".to_string());

            let ht = entry
                .get("ht")
                .and_then(|v| v.as_str())
                .or_else(|| entry.get("ht").and_then(|v| v.as_u64()).map(|_| "20"))
                .unwrap_or("20");
            let channel_width = format!("{}MHz", ht);

            let tx_power = entry
                .get("tx_power")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    entry
                        .get("tx_power_mode")
                        .and_then(|v| v.as_str())
                        .and_then(|m| if m == "auto" { Some(0) } else { None })
                })
                .map(|v| format!("{}dBm", v))
                .unwrap_or_else(|| "auto".to_string());

            radios.push(WifiRadioConfig {
                band,
                channel,
                channel_width,
                tx_power,
                enabled: true, // present in radio_table → enabled
            });
        }

        Ok(radios)
    }

    async fn set_radio(&self, config: &WifiRadioConfig) -> Result<()> {
        // Fetch current device to get full radio_table.
        let dev = self.fetch_device().await?;
        let mut radio_table = dev
            .get("radio_table")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let target_radio = band_to_unifi_radio(&config.band);

        // Find the radio entry to update.
        let idx = radio_table
            .iter()
            .position(|e| {
                e.get("radio")
                    .and_then(|v| v.as_str())
                    .map(|r| r == target_radio)
                    .unwrap_or(false)
            })
            .ok_or_else(|| anyhow::anyhow!("radio {} not found on AP {}", config.band, self.mac))?;

        let entry = &mut radio_table[idx];

        // Update channel.
        let channel: u64 = if config.channel == "Auto" || config.channel == "auto" {
            0
        } else {
            config.channel.parse().unwrap_or(0)
        };
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("channel".to_string(), json!(channel));
        }

        // Update channel width (strip "MHz" suffix).
        let ht = config
            .channel_width
            .trim_end_matches("MHz")
            .trim_end_matches("mhz");
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("ht".to_string(), json!(ht));
        }

        // Update tx_power.
        let tx_power_str = config.tx_power.trim_end_matches("dBm").trim_end_matches("dbm");
        if tx_power_str == "auto" || tx_power_str == "0" {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("tx_power_mode".to_string(), json!("auto"));
                obj.remove("tx_power");
            }
        } else if let Ok(tp) = tx_power_str.parse::<u64>()
            && let Some(obj) = entry.as_object_mut() {
                obj.insert("tx_power_mode".to_string(), json!("custom"));
                obj.insert("tx_power".to_string(), json!(tp));
            }

        // PUT the full radio_table back.
        let url = self
            .session
            .site_url(&format!("rest/device/{}", self.device_id));
        let body = json!({ "radio_table": radio_table });
        self.session.api_put(&url, &body).await?;

        Ok(())
    }
}

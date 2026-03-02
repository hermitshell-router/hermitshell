use super::*;
use zeroize::Zeroizing;

/// Validate a PEM-encoded CA certificate string. Returns error message on failure.
pub(super) fn validate_ca_cert_pem_str(pem: &str) -> Result<(), String> {
    validate_ca_cert_pem(pem)
}

fn validate_ca_cert_pem(pem: &str) -> Result<(), String> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect();
    if certs.is_empty() {
        return Err("no certificate found in PEM data".to_string());
    }
    if let Some(Err(e)) = certs.iter().find(|c| c.is_err()) {
        return Err(format!("invalid PEM certificate: {}", e));
    }
    Ok(())
}

pub(super) fn handle_wifi_list_aps(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_wifi_aps() {
        Ok(aps) => {
            let mut resp = Response::ok();
            resp.wifi_aps = Some(aps);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_wifi_list_providers(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_wifi_providers() {
        Ok(providers) => {
            let mut resp = Response::ok();
            resp.wifi_providers = Some(providers);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_wifi_add_provider(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let Some(ref url) = req.url else {
        return Response::err("url required");
    };
    let Some(ref password) = req.value else {
        return Response::err("value required (password)");
    };
    if password.is_empty() {
        return Response::err("password cannot be empty");
    }
    let username = req.key.as_deref().unwrap_or("admin");
    let provider_type = req.protocol.as_deref().unwrap_or("eap_standalone");

    // Validate provider type
    let valid_types = ["eap_standalone", "unifi"];
    if !valid_types.contains(&provider_type) {
        return Response::err("provider_type must be eap_standalone or unifi");
    }

    // Validate name: 1-64 alphanumeric (+ - _ . space)
    if name.is_empty() || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Response::err("name must be 1-64 alphanumeric characters (plus - _ . space)");
    }

    // Type-specific validation
    match provider_type {
        "eap_standalone" => {
            // URL must be a valid IP
            if url.parse::<std::net::IpAddr>().is_err() {
                return Response::err("url must be a valid IP address for eap_standalone");
            }
            // MAC is required for eap_standalone
            if req.mac.is_none() {
                return Response::err("mac required for eap_standalone provider");
            }
        }
        "unifi" => {
            // URL must be a valid https URL
            match reqwest::Url::parse(url) {
                Ok(parsed) if parsed.scheme() == "https" => {}
                Ok(_) => return Response::err("url must use https:// for unifi"),
                Err(_) => return Response::err("url must be a valid URL (https://...) for unifi"),
            }
            // Validate site if provided
            if let Some(ref site) = req.site
                && (site.is_empty() || site.len() > 64
                    || !site.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            {
                    return Response::err("site must be 1-64 alphanumeric characters (plus - _)");
                }
        }
        _ => {}
    }

    // Encrypt password
    let session_secret = Zeroizing::new({
        let db_locked = db.lock().unwrap();
        db_locked.get_config("session_secret").ok().flatten()
            .unwrap_or_default()
    });
    let password_enc = if session_secret.is_empty() {
        password.clone()
    } else {
        match crate::crypto::encrypt_password(password, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    // Encrypt API key if provided
    let api_key_enc = req.api_key.as_ref().and_then(|key| {
        if key.is_empty() { return None; }
        if session_secret.is_empty() {
            Some(key.clone())
        } else {
            crate::crypto::encrypt_password(key, &session_secret).ok()
        }
    });

    let provider_id = uuid::Uuid::new_v4().to_string();
    let site = req.site.as_deref();

    let db = db.lock().unwrap();
    if let Err(e) = db.insert_wifi_provider(
        &provider_id, provider_type, name, url, username, &password_enc,
        site, api_key_enc.as_deref(),
    ) {
        return Response::err(&format!("failed to add provider: {}", e));
    }

    // Store CA cert if provided
    if let Some(ref ca_cert) = req.ca_cert
        && !ca_cert.is_empty() {
            if let Err(msg) = validate_ca_cert_pem(ca_cert) {
                let _ = db.remove_wifi_provider(&provider_id);
                return Response::err(&msg);
            }
            let _ = db.set_wifi_provider_ca_cert(&provider_id, Some(ca_cert));
        }

    // For eap_standalone, insert the initial AP record
    if provider_type == "eap_standalone"
        && let Some(ref mac) = req.mac {
            let _ = db.insert_wifi_ap_for_provider(mac, &provider_id, url, name);
        }

    let _ = db.log_audit("wifi_add_provider", &format!("added {} provider {}", provider_type, name));
    Response::ok()
}

pub(super) fn handle_wifi_remove_provider(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let db = db.lock().unwrap();
    if let Err(e) = db.remove_wifi_provider(provider_id) {
        return Response::err(&format!("failed to remove provider: {}", e));
    }
    let _ = db.log_audit("wifi_remove_provider", &format!("removed provider {}", provider_id));
    Response::ok()
}

pub(super) fn handle_wifi_set_provider_ca_cert(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let db = db.lock().unwrap();

    // Check provider exists
    match db.get_wifi_provider(provider_id) {
        Ok(Some(_)) => {}
        Ok(None) => return Response::err("provider not found"),
        Err(e) => return Response::err(&format!("DB error: {}", e)),
    }

    // Empty or missing value clears the CA cert
    let ca_cert = req.value.as_deref().unwrap_or("");
    if ca_cert.is_empty() {
        let _ = db.set_wifi_provider_ca_cert(provider_id, None);
        let _ = db.log_audit("wifi_set_provider_ca_cert", &format!("cleared CA cert for provider {}", provider_id));
        return Response::ok();
    }

    if let Err(msg) = validate_ca_cert_pem(ca_cert) {
        return Response::err(&msg);
    }
    let _ = db.set_wifi_provider_ca_cert(provider_id, Some(ca_cert));
    let _ = db.log_audit("wifi_set_provider_ca_cert", &format!("set CA cert for provider {}", provider_id));
    Response::ok()
}

pub(super) fn handle_wifi_get_clients(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    // Return devices that have wifi_ap_mac set (i.e., seen on WiFi)
    let db = db.lock().unwrap();
    match db.list_devices() {
        Ok(devices) => {
            let wifi_devices: Vec<_> = devices.into_iter()
                .filter(|d| d.wifi_ap_mac.is_some())
                .collect();
            let clients: Vec<hermitshell_common::WifiClient> = wifi_devices.iter().map(|d| {
                hermitshell_common::WifiClient {
                    mac: d.mac.clone(),
                    ap_mac: d.wifi_ap_mac.clone().unwrap_or_default(),
                    ssid: d.wifi_ssid.clone().unwrap_or_default(),
                    band: d.wifi_band.clone().unwrap_or_default(),
                    rssi: d.wifi_rssi,
                    rx_rate: None,
                    tx_rate: None,
                }
            }).collect();
            let mut resp = Response::ok();
            resp.wifi_clients = Some(clients);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

/// Async handler for WiFi methods that require provider/AP communication.
pub(super) async fn handle_wifi_async(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    match req.method.as_str() {
        "wifi_get_ssids" => handle_wifi_get_ssids(req, db).await,
        "wifi_set_ssid" => handle_wifi_set_ssid(req, db).await,
        "wifi_delete_ssid" => handle_wifi_delete_ssid(req, db).await,
        "wifi_get_radios" => handle_wifi_get_radios(req, db).await,
        "wifi_set_radio" => handle_wifi_set_radio(req, db).await,
        "wifi_set_ssid_vlan" => handle_wifi_set_ssid_vlan(req, db).await,
        "wifi_get_ssid_vlans" => handle_wifi_get_ssid_vlans(req, db).await,
        _ => Response::err("unknown wifi method"),
    }
}

/// Helper: connect to a provider by provider_id, looking up credentials from DB.
/// If a TOFU cert is captured (first connection without CA), saves it.
async fn connect_to_provider(provider_id: &str, db: &Arc<Mutex<Db>>) -> Result<Box<dyn crate::wifi::WifiProvider>, Response> {
    let (provider_type, url, username, password_enc, site, api_key_enc, ca_cert_pem) = {
        let db = db.lock().unwrap();
        let creds = match db.get_wifi_provider_credentials(provider_id) {
            Ok(Some(creds)) => creds,
            Ok(None) => return Err(Response::err("provider not found")),
            Err(e) => return Err(Response::err(&format!("DB error: {}", e))),
        };
        let ca_cert = db.get_wifi_provider_ca_cert(provider_id).ok().flatten();
        (creds.0, creds.1, creds.2, creds.3, creds.4, creds.5, ca_cert)
    };

    // Decrypt password
    let password: Zeroizing<String> = {
        let session_secret = Zeroizing::new({
            let db = db.lock().unwrap();
            db.get_config("session_secret").ok().flatten().unwrap_or_default()
        });
        if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
            Zeroizing::new(password_enc)
        } else {
            match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                Ok(p) => Zeroizing::new(p),
                Err(e) => return Err(Response::err(&format!("decrypt failed: {}", e))),
            }
        }
    };

    // Decrypt API key if present
    let api_key: Option<Zeroizing<String>> = api_key_enc.and_then(|enc| {
        if enc.is_empty() { return None; }
        let session_secret = Zeroizing::new({
            let db = db.lock().unwrap();
            db.get_config("session_secret").ok().flatten().unwrap_or_default()
        });
        if session_secret.is_empty() || !crate::crypto::is_encrypted(&enc) {
            Some(Zeroizing::new(enc))
        } else {
            crate::crypto::decrypt_password(&enc, &session_secret).ok().map(Zeroizing::new)
        }
    });

    match crate::wifi::connect(
        &provider_type, &url, &username, &password,
        ca_cert_pem.as_deref(), site.as_deref(), api_key.as_ref().map(|k| k.as_str()),
    ).await {
        Ok((provider, tofu_pem)) => {
            // Save TOFU cert if captured
            if let Some(ref pem) = tofu_pem {
                let db = db.lock().unwrap();
                let _ = db.set_wifi_provider_ca_cert(provider_id, Some(pem));
            }
            Ok(provider)
        }
        Err(e) => Err(Response::err(&format!("provider connection failed: {}", e))),
    }
}

/// Helper: for per-AP operations, look up the AP's provider_id and connect.
async fn connect_to_ap_device(mac: &str, db: &Arc<Mutex<Db>>) -> Result<Box<dyn crate::wifi::WifiDevice>, Response> {
    let provider_id = {
        let db = db.lock().unwrap();
        match db.get_wifi_ap_provider_id(mac) {
            Ok(Some(id)) => id,
            Ok(None) => return Err(Response::err("AP not found")),
            Err(e) => return Err(Response::err(&format!("DB error: {}", e))),
        }
    };

    let provider = connect_to_provider(&provider_id, db).await?;
    match provider.device(mac).await {
        Ok(device) => Ok(device),
        Err(e) => Err(Response::err(&format!("failed to get device handle: {}", e))),
    }
}

async fn handle_wifi_get_ssids(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.get_ssids().await {
        Ok(ssids) => {
            let mut resp = Response::ok();
            resp.wifi_ssids = Some(ssids);
            resp
        }
        Err(e) => Response::err(&format!("get_ssids failed: {}", e)),
    }
}

async fn handle_wifi_set_ssid(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref ssid_name) = req.ssid_name else {
        return Response::err("ssid_name required");
    };
    let Some(ref band) = req.band else {
        return Response::err("band required");
    };

    if !["2.4GHz", "5GHz", "5GHz-2", "6GHz"].contains(&band.as_str()) {
        return Response::err("band must be 2.4GHz, 5GHz, 5GHz-2, or 6GHz");
    }
    if ssid_name.is_empty() || ssid_name.len() > 32 {
        return Response::err("ssid_name must be 1-32 characters");
    }

    let security = req.security.as_deref().unwrap_or("wpa-psk");
    if !["none", "wpa-psk", "wpa-enterprise"].contains(&security) {
        return Response::err("security must be none, wpa-psk, or wpa-enterprise");
    }

    if security == "wpa-psk" {
        match req.value {
            Some(ref pw) if pw.len() >= 8 && pw.len() <= 63 && pw.is_ascii() => {}
            Some(_) => return Response::err("WPA-PSK password must be 8-63 ASCII characters"),
            None => return Response::err("password required for WPA-PSK security"),
        }
    }

    let config = hermitshell_common::WifiSsidConfig {
        ssid_name: ssid_name.clone(),
        password: req.value.clone(),
        band: band.clone(),
        vlan_id: req.vlan_id,
        hidden: req.hidden.unwrap_or(false),
        enabled: req.enabled.unwrap_or(true),
        security: security.to_string(),
    };

    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.set_ssid(&config).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_set_ssid", &format!("{} on provider {}", ssid_name, provider_id));
            Response::ok()
        }
        Err(e) => Response::err(&format!("set_ssid failed: {}", e)),
    }
}

async fn handle_wifi_delete_ssid(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref ssid_name) = req.ssid_name else {
        return Response::err("ssid_name required");
    };
    let Some(ref band) = req.band else {
        return Response::err("band required");
    };

    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.delete_ssid(ssid_name, band).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_delete_ssid", &format!("{} on provider {}", ssid_name, provider_id));
            Response::ok()
        }
        Err(e) => Response::err(&format!("delete_ssid failed: {}", e)),
    }
}

async fn handle_wifi_get_radios(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let device = match connect_to_ap_device(mac, db).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    match device.get_radios().await {
        Ok(radios) => {
            let mut resp = Response::ok();
            resp.wifi_radios = Some(radios);
            resp
        }
        Err(e) => Response::err(&format!("get_radios failed: {}", e)),
    }
}

async fn handle_wifi_set_radio(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let Some(ref band) = req.band else {
        return Response::err("band required");
    };
    if !["2.4GHz", "5GHz", "5GHz-2", "6GHz"].contains(&band.as_str()) {
        return Response::err("band must be 2.4GHz, 5GHz, 5GHz-2, or 6GHz");
    }

    let config = hermitshell_common::WifiRadioConfig {
        band: band.clone(),
        channel: req.channel.clone().unwrap_or_else(|| "Auto".to_string()),
        channel_width: req.channel_width.clone().unwrap_or_else(|| "Auto".to_string()),
        tx_power: req.tx_power.clone().unwrap_or_else(|| "25dBm".to_string()),
        enabled: req.enabled.unwrap_or(true),
    };

    let device = match connect_to_ap_device(mac, db).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    match device.set_radio(&config).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_set_radio", &format!("{} on {}", band, mac));
            Response::ok()
        }
        Err(e) => Response::err(&format!("set_radio failed: {}", e)),
    }
}

async fn handle_wifi_set_ssid_vlan(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref ssid_name) = req.ssid_name else {
        return Response::err("ssid_name required");
    };
    // vlan_id can be None (to remove VLAN tagging) or Some(id) to set it
    let vlan_id = req.vlan_id;

    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Get current SSIDs to find the one to modify
    let ssids = match provider.get_ssids().await {
        Ok(s) => s,
        Err(e) => return Response::err(&format!("get_ssids failed: {}", e)),
    };

    let Some(mut config) = ssids.into_iter().find(|s| s.ssid_name == *ssid_name) else {
        return Response::err(&format!("SSID '{}' not found", ssid_name));
    };

    config.vlan_id = vlan_id;

    match provider.set_ssid(&config).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_set_ssid_vlan", &format!("{} vlan={:?} on provider {}", ssid_name, vlan_id, provider_id));
            Response::ok()
        }
        Err(e) => Response::err(&format!("set_ssid_vlan failed: {}", e)),
    }
}

async fn handle_wifi_get_ssid_vlans(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let providers = {
        let db = db.lock().unwrap();
        db.list_wifi_providers().unwrap_or_default()
    };

    let mut results = Vec::new();
    for pinfo in &providers {
        if !pinfo.enabled { continue; }
        let provider = match connect_to_provider(&pinfo.id, db).await {
            Ok(p) => p,
            Err(_) => continue,
        };
        match provider.get_ssids().await {
            Ok(ssids) => {
                for ssid in &ssids {
                    results.push(serde_json::json!({
                        "provider_id": pinfo.id,
                        "provider_name": pinfo.name,
                        "ssid_name": ssid.ssid_name,
                        "band": ssid.band,
                        "vlan_id": ssid.vlan_id,
                    }));
                }
            }
            Err(_) => continue,
        }
    }

    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::to_string(&results).unwrap_or_default());
    resp
}

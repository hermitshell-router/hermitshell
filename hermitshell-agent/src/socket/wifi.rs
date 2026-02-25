use super::*;

/// Validate a PEM-encoded CA certificate string. Returns error message on failure.
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

pub(super) fn handle_wifi_adopt_ap(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let Some(ref ip) = req.url else {
        return Response::err("url required (AP IP address)");
    };
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let username = req.key.as_deref().unwrap_or("admin");
    let Some(ref password) = req.value else {
        return Response::err("value required (AP password)");
    };
    if password.is_empty() {
        return Response::err("password cannot be empty");
    }
    let provider = req.protocol.as_deref().unwrap_or("eap_standalone");

    // Validate inputs
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Response::err("url must be a valid IP address");
    }
    if name.is_empty() || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Response::err("name must be 1-64 alphanumeric characters (plus - _ . space)");
    }
    let valid_providers = ["eap_standalone"];
    if !valid_providers.contains(&provider) {
        return Response::err("unknown provider");
    }

    let session_secret = {
        let db_locked = db.lock().unwrap();
        db_locked.get_config("session_secret").ok().flatten()
            .unwrap_or_default()
    };
    let password_enc = if session_secret.is_empty() {
        password.clone()
    } else {
        match crate::crypto::encrypt_password(password, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let db = db.lock().unwrap();
    if let Err(e) = db.insert_wifi_ap(mac, ip, name, provider, username, &password_enc) {
        return Response::err(&format!("failed to adopt AP: {}", e));
    }

    // Store CA cert if provided
    if let Some(ref ca_cert) = req.ca_cert {
        if !ca_cert.is_empty() {
            if let Err(msg) = validate_ca_cert_pem(ca_cert) {
                // Roll back: remove the AP we just inserted
                let _ = db.remove_wifi_ap(mac);
                return Response::err(&msg);
            }
            let _ = db.set_wifi_ap_ca_cert(mac, Some(ca_cert));
        }
    }

    let _ = db.log_audit("wifi_adopt_ap", &format!("adopted {} ({})", name, mac));
    Response::ok()
}

pub(super) fn handle_wifi_remove_ap(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    if let Err(e) = db.remove_wifi_ap(mac) {
        return Response::err(&format!("failed to remove AP: {}", e));
    }
    let _ = db.log_audit("wifi_remove_ap", &format!("removed AP {}", mac));
    Response::ok()
}

pub(super) fn handle_wifi_set_ap_ca_cert(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();

    // Check AP exists
    match db.get_wifi_ap(mac) {
        Ok(Some(_)) => {}
        Ok(None) => return Response::err("AP not found"),
        Err(e) => return Response::err(&format!("DB error: {}", e)),
    }

    // Empty or missing value clears the CA cert
    let ca_cert = req.value.as_deref().unwrap_or("");
    if ca_cert.is_empty() {
        let _ = db.set_wifi_ap_ca_cert(mac, None);
        let _ = db.log_audit("wifi_set_ap_ca_cert", &format!("cleared CA cert for {}", mac));
        return Response::ok();
    }

    if let Err(msg) = validate_ca_cert_pem(ca_cert) {
        return Response::err(&msg);
    }
    let _ = db.set_wifi_ap_ca_cert(mac, Some(ca_cert));
    let _ = db.log_audit("wifi_set_ap_ca_cert", &format!("set CA cert for {}", mac));
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

/// Async handler for WiFi methods that require AP communication.
pub(super) async fn handle_wifi_async(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    match req.method.as_str() {
        "wifi_get_ssids" => handle_wifi_get_ssids(req, db).await,
        "wifi_set_ssid" => handle_wifi_set_ssid(req, db).await,
        "wifi_delete_ssid" => handle_wifi_delete_ssid(req, db).await,
        "wifi_get_radios" => handle_wifi_get_radios(req, db).await,
        "wifi_set_radio" => handle_wifi_set_radio(req, db).await,
        _ => Response::err("unknown wifi method"),
    }
}

/// Helper: connect to an AP by MAC, looking up credentials from DB.
async fn connect_to_ap(mac: &str, db: &Arc<Mutex<Db>>) -> Result<Box<dyn crate::wifi::WifiSession>, Response> {
    let (ip, username, password_enc, ca_cert_pem) = {
        let db = db.lock().unwrap();
        let creds = match db.get_wifi_ap_credentials(mac) {
            Ok(Some(creds)) => creds,
            Ok(None) => return Err(Response::err("AP not found")),
            Err(e) => return Err(Response::err(&format!("DB error: {}", e))),
        };
        let ca_cert = db.get_wifi_ap_ca_cert(mac).ok().flatten();
        (creds.0, creds.1, creds.2, ca_cert)
    };

    // Decrypt password
    let password = {
        let session_secret = {
            let db = db.lock().unwrap();
            db.get_config("session_secret").ok().flatten().unwrap_or_default()
        };
        if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
            password_enc
        } else {
            match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                Ok(p) => p,
                Err(e) => return Err(Response::err(&format!("decrypt failed: {}", e))),
            }
        }
    };

    let provider = {
        let db = db.lock().unwrap();
        db.get_wifi_ap(mac).ok().flatten()
            .map(|ap| ap.provider)
            .unwrap_or_else(|| "eap_standalone".to_string())
    };

    match crate::wifi::connect(&provider, &ip, &username, &password, ca_cert_pem.as_deref()).await {
        Ok(session) => Ok(session),
        Err(e) => Err(Response::err(&format!("AP connection failed: {}", e))),
    }
}

async fn handle_wifi_get_ssids(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let session = match connect_to_ap(mac, db).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match session.get_ssids().await {
        Ok(ssids) => {
            let mut resp = Response::ok();
            resp.wifi_ssids = Some(ssids);
            resp
        }
        Err(e) => Response::err(&format!("get_ssids failed: {}", e)),
    }
}

async fn handle_wifi_set_ssid(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
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
        vlan_id: None,
        hidden: req.hidden.unwrap_or(false),
        enabled: req.enabled.unwrap_or(true),
        security: security.to_string(),
    };

    let session = match connect_to_ap(mac, db).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match session.set_ssid(&config).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_set_ssid", &format!("{} on {}", ssid_name, mac));
            Response::ok()
        }
        Err(e) => Response::err(&format!("set_ssid failed: {}", e)),
    }
}

async fn handle_wifi_delete_ssid(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let Some(ref ssid_name) = req.ssid_name else {
        return Response::err("ssid_name required");
    };
    let Some(ref band) = req.band else {
        return Response::err("band required");
    };

    let session = match connect_to_ap(mac, db).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match session.delete_ssid(ssid_name, band).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_delete_ssid", &format!("{} on {}", ssid_name, mac));
            Response::ok()
        }
        Err(e) => Response::err(&format!("delete_ssid failed: {}", e)),
    }
}

async fn handle_wifi_get_radios(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let session = match connect_to_ap(mac, db).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match session.get_radios().await {
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

    let session = match connect_to_ap(mac, db).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match session.set_radio(&config).await {
        Ok(()) => {
            let db = db.lock().unwrap();
            let _ = db.log_audit("wifi_set_radio", &format!("{} on {}", band, mac));
            Response::ok()
        }
        Err(e) => Response::err(&format!("set_radio failed: {}", e)),
    }
}

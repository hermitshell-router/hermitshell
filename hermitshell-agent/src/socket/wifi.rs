use super::*;

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

    // TODO: encrypt password before storing
    let password_enc = password.clone();

    let db = db.lock().unwrap();
    if let Err(e) = db.insert_wifi_ap(mac, ip, name, provider, username, &password_enc) {
        return Response::err(&format!("failed to adopt AP: {}", e));
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

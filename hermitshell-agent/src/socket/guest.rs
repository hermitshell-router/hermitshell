use std::sync::{Arc, Mutex};

use rand::Rng;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::db::Db;
use super::{Request, Response};

/// Synchronous handler: return current guest network config.
pub(super) fn handle_guest_network_status(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();

    let config = match db_guard.get_guest_network() {
        Ok(Some(c)) => c,
        Ok(None) => {
            let mut resp = Response::ok();
            resp.config_value = Some(serde_json::json!({"enabled": false}).to_string());
            return resp;
        }
        Err(e) => return Response::err(&format!("failed to get guest network config: {}", e)),
    };

    // Decrypt password for response
    let session_secret = Zeroizing::new(
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    );
    let password = if session_secret.is_empty() || !crate::crypto::is_encrypted(&config.password_enc) {
        config.password_enc.clone()
    } else {
        match crate::crypto::decrypt_password(&config.password_enc, &session_secret) {
            Ok(p) => p,
            Err(e) => return Response::err(&format!("failed to decrypt password: {}", e)),
        }
    };

    // Count devices in "guest" group connected via the guest SSID
    let ssid = config.ssid_name.clone();
    let guest_count = db_guard.list_devices()
        .map(|devs| devs.iter().filter(|d| {
            d.device_group == "guest"
                && d.wifi_ssid.as_deref() == Some(ssid.as_str())
        }).count())
        .unwrap_or(0);

    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::json!({
        "enabled": config.enabled,
        "ssid_name": config.ssid_name,
        "password": password,
        "band": config.band,
        "provider_id": config.provider_id,
        "guest_count": guest_count,
    }).to_string());
    resp
}

/// Async handler dispatcher for guest network methods.
pub(super) async fn handle_guest_network_async(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    match req.method.as_str() {
        "guest_network_enable" => handle_guest_network_enable(req, db).await,
        "guest_network_disable" => handle_guest_network_disable(req, db).await,
        "guest_network_update" => handle_guest_network_update(req, db).await,
        "guest_network_regenerate_password" => handle_guest_network_regenerate_password(req, db).await,
        _ => Response::err("unknown guest network method"),
    }
}

async fn handle_guest_network_enable(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref ssid_name) = req.ssid_name else {
        return Response::err("ssid_name required");
    };
    let Some(ref password) = req.value else {
        return Response::err("value required (password)");
    };

    // Validate SSID name: 1-32 characters
    if ssid_name.is_empty() || ssid_name.len() > 32 {
        return Response::err("ssid_name must be 1-32 characters");
    }

    // Validate password: 8-63 ASCII characters (WPA-PSK requirement)
    if password.len() < 8 || password.len() > 63 || !password.is_ascii() {
        return Response::err("password must be 8-63 ASCII characters");
    }

    let band = req.band.as_deref().unwrap_or("2.4GHz").to_string();
    if !["2.4GHz", "5GHz", "5GHz-2", "6GHz"].contains(&band.as_str()) {
        return Response::err("band must be 2.4GHz, 5GHz, 5GHz-2, or 6GHz");
    }

    // Connect to provider and create SSID
    let provider = match super::wifi::connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let ssid_config = hermitshell_common::WifiSsidConfig {
        ssid_name: ssid_name.clone(),
        password: Some(password.clone()),
        band: band.clone(),
        vlan_id: None,
        hidden: false,
        enabled: true,
        security: "wpa-psk".to_string(),
    };

    if let Err(e) = provider.set_ssid(&ssid_config).await {
        return Response::err(&format!("failed to create guest SSID: {}", e));
    }

    // Encrypt password and store in DB
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    });
    let password_enc = if session_secret.is_empty() {
        password.clone()
    } else {
        match crate::crypto::encrypt_password(password, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_guest_network(provider_id, ssid_name, &password_enc, &band) {
        return Response::err(&format!("failed to save guest network config: {}", e));
    }
    let _ = db_guard.log_audit("guest_network_enable", &format!("enabled guest SSID '{}'", ssid_name));

    info!(ssid = %ssid_name, provider = %provider_id, "guest network enabled");
    Response::ok()
}

async fn handle_guest_network_disable(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    // Get current config
    let config = {
        let db_guard = db.lock().unwrap();
        match db_guard.get_guest_network() {
            Ok(Some(c)) => c,
            Ok(None) => return Response::err("guest network not configured"),
            Err(e) => return Response::err(&format!("failed to get guest network config: {}", e)),
        }
    };

    // Try to delete SSID from provider (warn but continue if it fails)
    match super::wifi::connect_to_provider(&config.provider_id, db).await {
        Ok(provider) => {
            if let Err(e) = provider.delete_ssid(&config.ssid_name, &config.band).await {
                warn!(ssid = %config.ssid_name, error = %e, "failed to delete guest SSID from provider (may already be removed)");
            }
        }
        Err(_) => {
            warn!(provider = %config.provider_id, "failed to connect to provider for guest SSID cleanup");
        }
    }

    // Remove from DB
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.delete_guest_network() {
        return Response::err(&format!("failed to delete guest network config: {}", e));
    }
    let _ = db_guard.log_audit("guest_network_disable", &format!("disabled guest SSID '{}'", config.ssid_name));

    info!(ssid = %config.ssid_name, "guest network disabled");
    Response::ok()
}

async fn handle_guest_network_update(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    // Get current config
    let config = {
        let db_guard = db.lock().unwrap();
        match db_guard.get_guest_network() {
            Ok(Some(c)) => c,
            Ok(None) => return Response::err("guest network not configured"),
            Err(e) => return Response::err(&format!("failed to get guest network config: {}", e)),
        }
    };

    let new_ssid_name = req.ssid_name.as_deref().unwrap_or(&config.ssid_name);
    let new_band = req.band.as_deref().unwrap_or(&config.band);

    // Validate new values
    if new_ssid_name.is_empty() || new_ssid_name.len() > 32 {
        return Response::err("ssid_name must be 1-32 characters");
    }
    if !["2.4GHz", "5GHz", "5GHz-2", "6GHz"].contains(&new_band) {
        return Response::err("band must be 2.4GHz, 5GHz, 5GHz-2, or 6GHz");
    }

    // Decrypt current password (needed for re-creating SSID if name or band changed)
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    });

    let current_password = if session_secret.is_empty() || !crate::crypto::is_encrypted(&config.password_enc) {
        config.password_enc.clone()
    } else {
        match crate::crypto::decrypt_password(&config.password_enc, &session_secret) {
            Ok(p) => p,
            Err(e) => return Response::err(&format!("failed to decrypt password: {}", e)),
        }
    };

    // Determine the password to use
    let new_password = if let Some(ref pw) = req.value {
        if pw.len() < 8 || pw.len() > 63 || !pw.is_ascii() {
            return Response::err("password must be 8-63 ASCII characters");
        }
        pw.clone()
    } else {
        current_password
    };

    let provider = match super::wifi::connect_to_provider(&config.provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // If name or band changed, delete old SSID first
    let name_changed = new_ssid_name != config.ssid_name;
    let band_changed = new_band != config.band;
    if name_changed || band_changed {
        if let Err(e) = provider.delete_ssid(&config.ssid_name, &config.band).await {
            warn!(ssid = %config.ssid_name, error = %e, "failed to delete old guest SSID (may already be removed)");
        }
    }

    // Create/update SSID on provider
    let ssid_config = hermitshell_common::WifiSsidConfig {
        ssid_name: new_ssid_name.to_string(),
        password: Some(new_password.clone()),
        band: new_band.to_string(),
        vlan_id: None,
        hidden: false,
        enabled: true,
        security: "wpa-psk".to_string(),
    };

    if let Err(e) = provider.set_ssid(&ssid_config).await {
        return Response::err(&format!("failed to update guest SSID: {}", e));
    }

    // Encrypt password and update DB
    let password_enc = if session_secret.is_empty() {
        new_password
    } else {
        match crate::crypto::encrypt_password(&new_password, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_guest_network(&config.provider_id, new_ssid_name, &password_enc, new_band) {
        return Response::err(&format!("failed to update guest network config: {}", e));
    }
    let _ = db_guard.log_audit("guest_network_update", &format!("updated guest SSID '{}'", new_ssid_name));

    info!(ssid = %new_ssid_name, "guest network updated");
    Response::ok()
}

async fn handle_guest_network_regenerate_password(
    _req: &Request,
    db: &Arc<Mutex<Db>>,
) -> Response {
    // Get current config
    let config = {
        let db_guard = db.lock().unwrap();
        match db_guard.get_guest_network() {
            Ok(Some(c)) => c,
            Ok(None) => return Response::err("guest network not configured"),
            Err(e) => return Response::err(&format!("failed to get guest network config: {}", e)),
        }
    };

    // Generate random 12-char alphanumeric password
    let new_password: String = {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..12)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    };

    // Update on provider
    let provider = match super::wifi::connect_to_provider(&config.provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let ssid_config = hermitshell_common::WifiSsidConfig {
        ssid_name: config.ssid_name.clone(),
        password: Some(new_password.clone()),
        band: config.band.clone(),
        vlan_id: None,
        hidden: false,
        enabled: true,
        security: "wpa-psk".to_string(),
    };

    if let Err(e) = provider.set_ssid(&ssid_config).await {
        return Response::err(&format!("failed to update guest SSID password: {}", e));
    }

    // Encrypt and save to DB
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    });
    let password_enc = if session_secret.is_empty() {
        new_password.clone()
    } else {
        match crate::crypto::encrypt_password(&new_password, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.update_guest_network_password(&password_enc) {
        return Response::err(&format!("failed to save new password: {}", e));
    }
    let _ = db_guard.log_audit("guest_network_regenerate_password", "regenerated guest network password");

    info!(ssid = %config.ssid_name, "guest network password regenerated");

    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::json!({"password": new_password}).to_string());
    resp
}

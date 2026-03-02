use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::switch::ssh::SshSwitchProvider;
use crate::switch::vendor;
use crate::switch::SwitchProvider;
use super::{Request, Response};

// ── Sync handlers (DB-only operations) ─────────────────────────────

pub(super) fn handle_switch_add(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let Some(ref host) = req.key else {
        return Response::err("key required (host)");
    };
    let Some(ref username) = req.value else {
        return Response::err("value required (username)");
    };
    let Some(ref password) = req.description else {
        return Response::err("description required (password)");
    };

    if name.is_empty() || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Response::err("name must be 1-64 alphanumeric characters (plus - _ . space)");
    }

    if host.is_empty() {
        return Response::err("host cannot be empty");
    }
    if username.is_empty() {
        return Response::err("username cannot be empty");
    }
    if password.is_empty() {
        return Response::err("password cannot be empty");
    }

    let port = req.port_start.unwrap_or(22);
    let vendor_profile = req.group.as_deref().unwrap_or("cisco_ios");

    // Validate vendor profile exists (built-in or custom)
    {
        let db_guard = db.lock().unwrap();
        let custom = db_guard
            .get_custom_vendor_profile(vendor_profile)
            .ok()
            .flatten();
        if custom.is_none() && vendor::built_in_profile(vendor_profile).is_none() {
            return Response::err(&format!("unknown vendor profile: {}", vendor_profile));
        }
    }

    // Encrypt password
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard
            .get_config("session_secret")
            .ok()
            .flatten()
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

    let id = uuid::Uuid::new_v4().to_string();

    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.insert_switch_provider(&id, name, host, port, username, &password_enc, vendor_profile) {
        return Response::err(&format!("failed to add switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_add", &format!("added switch {} ({})", name, host));

    info!(name = %name, host = %host, "switch provider added");
    Response::ok()
}

pub(super) fn handle_switch_remove(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required (switch id or name)");
    };

    let db_guard = db.lock().unwrap();
    let id = match resolve_switch_id(name_or_id, &db_guard) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(e) = db_guard.remove_switch_provider(&id) {
        return Response::err(&format!("failed to remove switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_remove", &format!("removed switch {}", name_or_id));

    info!(id = %id, "switch provider removed");
    Response::ok()
}

pub(super) fn handle_switch_list(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();
    match db_guard.list_switch_providers() {
        Ok(providers) => {
            let json = match serde_json::to_string(&providers) {
                Ok(j) => j,
                Err(e) => return Response::err(&format!("serialization failed: {}", e)),
            };
            let mut resp = Response::ok();
            resp.config_value = Some(json);
            resp
        }
        Err(e) => Response::err(&format!("failed to list switches: {}", e)),
    }
}

pub(super) fn handle_switch_set_uplink(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required (switch id or name)");
    };
    let Some(ref port_name) = req.value else {
        return Response::err("value required (port name)");
    };

    if port_name.is_empty() {
        return Response::err("port name cannot be empty");
    }

    let db_guard = db.lock().unwrap();
    let id = match resolve_switch_id(name_or_id, &db_guard) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(e) = db_guard.set_switch_uplink_port(&id, port_name) {
        return Response::err(&format!("failed to set uplink port: {}", e));
    }
    let _ = db_guard.log_audit(
        "switch_set_uplink",
        &format!("set uplink {} on switch {}", port_name, name_or_id),
    );

    info!(switch = %name_or_id, port = %port_name, "uplink port set");
    Response::ok()
}

// ── Async handlers (require SSH connections) ───────────────────────

pub(super) async fn handle_switch_async(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    match req.method.as_str() {
        "switch_test" => handle_switch_test(req, db).await,
        "switch_ports" => handle_switch_ports(req, db).await,
        "switch_provision_vlans" => handle_switch_provision_vlans(req, db).await,
        _ => Response::err("unknown switch method"),
    }
}

async fn handle_switch_test(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required (switch id or name)");
    };

    let provider = match get_provider(name_or_id, db) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    match provider.ping().await {
        Ok(()) => {
            // Update status to connected
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let id = {
                let db_guard = db.lock().unwrap();
                resolve_switch_id(name_or_id, &db_guard).ok()
            };
            if let Some(id) = id {
                let db_guard = db.lock().unwrap();
                let _ = db_guard.update_switch_provider_status(&id, "connected", now);
            }

            // Save TOFU host key if first connection
            if let Some(key) = provider.host_key() {
                let id = {
                    let db_guard = db.lock().unwrap();
                    resolve_switch_id(name_or_id, &db_guard).ok()
                };
                if let Some(id) = id {
                    let db_guard = db.lock().unwrap();
                    let _ = db_guard.set_switch_provider_host_key(&id, key);
                }
            }

            info!(switch = %name_or_id, "switch test successful");
            Response::ok()
        }
        Err(e) => {
            warn!(switch = %name_or_id, error = %e, "switch test failed");
            Response::err(&format!("switch test failed: {}", e))
        }
    }
}

async fn handle_switch_ports(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required (switch id or name)");
    };

    let provider = match get_provider(name_or_id, db) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    match provider.list_ports().await {
        Ok(ports) => {
            let port_list: Vec<serde_json::Value> = ports
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "status": match p.status {
                            crate::switch::PortStatus::Up => "up",
                            crate::switch::PortStatus::Down => "down",
                            crate::switch::PortStatus::Disabled => "disabled",
                        },
                        "vlan_id": p.vlan_id,
                        "is_trunk": p.is_trunk,
                        "macs": p.macs,
                    })
                })
                .collect();
            let json = match serde_json::to_string(&port_list) {
                Ok(j) => j,
                Err(e) => return Response::err(&format!("serialization failed: {}", e)),
            };
            let mut resp = Response::ok();
            resp.config_value = Some(json);
            resp
        }
        Err(e) => Response::err(&format!("failed to list ports: {}", e)),
    }
}

async fn handle_switch_provision_vlans(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required (switch id or name)");
    };

    let provider = match get_provider(name_or_id, db) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Get VLAN config from DB
    let vlans = {
        let db_guard = db.lock().unwrap();
        db_guard.get_vlan_config().unwrap_or_default()
    };

    if vlans.is_empty() {
        return Response::err("no VLANs configured");
    }

    // Create each VLAN on the switch
    for vlan in &vlans {
        if let Err(e) = provider.create_vlan(vlan.vlan_id, &vlan.group_name).await {
            warn!(vlan_id = vlan.vlan_id, error = %e, "failed to create VLAN");
            return Response::err(&format!(
                "failed to create VLAN {} ({}): {}",
                vlan.vlan_id, vlan.group_name, e
            ));
        }
    }

    // Save config on the switch
    if let Err(e) = provider.save_config().await {
        warn!(error = %e, "failed to save switch config after VLAN provisioning");
        return Response::err(&format!("VLANs created but save failed: {}", e));
    }

    let db_guard = db.lock().unwrap();
    let _ = db_guard.log_audit(
        "switch_provision_vlans",
        &format!(
            "provisioned {} VLANs on switch {}",
            vlans.len(),
            name_or_id
        ),
    );

    info!(switch = %name_or_id, count = vlans.len(), "VLANs provisioned on switch");
    Response::ok()
}

// ── Helpers ────────────────────────────────────────────────────────

/// Resolve a switch name or ID to a switch ID. The caller must hold the DB lock.
fn resolve_switch_id(name_or_id: &str, db: &Db) -> Result<String, Response> {
    let providers = db.list_switch_providers().unwrap_or_default();

    // Try exact ID match first
    if let Some(p) = providers.iter().find(|p| p.id == name_or_id) {
        return Ok(p.id.clone());
    }
    // Fall back to name match
    if let Some(p) = providers.iter().find(|p| p.name == name_or_id) {
        return Ok(p.id.clone());
    }

    Err(Response::err("switch not found"))
}

/// Build an SshSwitchProvider from DB credentials for the given switch name or ID.
fn get_provider(name_or_id: &str, db: &Arc<Mutex<Db>>) -> Result<SshSwitchProvider, Response> {
    let db_guard = db.lock().unwrap();
    let id = resolve_switch_id(name_or_id, &db_guard)?;

    let (host, port, username, password_enc, vendor_profile_name, host_key) =
        match db_guard.get_switch_provider_credentials(&id) {
            Ok(creds) => creds,
            Err(e) => return Err(Response::err(&format!("failed to get credentials: {}", e))),
        };

    drop(db_guard); // Release lock before decryption

    // Decrypt password
    let password = {
        let session_secret = Zeroizing::new({
            let db_guard = db.lock().unwrap();
            db_guard
                .get_config("session_secret")
                .ok()
                .flatten()
                .unwrap_or_default()
        });
        if session_secret.is_empty() || !crate::crypto::is_encrypted(&password_enc) {
            password_enc
        } else {
            match crate::crypto::decrypt_password(&password_enc, &session_secret) {
                Ok(p) => p,
                Err(e) => return Err(Response::err(&format!("decrypt failed: {}", e))),
            }
        }
    };

    // Resolve vendor profile (custom DB entry or built-in)
    let profile = {
        let custom = {
            let db_guard = db.lock().unwrap();
            db_guard
                .get_custom_vendor_profile(&vendor_profile_name)
                .ok()
                .flatten()
        };
        if let Some(json) = custom {
            match serde_json::from_str(&json) {
                Ok(p) => p,
                Err(e) => {
                    return Err(Response::err(&format!(
                        "failed to parse custom profile: {}",
                        e
                    )))
                }
            }
        } else {
            match vendor::built_in_profile(&vendor_profile_name) {
                Some(p) => p,
                None => {
                    return Err(Response::err(&format!(
                        "unknown vendor profile: {}",
                        vendor_profile_name
                    )))
                }
            }
        }
    };

    Ok(SshSwitchProvider::new(
        host, port, username, password, profile, host_key,
    ))
}

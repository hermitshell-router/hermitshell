use std::sync::{Arc, Mutex};
use tracing::info;
use zeroize::Zeroizing;

use crate::db::Db;
use crate::switch::{self, SnmpCredentials};
use super::{Request, Response};

pub(super) fn handle_switch_add(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let Some(ref host) = req.key else {
        return Response::err("key required (host)");
    };
    let Some(ref community) = req.value else {
        return Response::err("value required (community string)");
    };

    if name.is_empty() || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Response::err("name must be 1-64 alphanumeric characters (plus - _ . space)");
    }
    if host.is_empty() {
        return Response::err("host cannot be empty");
    }
    if community.is_empty() {
        return Response::err("community string cannot be empty");
    }

    // Encrypt community string
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    });
    let community_enc = if session_secret.is_empty() {
        community.clone()
    } else {
        match crate::crypto::encrypt_password(community, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.insert_snmp_switch(&id, name, host, &community_enc) {
        return Response::err(&format!("failed to add switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_add", &format!("added SNMP switch {} ({})", name, host));

    info!(name = %name, host = %host, "SNMP switch added");
    Response::ok()
}

pub(super) fn handle_switch_remove(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required");
    };

    let db_guard = db.lock().unwrap();
    let id = match resolve_switch_id(name_or_id, &db_guard) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(e) = db_guard.remove_snmp_switch(&id) {
        return Response::err(&format!("failed to remove switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_remove", &format!("removed SNMP switch {}", name_or_id));

    info!(id = %id, "SNMP switch removed");
    Response::ok()
}

pub(super) fn handle_switch_list(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();
    match db_guard.list_snmp_switches() {
        Ok(switches) => {
            let json = match serde_json::to_string(&switches) {
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

pub(super) async fn handle_switch_test(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required");
    };

    let (id, host, creds) = match get_switch_info(name_or_id, db) {
        Ok(info) => info,
        Err(resp) => return resp,
    };

    match switch::test_connectivity(&host, &creds).await {
        Ok(sys_descr) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let db_guard = db.lock().unwrap();
            let _ = db_guard.update_snmp_switch_status(&id, "connected", now);

            info!(switch = %name_or_id, sys_descr = %sys_descr, "SNMP test successful");
            Response::ok()
        }
        Err(e) => Response::err(&format!("SNMP test failed: {}", e)),
    }
}

fn resolve_switch_id(name_or_id: &str, db: &Db) -> Result<String, Response> {
    let switches = db.list_snmp_switches().unwrap_or_default();
    if let Some(s) = switches.iter().find(|s| s.id == name_or_id) {
        return Ok(s.id.clone());
    }
    if let Some(s) = switches.iter().find(|s| s.name == name_or_id) {
        return Ok(s.id.clone());
    }
    Err(Response::err("switch not found"))
}

fn get_switch_info(
    name_or_id: &str,
    db: &Arc<Mutex<Db>>,
) -> Result<(String, String, SnmpCredentials), Response> {
    let db_guard = db.lock().unwrap();
    let id = resolve_switch_id(name_or_id, &db_guard)?;

    let switches = db_guard.list_snmp_switches().unwrap_or_default();
    let sw = switches.iter().find(|s| s.id == id).unwrap();
    let host = sw.host.clone();
    let version = sw.version.clone();
    let v3_username = sw.v3_username.clone().unwrap_or_default();
    let v3_auth_protocol = sw.v3_auth_protocol.clone().unwrap_or_default();
    let v3_cipher = sw.v3_cipher.clone().unwrap_or_default();

    let secret = db_guard
        .get_config("session_secret")
        .ok()
        .flatten()
        .unwrap_or_default();

    let decrypt = |enc: &str| -> Result<String, Response> {
        if secret.is_empty() || !crate::crypto::is_encrypted(enc) {
            Ok(enc.to_string())
        } else {
            crate::crypto::decrypt_password(enc, &secret)
                .map_err(|e| Response::err(&format!("decrypt failed: {}", e)))
        }
    };

    let creds = if version == "3" {
        let (auth_enc, priv_enc) = db_guard
            .get_snmp_switch_v3_credentials(&id)
            .map_err(|e| Response::err(&format!("failed to get v3 credentials: {}", e)))?;
        drop(db_guard);
        let auth_pass = decrypt(&auth_enc)?;
        let priv_pass = decrypt(&priv_enc)?;
        SnmpCredentials::V3 {
            username: v3_username,
            auth_protocol: v3_auth_protocol,
            cipher: v3_cipher,
            auth_pass,
            priv_pass,
        }
    } else {
        let community_enc = db_guard
            .get_snmp_switch_community(&id)
            .map_err(|e| Response::err(&format!("failed to get community: {}", e)))?;
        drop(db_guard);
        let community = decrypt(&community_enc)?;
        SnmpCredentials::V2c { community }
    };

    Ok((id, host, creds))
}

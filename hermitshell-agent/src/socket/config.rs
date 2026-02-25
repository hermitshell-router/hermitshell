use super::*;

pub(super) fn handle_get_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref key) = req.key else { return Response::err("key required"); };
    if is_blocked_config_key(key) {
        warn!(key = %key, "blocked config key read attempt");
        return Response::err("access denied");
    }
    let db = db.lock().unwrap();
    match db.get_config(key) {
        Ok(val) => {
            let mut resp = Response::ok();
            resp.config_value = val;
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_set_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref key) = req.key else { return Response::err("key required"); };
    if is_blocked_config_key(key) {
        warn!(key = %key, "blocked config key write attempt");
        return Response::err("access denied");
    }
    let Some(ref value) = req.value else { return Response::err("value required"); };
    let db = db.lock().unwrap();
    match db.set_config(key, value) {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_get_ad_blocking(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let enabled = db.get_config_bool("ad_blocking_enabled", true);
    let mut resp = Response::ok();
    resp.ad_blocking_enabled = Some(enabled);
    resp
}

pub(super) fn handle_set_ad_blocking(req: &Request, db: &Arc<Mutex<Db>>, blocky: &Arc<Mutex<BlockyManager>>) -> Response {
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required");
    };
    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("ad_blocking_enabled", if enabled { "true" } else { "false" }) {
        return Response::err(&format!("failed to update config: {}", e));
    }
    drop(db);
    let mgr = blocky.lock().unwrap();
    if let Err(e) = mgr.set_blocking_enabled(enabled) {
        return Response::err(&format!("failed to update blocky: {}", e));
    }
    let mut resp = Response::ok();
    resp.ad_blocking_enabled = Some(enabled);
    resp
}

pub(super) fn handle_export_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let include_secrets = req.include_secrets.unwrap_or(false);
    let db = db.lock().unwrap();

    // Audit log the export
    let _ = db.log_audit("config_export", &format!("include_secrets={}", include_secrets));

    let devices = db.list_devices().unwrap_or_default();
    let reservations = db.list_dhcp_reservations().unwrap_or_default();
    let forwards = db.list_port_forwards().unwrap_or_default();
    let peers = db.list_wg_peers().unwrap_or_default();
    let pinholes: Vec<_> = db.list_ipv6_pinholes().unwrap_or_default()
        .into_iter()
        .filter(|p| matches!(p.get("protocol").and_then(|v| v.as_str()), Some("tcp" | "udp")))
        .collect();
    let wifi_aps = db.list_wifi_aps().unwrap_or_default();

    // v2 expanded config allowlist
    let config_keys = [
        "ad_blocking_enabled", "wg_listen_port", "dmz_host_ip", "log_format",
        "syslog_target", "webhook_url", "log_retention_days", "runzero_url",
        "runzero_sync_interval", "runzero_enabled", "qos_enabled", "qos_upload_mbps",
        "qos_download_mbps", "qos_test_url",
        // v2 additions
        "wg_enabled", "tls_mode", "analyzer_enabled",
        "alert_rule_dns_beaconing", "alert_rule_dns_volume_spike",
        "alert_rule_new_dest_spike", "alert_rule_suspicious_ports",
        "alert_rule_bandwidth_spike", "wan_iface", "lan_iface",
    ];
    let mut config_map = serde_json::Map::new();
    for key in &config_keys {
        if let Ok(Some(val)) = db.get_config(key) {
            config_map.insert(key.to_string(), serde_json::Value::String(val));
        }
    }

    // Build secrets section if requested
    let (secrets_value, secrets_encrypted) = if include_secrets {
        // Read all blocked config keys directly (bypassing the blocked check)
        let mut secrets_map = serde_json::Map::new();
        for key in super::BLOCKED_CONFIG_KEYS {
            if let Ok(Some(val)) = db.get_config(key) {
                secrets_map.insert(key.to_string(), serde_json::Value::String(val));
            }
        }

        // Decrypt WiFi AP passwords
        let session_secret = db.get_config("session_secret").ok().flatten().unwrap_or_default();
        let mut wifi_ap_passwords = serde_json::Map::new();
        for ap in &wifi_aps {
            if let Ok(Some((_ip, _username, password_enc))) = db.get_wifi_ap_credentials(&ap.mac) {
                if !password_enc.is_empty() {
                    let plaintext = if crate::crypto::is_encrypted(&password_enc) {
                        crate::crypto::decrypt_password(&password_enc, &session_secret)
                            .unwrap_or_else(|_| password_enc.clone())
                    } else {
                        password_enc
                    };
                    wifi_ap_passwords.insert(ap.mac.clone(), serde_json::Value::String(plaintext));
                }
            }
        }
        secrets_map.insert("wifi_ap_passwords".to_string(), serde_json::Value::Object(wifi_ap_passwords));

        let secrets_json = serde_json::Value::Object(secrets_map);

        // Optionally encrypt with passphrase
        let passphrase = req.passphrase.as_deref().unwrap_or("");
        if !passphrase.is_empty() {
            let secrets_str = serde_json::to_string(&secrets_json).unwrap_or_default();
            match crate::crypto::encrypt_with_passphrase(&secrets_str, passphrase) {
                Ok(encrypted) => (serde_json::Value::String(encrypted), true),
                Err(e) => return Response::err(&format!("failed to encrypt secrets: {}", e)),
            }
        } else {
            (secrets_json, false)
        }
    } else {
        (serde_json::Value::Null, false)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).expect("system clock before epoch").as_secs();

    let export = serde_json::json!({
        "version": 2,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "exported_at": now,
        "devices": devices.iter().map(|d| serde_json::json!({
            "mac": d.mac, "hostname": d.hostname, "device_group": d.device_group,
            "subnet_id": d.subnet_id, "nickname": d.nickname
        })).collect::<Vec<_>>(),
        "dhcp_reservations": reservations,
        "port_forwards": forwards,
        "wg_peers": peers.iter().map(|p| serde_json::json!({
            "public_key": p.public_key, "name": p.name, "subnet_id": p.subnet_id,
            "device_group": p.device_group, "enabled": p.enabled
        })).collect::<Vec<_>>(),
        "ipv6_pinholes": pinholes,
        "wifi_aps": wifi_aps.iter().map(|ap| serde_json::json!({
            "mac": ap.mac, "ip": ap.ip, "name": ap.name, "provider": ap.provider,
            "model": ap.model, "firmware": ap.firmware, "enabled": ap.enabled
        })).collect::<Vec<_>>(),
        "config": config_map,
        "secrets": secrets_value,
        "secrets_encrypted": secrets_encrypted,
    });

    let mut resp = Response::ok();
    resp.config_value = Some(export.to_string());
    resp
}

pub(super) fn handle_import_config(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str, lan_iface: &str) -> Response {
    let Some(ref data) = req.value else { return Response::err("value required (JSON config)"); };
    let parsed: serde_json::Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
    };

    // Version check: accept v1 and v2
    let version = match parsed.get("version").and_then(|v| v.as_i64()) {
        Some(v) if v >= 1 && v <= 2 => v,
        Some(v) if v > 2 => return Response::err("backup was created by a newer version — upgrade the agent first"),
        _ => return Response::err("missing or invalid version"),
    };

    // Decrypt secrets if present
    let secrets_obj: Option<serde_json::Map<String, serde_json::Value>> = {
        let secrets_val = parsed.get("secrets");
        let is_encrypted = parsed.get("secrets_encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
        match secrets_val {
            None | Some(serde_json::Value::Null) => None,
            Some(val) if is_encrypted => {
                // Encrypted secrets: require passphrase, decrypt
                let passphrase = match req.passphrase.as_deref() {
                    Some(p) if !p.is_empty() => p,
                    _ => return Response::err("passphrase required for encrypted backup"),
                };
                let encrypted_b64 = match val.as_str() {
                    Some(s) => s,
                    None => return Response::err("secrets decryption failed: expected encrypted string"),
                };
                match crate::crypto::decrypt_with_passphrase(encrypted_b64, passphrase) {
                    Ok(json_str) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                        Ok(serde_json::Value::Object(map)) => Some(map),
                        _ => return Response::err("secrets decryption failed: invalid JSON in decrypted secrets"),
                    },
                    Err(e) => return Response::err(&format!("secrets decryption failed: {}", e)),
                }
            }
            Some(serde_json::Value::Object(obj)) => Some(obj.clone()),
            _ => None,
        }
    };

    // Validation pass: devices
    if let Some(devices) = parsed.get("devices").and_then(|v| v.as_array()) {
        for dev in devices {
            let mac = dev.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            if !mac.is_empty() {
                if nftables::validate_mac(mac).is_err() {
                    return Response::err(&format!("invalid device MAC: {}", mac));
                }
                let group = dev.get("device_group").and_then(|v| v.as_str()).unwrap_or("quarantine");
                if nftables::validate_group(group).is_err() {
                    return Response::err(&format!("invalid device group: {}", group));
                }
            }
        }
    }
    // Validation pass: port forwards
    if let Some(forwards) = parsed.get("port_forwards").and_then(|v| v.as_array()) {
        for f in forwards {
            let protocol = f.get("protocol").and_then(|v| v.as_str()).unwrap_or("both");
            match protocol {
                "tcp" | "udp" | "both" => {}
                _ => return Response::err(&format!("invalid port forward protocol: {}", protocol)),
            }
            let internal_ip = f.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("");
            if !internal_ip.is_empty() && nftables::validate_ip(internal_ip).is_err() {
                return Response::err(&format!("invalid port forward IP: {}", internal_ip));
            }
        }
    }
    // Validation pass: pinholes
    if let Some(pinholes) = parsed.get("ipv6_pinholes").and_then(|v| v.as_array()) {
        for p in pinholes {
            let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            if !protocol.is_empty() && nftables::validate_protocol(protocol).is_err() {
                return Response::err(&format!("invalid pinhole protocol: {}", protocol));
            }
        }
    }

    let db = db.lock().unwrap();

    // Import devices: best-effort per-device -- skip invalid entries rather than aborting import.
    let mut device_count: usize = 0;
    if let Some(devices) = parsed.get("devices").and_then(|v| v.as_array()) {
        for dev in devices {
            let mac = dev.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            let group = dev.get("device_group").and_then(|v| v.as_str()).unwrap_or("quarantine");
            if !mac.is_empty() {
                let _ = db.set_device_group(mac, group);
                if let Some(hostname) = dev.get("hostname").and_then(|v| v.as_str()) {
                    let _ = db.set_device_hostname(mac, hostname);
                }
                if let Some(nickname) = dev.get("nickname").and_then(|v| v.as_str()) {
                    let _ = db.set_device_nickname(mac, nickname);
                }
                device_count += 1;
            }
        }
    }

    // Replace DHCP reservations: best-effort per-entry.
    let _ = db.conn_exec("DELETE FROM dhcp_reservations");
    if let Some(reservations) = parsed.get("dhcp_reservations").and_then(|v| v.as_array()) {
        for r in reservations {
            let mac = r.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            let sid = r.get("subnet_id").and_then(|v| v.as_i64()).unwrap_or(-1);
            if !mac.is_empty() && sid >= 0 {
                let _ = db.set_dhcp_reservation(mac, sid);
            }
        }
    }

    // Replace port forwards: best-effort per-entry.
    let _ = db.conn_exec("DELETE FROM port_forwards");
    if let Some(forwards) = parsed.get("port_forwards").and_then(|v| v.as_array()) {
        for f in forwards {
            let protocol = f.get("protocol").and_then(|v| v.as_str()).unwrap_or("both");
            let ext_start = f.get("external_port_start").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let ext_end = f.get("external_port_end").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let internal_ip = f.get("internal_ip").and_then(|v| v.as_str()).unwrap_or("");
            let int_port = f.get("internal_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
            if ext_start > 0 && !internal_ip.is_empty() {
                let _ = db.add_port_forward(protocol, ext_start, ext_end, internal_ip, int_port, desc);
            }
        }
    }

    // Replace IPv6 pinholes: best-effort per-entry.
    let _ = db.conn_exec("DELETE FROM ipv6_pinholes");
    if let Some(pinholes) = parsed.get("ipv6_pinholes").and_then(|v| v.as_array()) {
        for p in pinholes {
            let mac = p.get("device_mac").and_then(|v| v.as_str()).unwrap_or("");
            let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            let port_start = p.get("port_start").and_then(|v| v.as_i64()).unwrap_or(0);
            let port_end = p.get("port_end").and_then(|v| v.as_i64()).unwrap_or(0);
            let desc = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
            if !mac.is_empty() && !protocol.is_empty() && port_start > 0 {
                let _ = db.add_ipv6_pinhole(mac, protocol, port_start, port_end, desc);
            }
        }
    }

    // Import WiFi APs: best-effort per-entry.
    if let Some(wifi_aps) = parsed.get("wifi_aps").and_then(|v| v.as_array()) {
        let session_secret = db.get_config("session_secret").ok().flatten().unwrap_or_default();
        let ap_passwords = secrets_obj.as_ref()
            .and_then(|s| s.get("wifi_ap_passwords"))
            .and_then(|v| v.as_object());

        for ap in wifi_aps {
            let mac = ap.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            let ip = ap.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let name = ap.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if mac.is_empty() || ip.is_empty() || name.is_empty() {
                continue;
            }
            let provider = ap.get("provider").and_then(|v| v.as_str()).unwrap_or("eap_standalone");
            let enabled = ap.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

            // Look up plaintext password from secrets, re-encrypt with current session_secret
            let password_enc = ap_passwords
                .and_then(|m| m.get(mac))
                .and_then(|v| v.as_str())
                .and_then(|plaintext| crate::crypto::encrypt_password(plaintext, &session_secret).ok())
                .unwrap_or_default();

            // Delete existing AP with same MAC, then insert
            let _ = db.remove_wifi_ap(mac);
            let _ = db.insert_wifi_ap(mac, ip, name, provider, "admin", &password_enc);

            // Update model/firmware if present
            let model = ap.get("model").and_then(|v| v.as_str());
            let firmware = ap.get("firmware").and_then(|v| v.as_str());
            if model.is_some() || firmware.is_some() {
                let _ = db.update_wifi_ap_info(mac, model, firmware);
            }

            // Set enabled state: insert defaults to enabled, so only update if disabled
            if !enabled {
                let _ = db.set_wifi_ap_enabled(mac, false);
            }
        }
    }

    // Import config keys (expanded allowlist for v2).
    if let Some(config) = parsed.get("config").and_then(|v| v.as_object()) {
        for (key, val) in config {
            match key.as_str() {
                "ad_blocking_enabled" | "wg_listen_port" | "dmz_host_ip" | "log_format"
                | "syslog_target" | "webhook_url" | "log_retention_days" | "runzero_url"
                | "runzero_sync_interval" | "runzero_enabled" | "qos_enabled" | "qos_upload_mbps"
                | "qos_download_mbps" | "qos_test_url"
                | "wg_enabled" | "tls_mode" | "analyzer_enabled"
                | "alert_rule_dns_beaconing" | "alert_rule_dns_volume_spike"
                | "alert_rule_new_dest_spike" | "alert_rule_suspicious_ports"
                | "alert_rule_bandwidth_spike" | "wan_iface" | "lan_iface" => {
                    if let Some(v) = val.as_str() {
                        let _ = db.set_config(key, v);
                    }
                }
                _ => {}
            }
        }
    }

    // Import secrets (blocked config keys) if secrets object exists.
    if let Some(ref secrets) = secrets_obj {
        for key in super::BLOCKED_CONFIG_KEYS {
            if let Some(val) = secrets.get(*key).and_then(|v| v.as_str()) {
                let _ = db.set_config(key, val);
            }
        }
    }

    // Audit log
    let _ = db.log_audit("config_import", &format!("version={} devices={}", version, device_count));

    let forwards = db.list_enabled_port_forwards().unwrap_or_default();
    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
    let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };

    let qos_enabled = db.get_config_bool("qos_enabled", false);
    let qos_upload: u32 = db.get_config("qos_upload_mbps")
        .ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
    let qos_download: u32 = db.get_config("qos_download_mbps")
        .ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(0);
    let qos_devices: Vec<(String, String)> = if qos_enabled {
        let assigned = db.list_assigned_devices().unwrap_or_default();
        assigned.iter()
            .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
            .collect()
    } else {
        Vec::new()
    };

    drop(db);
    // Re-apply nftables rules from imported config. best-effort: partial apply is acceptable.
    let _ = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref);

    // Re-apply QoS from imported config. best-effort: partial apply is acceptable.
    if qos_enabled {
        if qos_upload > 0 && qos_download > 0 {
            let _ = crate::qos::enable(wan_iface, qos_upload, qos_download);
            let _ = crate::qos::apply_dscp_rules(&qos_devices);
        }
    } else {
        let _ = crate::qos::disable(wan_iface);
        let _ = crate::qos::remove_dscp_rules();
    }

    Response::ok()
}

pub(super) fn handle_backup_database(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let _ = std::fs::remove_file(Db::BACKUP_PATH);
    match db.vacuum_into_backup() {
        Ok(()) => {
            let mut resp = Response::ok();
            resp.config_value = Some(Db::BACKUP_PATH.to_string());
            resp
        }
        Err(e) => Response::err(&format!("backup failed: {}", e)),
    }
}

pub(super) fn handle_get_log_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let config = serde_json::json!({
        "log_format": db.get_config("log_format").ok().flatten().unwrap_or_else(|| "text".to_string()),
        "syslog_target": db.get_config("syslog_target").ok().flatten().unwrap_or_default(),
        "webhook_url": db.get_config("webhook_url").ok().flatten().unwrap_or_default(),
        "log_retention_days": db.get_config("log_retention_days").ok().flatten().unwrap_or_else(|| "7".to_string()),
    });
    let mut resp = Response::ok();
    resp.log_config = Some(config);
    resp
}

pub(super) fn handle_set_log_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required (JSON object)");
    };
    let parsed: serde_json::Value = match serde_json::from_str(value) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
    };
    let db = db.lock().unwrap();
    let allowed_keys = ["log_format", "syslog_target", "webhook_url", "webhook_secret", "log_retention_days"];
    if let Some(obj) = parsed.as_object() {
        for (key, val) in obj {
            if allowed_keys.contains(&key.as_str()) {
                if let Some(v) = val.as_str() {
                    let _ = db.set_config(key, v);
                }
            }
        }
    }
    Response::ok()
}

pub(super) fn handle_get_runzero_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
    let sync_interval = db.get_config("runzero_sync_interval").ok().flatten().unwrap_or_else(|| "3600".to_string());
    let enabled = db.get_config_bool("runzero_enabled", false);
    let has_token = db.get_config("runzero_token").ok().flatten().map(|t| !t.is_empty()).unwrap_or(false);
    let has_ca_cert = db.get_config("runzero_ca_cert").ok().flatten().map(|c| !c.is_empty()).unwrap_or(false);
    let mut resp = Response::ok();
    resp.runzero_config = Some(serde_json::json!({
        "runzero_url": url,
        "runzero_sync_interval": sync_interval,
        "enabled": enabled,
        "has_token": has_token,
        "has_ca_cert": has_ca_cert,
    }));
    resp
}

pub(super) fn handle_set_runzero_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required (JSON object)");
    };
    let parsed: serde_json::Value = match serde_json::from_str(value) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
    };
    let db = db.lock().unwrap();
    if let Some(url) = parsed.get("runzero_url").and_then(|v| v.as_str()) {
        if !url.is_empty() && !url.starts_with("https://") {
            return Response::err("runzero_url must start with https://");
        }
        let _ = db.set_config("runzero_url", url);
    }
    if let Some(token) = parsed.get("runzero_token").and_then(|v| v.as_str()) {
        let _ = db.set_config("runzero_token", token);
    }
    if let Some(interval_str) = parsed.get("runzero_sync_interval").and_then(|v| v.as_str()) {
        if let Ok(secs) = interval_str.parse::<u64>() {
            if secs >= 60 {
                let _ = db.set_config("runzero_sync_interval", interval_str);
            } else {
                return Response::err("sync interval must be >= 60 seconds");
            }
        }
    }
    if let Some(enabled) = parsed.get("runzero_enabled").and_then(|v| v.as_str()) {
        let _ = db.set_config("runzero_enabled", enabled);
    }
    if let Some(ca_cert) = parsed.get("runzero_ca_cert").and_then(|v| v.as_str()) {
        if ca_cert.is_empty() {
            let _ = db.set_config("runzero_ca_cert", "");
        } else {
            let mut reader = std::io::BufReader::new(ca_cert.as_bytes());
            let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect();
            if certs.is_empty() || certs.iter().any(|c| c.is_err()) {
                return Response::err("invalid CA certificate PEM");
            }
            let _ = db.set_config("runzero_ca_cert", ca_cert);
        }
    }
    Response::ok()
}

pub(super) fn handle_sync_runzero(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let (url, token) = {
        let db = db.lock().unwrap();
        let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
        let token = db.get_config("runzero_token").ok().flatten().unwrap_or_default();
        (url, token)
    };
    if url.is_empty() || token.is_empty() {
        return Response::err("runzero_url and runzero_token must be configured");
    }
    let db_clone = db.clone();
    tokio::task::spawn(async move {
        match crate::runzero::sync_once(&db_clone, &url, &token).await {
            Ok(n) => info!(matched = n, "manual runZero sync complete"),
            Err(e) => warn!(error = %e, "manual runZero sync failed"),
        }
    });
    let mut resp = Response::ok();
    resp.config_value = Some("sync started".to_string());
    resp
}

pub(super) fn handle_get_analyzer_status(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let enabled = db.get_config("analyzer_enabled")
        .ok().flatten().unwrap_or_else(|| "true".to_string());
    let rules = ["dns_beaconing", "dns_volume_spike", "new_dest_spike", "suspicious_ports", "bandwidth_spike"];
    let rule_status: serde_json::Value = rules.iter().map(|r| {
        let key = format!("alert_rule_{r}");
        let val = db.get_config(&key).ok().flatten().unwrap_or_else(|| "enabled".to_string());
        (r.to_string(), serde_json::Value::String(val))
    }).collect::<serde_json::Map<String, serde_json::Value>>().into();

    let (high, medium, low) = db.alert_counts_by_severity().unwrap_or((0, 0, 0));

    let status = serde_json::json!({
        "enabled": enabled,
        "rules": rule_status,
        "unacknowledged_alerts": {
            "high": high,
            "medium": medium,
            "low": low,
        },
    });
    let mut resp = Response::ok();
    resp.analyzer_status = Some(status);
    resp
}

pub(super) fn handle_get_qos_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let enabled = db.get_config_bool("qos_enabled", false);
    let upload = db.get_config("qos_upload_mbps").ok().flatten().unwrap_or_default();
    let download = db.get_config("qos_download_mbps").ok().flatten().unwrap_or_default();
    let test_url = db.get_config("qos_test_url").ok().flatten().unwrap_or_default();
    let mut resp = Response::ok();
    resp.qos_config = Some(serde_json::json!({
        "enabled": enabled,
        "upload_mbps": upload,
        "download_mbps": download,
        "test_url": test_url,
    }));
    resp
}

pub(super) fn handle_set_qos_config(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str) -> Response {
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required");
    };
    let db = db.lock().unwrap();
    if enabled {
        let Some(upload) = req.upload_mbps else {
            return Response::err("upload_mbps required when enabling");
        };
        let Some(download) = req.download_mbps else {
            return Response::err("download_mbps required when enabling");
        };
        if let Err(e) = crate::qos::validate_bandwidth(upload) {
            return Response::err(&e.to_string());
        }
        if let Err(e) = crate::qos::validate_bandwidth(download) {
            return Response::err(&e.to_string());
        }
        // best-effort: save config even if individual writes fail
        let _ = db.set_config("qos_upload_mbps", &upload.to_string());
        let _ = db.set_config("qos_download_mbps", &download.to_string());
        let _ = db.set_config("qos_enabled", "true");
        if let Err(e) = crate::qos::enable(wan_iface, upload, download) {
            return Response::err(&format!("failed to enable QoS: {}", e));
        }
        let assigned = db.list_assigned_devices().unwrap_or_default();
        let devices: Vec<(String, String)> = assigned.iter()
            .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
            .collect();
        if let Err(e) = crate::qos::apply_dscp_rules(&devices) {
            return Response::err(&format!("failed to apply DSCP rules: {}", e));
        }
    } else {
        // best-effort: partial cleanup is acceptable on disable
        let _ = db.set_config("qos_enabled", "false");
        let _ = crate::qos::disable(wan_iface);
        let _ = crate::qos::remove_dscp_rules();
    }
    Response::ok()
}

pub(super) fn handle_set_qos_test_url(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref url) = req.url else {
        return Response::err("url required");
    };
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                return Response::err("url must be http or https");
            }
            if let Some(host) = parsed.host_str() {
                if let Ok(addr) = host.parse::<std::net::IpAddr>() {
                    if !crate::qos::is_public_ip(&addr) {
                        return Response::err("url must not point to private/loopback address");
                    }
                }
            }
        }
        Err(_) => return Response::err("invalid url"),
    }
    let db = db.lock().unwrap();
    let _ = db.set_config("qos_test_url", url);
    Response::ok()
}

pub(super) fn handle_check_update(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = db.get_config("update_latest_version").ok().flatten();
    let last_check = db.get_config("update_last_check").ok().flatten();
    let mut resp = Response::ok();
    resp.update_info = Some(serde_json::json!({
        "current_version": current,
        "latest_version": latest,
        "last_check": last_check,
    }));
    resp
}

pub(super) fn handle_run_speed_test(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let url = match db.get_config("qos_test_url") {
        Ok(Some(u)) if !u.is_empty() => u,
        _ => return Response::err("no speed test URL configured; set it first via set_qos_test_url"),
    };
    drop(db);
    let result = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(crate::qos::run_speed_test(&url))
    });
    match result {
        Ok(mbps) => {
            let mut resp = Response::ok();
            resp.qos_config = Some(serde_json::json!({
                "download_mbps": mbps,
            }));
            resp
        }
        Err(e) => Response::err(&format!("speed test failed: {}", e)),
    }
}

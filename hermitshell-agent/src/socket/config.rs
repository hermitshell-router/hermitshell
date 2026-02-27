use super::*;
use zeroize::Zeroizing;

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
    if value.len() > 4096 {
        return Response::err("value too long (max 4096 bytes)");
    }
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
    let wifi_providers = db.list_wifi_providers().unwrap_or_default();

    // v2 expanded config allowlist
    let config_keys = [
        "ad_blocking_enabled", "wg_listen_port", "dmz_host_ip", "log_format",
        "syslog_target", "webhook_url", "log_retention_days", "runzero_url",
        "runzero_sync_interval", "runzero_enabled", "runzero_ca_cert",
        "qos_enabled", "qos_upload_mbps",
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

        // Decrypt WiFi provider passwords and API keys
        let session_secret = db.get_config("session_secret").ok().flatten().unwrap_or_default();
        let mut wifi_provider_passwords = serde_json::Map::new();
        let mut wifi_provider_api_keys = serde_json::Map::new();
        for provider in &wifi_providers {
            if let Ok(Some((_ptype, _url, _username, password_enc, _site, api_key_enc))) = db.get_wifi_provider_credentials(&provider.id) {
                if !password_enc.is_empty() {
                    let plaintext = Zeroizing::new(if crate::crypto::is_encrypted(&password_enc) {
                        crate::crypto::decrypt_password(&password_enc, &session_secret)
                            .unwrap_or_else(|_| password_enc.clone())
                    } else {
                        password_enc
                    });
                    wifi_provider_passwords.insert(provider.id.clone(), serde_json::Value::String((*plaintext).clone()));
                }
                if let Some(api_key) = api_key_enc {
                    if !api_key.is_empty() {
                        let plaintext = Zeroizing::new(if crate::crypto::is_encrypted(&api_key) {
                            crate::crypto::decrypt_password(&api_key, &session_secret)
                                .unwrap_or_else(|_| api_key.clone())
                        } else {
                            api_key
                        });
                        wifi_provider_api_keys.insert(provider.id.clone(), serde_json::Value::String((*plaintext).clone()));
                    }
                }
            }
        }
        secrets_map.insert("wifi_provider_passwords".to_string(), serde_json::Value::Object(wifi_provider_passwords));
        secrets_map.insert("wifi_provider_api_keys".to_string(), serde_json::Value::Object(wifi_provider_api_keys));

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
        "wifi_providers": wifi_providers.iter().map(|p| {
            let ca_cert_pem = db.get_wifi_provider_ca_cert(&p.id).ok().flatten();
            let creds = db.get_wifi_provider_credentials(&p.id).ok().flatten();
            let (site, username) = creds.map(|c| (c.4, c.2)).unwrap_or((None, String::new()));
            serde_json::json!({
                "id": p.id, "provider_type": p.provider_type, "name": p.name,
                "url": p.url, "enabled": p.enabled, "site": site,
                "username": username, "ca_cert_pem": ca_cert_pem,
            })
        }).collect::<Vec<_>>(),
        "wifi_aps": wifi_aps.iter().map(|ap| {
            serde_json::json!({
                "mac": ap.mac, "ip": ap.ip, "name": ap.name, "provider": ap.provider,
                "model": ap.model, "firmware": ap.firmware, "enabled": ap.enabled,
                "provider_id": ap.provider_id,
            })
        }).collect::<Vec<_>>(),
        "config": config_map,
        "secrets": secrets_value,
        "secrets_encrypted": secrets_encrypted,
    });

    let mut resp = Response::ok();
    resp.config_value = Some(export.to_string());
    resp
}

pub(super) fn handle_import_config(req: &Request, db: &Arc<Mutex<Db>>, portmap: &crate::portmap::SharedRegistry) -> Response {
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
            if !internal_ip.is_empty() {
                if nftables::validate_ip(internal_ip).is_err() {
                    return Response::err(&format!("invalid port forward IP: {}", internal_ip));
                }
                if nftables::is_gateway_ip(internal_ip) {
                    return Response::err("port forward cannot target the gateway address");
                }
            }
            let desc = f.get("description").and_then(|v| v.as_str()).unwrap_or("");
            if desc.len() > 256 {
                return Response::err("port forward description too long (max 256 characters)");
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
    // Validation pass: config keys
    if let Some(config) = parsed.get("config").and_then(|v| v.as_object()) {
        if let Some(wan) = config.get("wan_iface").and_then(|v| v.as_str()) {
            if nftables::validate_iface(wan).is_err() {
                return Response::err(&format!("invalid WAN interface: {}", wan));
            }
        }
        if let Some(lan) = config.get("lan_iface").and_then(|v| v.as_str()) {
            if nftables::validate_iface(lan).is_err() {
                return Response::err(&format!("invalid LAN interface: {}", lan));
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
                    let clean = sanitize_hostname(hostname);
                    if !clean.is_empty() {
                        let _ = db.set_device_hostname(mac, &clean);
                    }
                }
                if let Some(nickname) = dev.get("nickname").and_then(|v| v.as_str()) {
                    let clean: String = nickname.chars().filter(|c| !c.is_control()).collect();
                    let _ = db.set_device_nickname(mac, &clean);
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

    // Import WiFi providers: best-effort per-entry.
    if let Some(wifi_providers) = parsed.get("wifi_providers").and_then(|v| v.as_array()) {
        let session_secret = db.get_config("session_secret").ok().flatten().unwrap_or_default();
        let provider_passwords = secrets_obj.as_ref()
            .and_then(|s| s.get("wifi_provider_passwords"))
            .and_then(|v| v.as_object());
        let provider_api_keys = secrets_obj.as_ref()
            .and_then(|s| s.get("wifi_provider_api_keys"))
            .and_then(|v| v.as_object());

        for p in wifi_providers {
            let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let provider_type = p.get("provider_type").and_then(|v| v.as_str()).unwrap_or("");
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let url = p.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() || provider_type.is_empty() || name.is_empty() || url.is_empty() {
                continue;
            }
            let valid_types = ["eap_standalone", "unifi"];
            if !valid_types.contains(&provider_type) {
                warn!(provider_type = %provider_type, "import_config: skipping WiFi provider with unknown type");
                continue;
            }
            if name.len() > 64
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
            {
                warn!(name = %name, "import_config: skipping WiFi provider with invalid name");
                continue;
            }

            // Type-specific URL validation (matches handle_wifi_add_provider)
            match provider_type {
                "eap_standalone" => {
                    if url.parse::<std::net::IpAddr>().is_err() {
                        warn!(url = %url, "import_config: skipping eap_standalone provider with invalid IP");
                        continue;
                    }
                }
                "unifi" => {
                    match reqwest::Url::parse(url) {
                        Ok(parsed) if parsed.scheme() == "https" => {}
                        _ => {
                            warn!(url = %url, "import_config: skipping unifi provider with invalid URL");
                            continue;
                        }
                    }
                }
                _ => {}
            }

            let username = p.get("username").and_then(|v| v.as_str()).unwrap_or("admin");
            let site = p.get("site").and_then(|v| v.as_str());

            // Look up plaintext password from secrets, re-encrypt with current session_secret
            let password_enc = provider_passwords
                .and_then(|m| m.get(id))
                .and_then(|v| v.as_str())
                .and_then(|plaintext| crate::crypto::encrypt_password(plaintext, &session_secret).ok())
                .unwrap_or_default();

            let api_key_enc = provider_api_keys
                .and_then(|m| m.get(id))
                .and_then(|v| v.as_str())
                .and_then(|plaintext| crate::crypto::encrypt_password(plaintext, &session_secret).ok());

            // Delete existing provider with same ID, then insert
            let _ = db.remove_wifi_provider(id);
            let _ = db.insert_wifi_provider(id, provider_type, name, url, username, &password_enc, site, api_key_enc.as_deref());

            // Import CA cert if present (validate PEM before storing)
            let ca_cert = p.get("ca_cert_pem").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
            if let Some(pem) = ca_cert {
                if wifi::validate_ca_cert_pem_str(pem).is_ok() {
                    let _ = db.set_wifi_provider_ca_cert(id, Some(pem));
                } else {
                    warn!(provider = %id, "import_config: skipping invalid CA cert PEM");
                }
            }
        }
    }

    // Import WiFi APs: best-effort per-entry.
    if let Some(wifi_aps) = parsed.get("wifi_aps").and_then(|v| v.as_array()) {
        for ap in wifi_aps {
            let mac = ap.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            let provider_id = ap.get("provider_id").and_then(|v| v.as_str()).unwrap_or("");
            if mac.is_empty() || provider_id.is_empty() {
                continue;
            }
            let ip = ap.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let name = ap.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let _ = db.insert_wifi_ap_for_provider(mac, provider_id, ip, name);
        }
    }

    // Backward compat: old-format wifi_aps with username/password (pre-v8 schema)
    // If wifi_providers section is absent but wifi_aps has credential fields, create providers.
    if parsed.get("wifi_providers").is_none() {
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
                let provider_type = ap.get("provider").and_then(|v| v.as_str()).unwrap_or("eap_standalone");
                let valid_types = ["eap_standalone"];
                if !valid_types.contains(&provider_type) {
                    continue;
                }
                if ip.parse::<std::net::IpAddr>().is_err() {
                    continue;
                }
                if name.len() > 64
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
                {
                    continue;
                }

                let password_enc = ap_passwords
                    .and_then(|m| m.get(mac))
                    .and_then(|v| v.as_str())
                    .and_then(|plaintext| crate::crypto::encrypt_password(plaintext, &session_secret).ok())
                    .unwrap_or_default();

                let provider_id = uuid::Uuid::new_v4().to_string();
                let _ = db.insert_wifi_provider(&provider_id, provider_type, name, ip, "admin", &password_enc, None, None);
                let _ = db.insert_wifi_ap_for_provider(mac, &provider_id, ip, name);

                let ca_cert = ap.get("ca_cert_pem").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
                if let Some(pem) = ca_cert {
                    if wifi::validate_ca_cert_pem_str(pem).is_ok() {
                        let _ = db.set_wifi_provider_ca_cert(&provider_id, Some(pem));
                    }
                }
            }
        }
    }

    // Import config keys (expanded allowlist for v2).
    if let Some(config) = parsed.get("config").and_then(|v| v.as_object()) {
        for (key, val) in config {
            match key.as_str() {
                "ad_blocking_enabled" | "wg_listen_port" | "dmz_host_ip" | "log_format"
                | "syslog_target" | "webhook_url" | "log_retention_days" | "runzero_url"
                | "runzero_sync_interval" | "runzero_enabled" | "runzero_ca_cert"
                | "qos_enabled" | "qos_upload_mbps"
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
    // Re-apply nftables rules from imported config via shared registry.
    portmap.reapply_rules();

    // Re-apply QoS from imported config. best-effort: partial apply is acceptable.
    let wan_iface = portmap.wan_iface();
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
    let (url, token, ca_cert) = {
        let db = db.lock().unwrap();
        let url = db.get_config("runzero_url").ok().flatten().unwrap_or_default();
        let token = db.get_config("runzero_token").ok().flatten().unwrap_or_default();
        let ca_cert = db.get_config("runzero_ca_cert").ok().flatten()
            .filter(|c| !c.is_empty());
        (url, token, ca_cert)
    };
    if url.is_empty() || token.is_empty() {
        return Response::err("runzero_url and runzero_token must be configured");
    }
    let db_clone = db.clone();
    tokio::task::spawn(async move {
        match crate::runzero::sync_once(&db_clone, &url, &token, ca_cert.as_deref()).await {
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
    let enabled = db.get_config("update_check_enabled").ok().flatten()
        .map(|v| v == "true").unwrap_or(false);
    let auto_update = db.get_config("auto_update_enabled").ok().flatten()
        .map(|v| v == "true").unwrap_or(false);
    let mut resp = Response::ok();
    resp.update_info = Some(serde_json::json!({
        "current_version": current,
        "latest_version": latest,
        "last_check": last_check,
        "enabled": enabled,
        "auto_update_enabled": auto_update,
    }));
    resp
}

pub(super) fn handle_run_speed_test(_req: &Request, db: &Arc<Mutex<Db>>, state: &SpeedTestState) -> Response {
    {
        let st = state.lock().unwrap();
        if st.0 {
            return Response::err("speed test already running");
        }
    }
    let db = db.lock().unwrap();
    let url = match db.get_config("qos_test_url") {
        Ok(Some(u)) if !u.is_empty() => u,
        _ => return Response::err("no speed test URL configured; set it first via set_qos_test_url"),
    };
    drop(db);
    {
        let mut st = state.lock().unwrap();
        st.0 = true;
        st.1 = None;
        st.2 = None;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let result = crate::qos::run_speed_test(&url).await;
        let mut st = state.lock().unwrap();
        st.0 = false;
        match result {
            Ok(mbps) => st.1 = Some(mbps),
            Err(e) => st.2 = Some(format!("{}", e)),
        }
    });
    let mut resp = Response::ok();
    resp.config_value = Some("started".to_string());
    resp
}

pub(super) fn handle_get_speed_test_result(_req: &Request, state: &SpeedTestState) -> Response {
    let st = state.lock().unwrap();
    let mut resp = Response::ok();
    if st.0 {
        resp.qos_config = Some(serde_json::json!({"status": "running"}));
    } else if let Some(mbps) = st.1 {
        resp.qos_config = Some(serde_json::json!({"status": "complete", "download_mbps": mbps}));
    } else if let Some(ref err) = st.2 {
        resp.qos_config = Some(serde_json::json!({"status": "error", "error": err}));
    } else {
        resp.qos_config = Some(serde_json::json!({"status": "idle"}));
    }
    resp
}

pub(super) async fn handle_apply_update(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    match crate::update::apply_update(db).await {
        Ok(version) => {
            // Trigger staged restart in background
            crate::update::trigger_staged_restart();
            let mut resp = Response::ok();
            resp.config_value = Some(version);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

use super::*;
use zeroize::{Zeroize, Zeroizing};

const MAX_IMPORT_DEVICES: usize = 10_000;
const MAX_IMPORT_PORT_FORWARDS: usize = 1_000;
const MAX_IMPORT_PINHOLES: usize = 1_000;
const MAX_IMPORT_WIFI_PROVIDERS: usize = 100;

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

pub(super) fn handle_set_ad_blocking(req: &Request, db: &Arc<Mutex<Db>>, unbound: &Arc<Mutex<UnboundManager>>) -> Response {
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required");
    };
    let mut mgr = unbound.lock().unwrap();
    if let Err(e) = mgr.set_blocking_enabled(db, enabled) {
        return Response::err(&format!("failed to update blocking: {}", e));
    }
    let mut resp = Response::ok();
    resp.ad_blocking_enabled = Some(enabled);
    resp
}

pub(super) fn handle_export_config(req: &Request, db: &Arc<Mutex<Db>>, caller_uid: u32) -> Response {
    let include_secrets = req.include_secrets.unwrap_or(false);
    if include_secrets && caller_uid != 0 {
        return Response::err("include_secrets requires root");
    }
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
    let dns_forwards = db.list_dns_forward_zones().unwrap_or_default();
    let dns_rules = db.list_dns_custom_rules().unwrap_or_default();
    let dns_blocklists = db.list_dns_blocklists().unwrap_or_default();

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
        "dns_ratelimit_per_client", "dns_ratelimit_per_domain",
        "dns_bypass_allowed_trusted", "dns_bypass_allowed_guest",
        "dns_bypass_allowed_quarantine", "dns_bypass_allowed_iot",
        "dns_bypass_allowed_servers",
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
        let session_secret = Zeroizing::new(db.get_config("session_secret").ok().flatten().unwrap_or_default());
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
                if let Some(api_key) = api_key_enc
                    && !api_key.is_empty() {
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
        "dns_forward_zones": dns_forwards,
        "dns_custom_rules": dns_rules,
        "dns_blocklists": dns_blocklists,
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
        Some(v) if (1..=2).contains(&v) => v,
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

    // Count limits
    if let Some(devices) = parsed.get("devices").and_then(|v| v.as_array())
        && devices.len() > MAX_IMPORT_DEVICES {
            return Response::err(&format!("too many devices ({}, max {})", devices.len(), MAX_IMPORT_DEVICES));
        }
    if let Some(forwards) = parsed.get("port_forwards").and_then(|v| v.as_array())
        && forwards.len() > MAX_IMPORT_PORT_FORWARDS {
            return Response::err(&format!("too many port forwards ({}, max {})", forwards.len(), MAX_IMPORT_PORT_FORWARDS));
        }
    if let Some(pinholes) = parsed.get("ipv6_pinholes").and_then(|v| v.as_array())
        && pinholes.len() > MAX_IMPORT_PINHOLES {
            return Response::err(&format!("too many IPv6 pinholes ({}, max {})", pinholes.len(), MAX_IMPORT_PINHOLES));
        }
    if let Some(providers) = parsed.get("wifi_providers").and_then(|v| v.as_array())
        && providers.len() > MAX_IMPORT_WIFI_PROVIDERS {
            return Response::err(&format!("too many WiFi providers ({}, max {})", providers.len(), MAX_IMPORT_WIFI_PROVIDERS));
        }

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
        if let Some(wan) = config.get("wan_iface").and_then(|v| v.as_str())
            && nftables::validate_iface(wan).is_err() {
                return Response::err(&format!("invalid WAN interface: {}", wan));
            }
        if let Some(lan) = config.get("lan_iface").and_then(|v| v.as_str())
            && nftables::validate_iface(lan).is_err() {
                return Response::err(&format!("invalid LAN interface: {}", lan));
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
                    let mut clean: String = nickname.chars().filter(|c| !c.is_control()).collect();
                    if clean.len() > 256 {
                        let mut end = 256;
                        while !clean.is_char_boundary(end) {
                            end -= 1;
                        }
                        clean.truncate(end);
                    }
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
        let session_secret = Zeroizing::new(db.get_config("session_secret").ok().flatten().unwrap_or_default());
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
    if parsed.get("wifi_providers").is_none()
        && let Some(wifi_aps) = parsed.get("wifi_aps").and_then(|v| v.as_array()) {
            let session_secret = Zeroizing::new(db.get_config("session_secret").ok().flatten().unwrap_or_default());
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
                if let Some(pem) = ca_cert
                    && wifi::validate_ca_cert_pem_str(pem).is_ok() {
                        let _ = db.set_wifi_provider_ca_cert(&provider_id, Some(pem));
                    }
            }
        }

    // Import DNS forward zones
    let _ = db.conn_exec("DELETE FROM dns_forward_zones");
    if let Some(zones) = parsed.get("dns_forward_zones").and_then(|v| v.as_array()) {
        for z in zones {
            let domain = z.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let forward_addr = z.get("forward_addr").and_then(|v| v.as_str()).unwrap_or("");
            if !domain.is_empty() && !forward_addr.is_empty()
                && crate::unbound::validate_domain(domain).is_ok()
                && forward_addr.parse::<std::net::IpAddr>().is_ok() {
                    let _ = db.add_dns_forward_zone(domain, forward_addr);
                }
        }
    }

    // Import DNS custom rules
    let _ = db.conn_exec("DELETE FROM dns_custom_rules");
    if let Some(rules) = parsed.get("dns_custom_rules").and_then(|v| v.as_array()) {
        let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT"];
        for r in rules {
            let domain = r.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let record_type = r.get("record_type").and_then(|v| v.as_str()).unwrap_or("");
            let value = r.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if !domain.is_empty() && !value.is_empty() && valid_types.contains(&record_type)
                && crate::unbound::validate_domain(domain).is_ok() {
                    let _ = db.add_dns_custom_rule(domain, record_type, value);
                }
        }
    }

    // Import DNS blocklists (SSRF protection: require HTTPS, reject internal IPs)
    let _ = db.conn_exec("DELETE FROM dns_blocklists");
    if let Some(lists) = parsed.get("dns_blocklists").and_then(|v| v.as_array()) {
        let valid_tags = ["ads", "custom", "strict"];
        for bl in lists {
            let name = bl.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let url = bl.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let tag = bl.get("tag").and_then(|v| v.as_str()).unwrap_or("ads");
            if !name.is_empty() && !url.is_empty() && valid_tags.contains(&tag)
                && crate::unbound::validate_outbound_url(url, false).is_ok() {
                        let _ = db.add_dns_blocklist(name, url, tag);
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
                | "alert_rule_bandwidth_spike" | "wan_iface" | "lan_iface"
                | "dns_ratelimit_per_client" | "dns_ratelimit_per_domain"
                | "dns_bypass_allowed_trusted" | "dns_bypass_allowed_guest"
                | "dns_bypass_allowed_quarantine" | "dns_bypass_allowed_iot"
                | "dns_bypass_allowed_servers" => {
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

pub(super) fn handle_get_full_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let config = build_hermit_config(&db);
    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::to_string(&config).unwrap_or_default());
    resp
}

/// Build a HermitConfig from the current DB state.
pub fn build_hermit_config(db: &Db) -> hermitshell_common::HermitConfig {
    use hermitshell_common::*;

    let devices = db.list_devices().unwrap_or_default();
    let reservations = db.list_dhcp_reservations().unwrap_or_default();
    let forwards = db.list_port_forwards().unwrap_or_default();
    let peers = db.list_wg_peers().unwrap_or_default();
    let pinholes = db.list_ipv6_pinholes().unwrap_or_default();
    let wifi_providers = db.list_wifi_providers().unwrap_or_default();
    let dns_forwards = db.list_dns_forward_zones().unwrap_or_default();
    let dns_rules = db.list_dns_custom_rules().unwrap_or_default();
    let dns_blocklists = db.list_dns_blocklists().unwrap_or_default();

    HermitConfig {
        network: NetworkConfig {
            wan_interface: db.get_config("wan_iface").ok().flatten(),
            lan_interface: db.get_config("lan_iface").ok().flatten(),
            hostname: None, // hostname is system-level, read from /etc/hostname
            timezone: None, // timezone is system-level
            upstream_dns: Vec::new(), // stored in unbound config, not DB KV
            wan: WanConfig::default(),
        },
        dns: DnsConfig {
            ad_blocking: db.get_config_bool("ad_blocking_enabled", true),
            ratelimit_per_second: db.get_config("dns_ratelimit_per_client").ok().flatten()
                .and_then(|v| v.parse().ok()),
            blocklists: dns_blocklists.iter().map(|bl| BlocklistConfig {
                name: bl.name.clone(),
                url: bl.url.clone(),
                tag: bl.tag.clone(),
                enabled: bl.enabled,
            }).collect(),
            forward_zones: dns_forwards.iter().map(|fz| ForwardZoneConfig {
                domain: fz.domain.clone(),
                forward_to: fz.forward_addr.clone(),
                enabled: fz.enabled,
            }).collect(),
            custom_records: dns_rules.iter().map(|cr| CustomRecordConfig {
                domain: cr.domain.clone(),
                record_type: cr.record_type.clone(),
                value: cr.value.clone(),
                enabled: cr.enabled,
            }).collect(),
            bypass_allowed: Some(DnsBypassConfig {
                trusted: db.get_config_bool("dns_bypass_allowed_trusted", false),
                guest: db.get_config_bool("dns_bypass_allowed_guest", false),
                quarantine: db.get_config_bool("dns_bypass_allowed_quarantine", false),
                iot: db.get_config_bool("dns_bypass_allowed_iot", false),
                servers: db.get_config_bool("dns_bypass_allowed_servers", false),
            }),
        },
        firewall: FirewallConfig {
            dmz_host: db.get_config("dmz_host_ip").ok().flatten().filter(|s| !s.is_empty()),
            port_forwards: forwards.iter().filter(|f| f.source == "manual" || f.source.is_empty()).map(|f| PortForwardConfig {
                protocol: f.protocol.clone(),
                external_port: f.external_port_start,
                external_port_end: if f.external_port_end != f.external_port_start { Some(f.external_port_end) } else { None },
                internal_ip: f.internal_ip.clone(),
                internal_port: f.internal_port,
                enabled: f.enabled,
                description: f.description.clone(),
            }).collect(),
            ipv6_pinholes: pinholes.iter().filter_map(|p| {
                Some(Ipv6PinholeConfig {
                    device: p.get("device_mac")?.as_str()?.to_string(),
                    protocol: p.get("protocol")?.as_str()?.to_string(),
                    port_start: p.get("port_start")?.as_i64()? as u16,
                    port_end: p.get("port_end").and_then(|v| v.as_i64()).map(|v| v as u16),
                    description: p.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                })
            }).collect(),
            upnp_enabled: db.get_config("upnp_enabled").ok().flatten().map(|v| v == "true"),
        },
        wireguard: WireguardConfig {
            enabled: db.get_config_bool("wg_enabled", false),
            listen_port: db.get_config("wg_listen_port").ok().flatten()
                .and_then(|v| v.parse().ok()).unwrap_or(51820),
            peers: peers.iter().map(|p| WgPeerConfig {
                name: p.name.clone(),
                public_key: p.public_key.clone(),
                device_group: p.device_group.clone(),
                enabled: p.enabled,
            }).collect(),
        },
        devices: devices.iter().filter(|d| d.subnet_id.is_some()).map(|d| DeviceConfig {
            mac: d.mac.clone(),
            hostname: d.hostname.clone(),
            nickname: d.nickname.clone(),
            group: d.device_group.clone(),
        }).collect(),
        dhcp: DhcpConfig {
            reservations: reservations.iter().map(|r| DhcpReservationConfig {
                mac: r.mac.clone(),
                subnet_id: r.subnet_id,
            }).collect(),
        },
        qos: QosConfig {
            enabled: db.get_config_bool("qos_enabled", false),
            upload_mbps: db.get_config("qos_upload_mbps").ok().flatten()
                .and_then(|v| v.parse().ok()).unwrap_or(0),
            download_mbps: db.get_config("qos_download_mbps").ok().flatten()
                .and_then(|v| v.parse().ok()).unwrap_or(0),
        },
        logging: LoggingConfig {
            format: db.get_config("log_format").ok().flatten().unwrap_or_else(|| "text".into()),
            retention_days: db.get_config("log_retention_days").ok().flatten()
                .and_then(|v| v.parse().ok()).unwrap_or(7),
            syslog_target: db.get_config("syslog_target").ok().flatten().filter(|s| !s.is_empty()),
            webhook_url: db.get_config("webhook_url").ok().flatten().filter(|s| !s.is_empty()),
        },
        tls: TlsConfig {
            mode: db.get_config("tls_mode").ok().flatten().unwrap_or_else(|| "self_signed".into()),
        },
        analysis: AnalysisConfig {
            enabled: db.get_config_bool("analyzer_enabled", false),
            alert_rules: Some(AlertRulesConfig {
                dns_beaconing: db.get_config("alert_rule_dns_beaconing").ok().flatten().map(|v| v == "true"),
                dns_volume_spike: db.get_config("alert_rule_dns_volume_spike").ok().flatten().map(|v| v == "true"),
                new_dest_spike: db.get_config("alert_rule_new_dest_spike").ok().flatten().map(|v| v == "true"),
                suspicious_ports: db.get_config("alert_rule_suspicious_ports").ok().flatten().map(|v| v == "true"),
                bandwidth_spike: db.get_config("alert_rule_bandwidth_spike").ok().flatten().map(|v| v == "true"),
            }),
        },
        wifi: WifiConfig {
            providers: wifi_providers.iter().map(|p| {
                let creds = db.get_wifi_provider_credentials(&p.id).ok().flatten();
                let (site, username) = creds.map(|c| (c.4, Some(c.2))).unwrap_or((None, None));
                WifiProviderConfig {
                    name: p.name.clone(),
                    provider_type: p.provider_type.clone(),
                    url: p.url.clone(),
                    enabled: p.enabled,
                    site,
                    username,
                }
            }).collect(),
        },
    }
}

pub(super) fn handle_apply_config(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(ref data) = req.value else {
        return Response::err("value required (JSON HermitConfig)");
    };
    let config: hermitshell_common::HermitConfig = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid config JSON: {}", e)),
    };

    // Parse optional secrets
    let mut secrets: Option<hermitshell_common::HermitSecrets> = req.secrets.as_ref().and_then(|s| {
        serde_json::from_str(s).ok()
    });

    let result = apply_hermit_config(&config, secrets.as_ref(), db, portmap, unbound);

    // Zeroize secrets after DB writes
    if let Some(ref mut s) = secrets {
        s.zeroize();
    }

    match result {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&e),
    }
}

/// Apply a HermitConfig: validate, write to DB, and reconcile all subsystems.
/// Shared by socket handler and REST API.
/// If `secrets` is provided, blocked config keys (password hashes, private keys, etc.)
/// are also written to the DB.
pub fn apply_hermit_config(
    config: &hermitshell_common::HermitConfig,
    secrets: Option<&hermitshell_common::HermitSecrets>,
    db: &Arc<Mutex<Db>>,
    portmap: &crate::portmap::SharedRegistry,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Result<(), String> {
    // Structural validation
    let errors = config.validate();
    if !errors.is_empty() {
        let msg = errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        return Err(format!("validation failed: {}", msg));
    }

    // Agent-level validation (nftables-specific checks)
    // Validate interfaces
    if let Some(ref iface) = config.network.wan_interface
        && crate::nftables::validate_iface(iface).is_err()
    {
        return Err(format!("invalid WAN interface: {}", iface));
    }
    if let Some(ref iface) = config.network.lan_interface
        && crate::nftables::validate_iface(iface).is_err()
    {
        return Err(format!("invalid LAN interface: {}", iface));
    }
    // Validate device MACs
    for dev in &config.devices {
        if crate::nftables::validate_mac(&dev.mac).is_err() {
            return Err(format!("invalid device MAC: {}", dev.mac));
        }
    }
    // Validate port forward IPs
    for pf in &config.firewall.port_forwards {
        if crate::nftables::validate_ip(&pf.internal_ip).is_err() {
            return Err(format!("invalid port forward IP: {}", pf.internal_ip));
        }
        if crate::nftables::is_gateway_ip(&pf.internal_ip) {
            return Err("port forward cannot target the gateway address".to_string());
        }
    }
    // Validate DNS domains
    for fz in &config.dns.forward_zones {
        if crate::unbound::validate_domain(&fz.domain).is_err() {
            return Err(format!("invalid forward zone domain: {}", fz.domain));
        }
    }
    for cr in &config.dns.custom_records {
        if crate::unbound::validate_domain(&cr.domain).is_err() {
            return Err(format!("invalid custom record domain: {}", cr.domain));
        }
    }
    // Validate blocklist URLs (SSRF protection: require HTTPS, reject internal IPs)
    for bl in &config.dns.blocklists {
        if let Err(e) = crate::unbound::validate_outbound_url(&bl.url, false) {
            return Err(format!("invalid blocklist URL '{}': {}", bl.url, e));
        }
    }
    // Validate syslog target format (host:port)
    if let Some(ref target) = config.logging.syslog_target
        && !target.is_empty()
    {
        let parts: Vec<&str> = target.rsplitn(2, ':').collect();
        if parts.len() != 2 || parts[0].parse::<u16>().is_err() {
            return Err(format!("invalid syslog_target (expected host:port): {}", target));
        }
    }
    // Validate webhook URL (SSRF protection: require HTTPS, reject internal IPs)
    if let Some(ref url) = config.logging.webhook_url
        && !url.is_empty()
        && let Err(e) = crate::unbound::validate_outbound_url(url, false)
    {
        return Err(format!("invalid webhook_url: {}", e));
    }

    // Count limits
    if config.devices.len() > MAX_IMPORT_DEVICES {
        return Err(format!("too many devices ({}, max {})", config.devices.len(), MAX_IMPORT_DEVICES));
    }
    if config.firewall.port_forwards.len() > MAX_IMPORT_PORT_FORWARDS {
        return Err(format!("too many port forwards ({}, max {})", config.firewall.port_forwards.len(), MAX_IMPORT_PORT_FORWARDS));
    }
    if config.firewall.ipv6_pinholes.len() > MAX_IMPORT_PINHOLES {
        return Err(format!("too many pinholes ({}, max {})", config.firewall.ipv6_pinholes.len(), MAX_IMPORT_PINHOLES));
    }

    let db_guard = db.lock().unwrap();

    // --- Write config to DB (inside a transaction for atomicity) ---
    db_guard.begin_transaction().map_err(|e| format!("begin transaction: {}", e))?;

    let mut peer_subnets: std::collections::HashMap<String, (String, String, String)> = std::collections::HashMap::new();
    let mut old_wg_peers: Vec<crate::db::WgPeer> = Vec::new();
    let db_write_result: Result<(), String> = (|| {
        // Network config
        if let Some(ref iface) = config.network.wan_interface {
            db_guard.set_config("wan_iface", iface).map_err(|e| format!("set wan_iface: {e}"))?;
        }
        if let Some(ref iface) = config.network.lan_interface {
            db_guard.set_config("lan_iface", iface).map_err(|e| format!("set lan_iface: {e}"))?;
        }

        // Devices
        for dev in &config.devices {
            db_guard.set_device_group(&dev.mac, &dev.group).map_err(|e| format!("set device group: {e}"))?;
            if let Some(ref hostname) = dev.hostname {
                let clean = sanitize_hostname(hostname);
                if !clean.is_empty() {
                    db_guard.set_device_hostname(&dev.mac, &clean).map_err(|e| format!("set device hostname: {e}"))?;
                }
            }
            if let Some(ref nickname) = dev.nickname {
                let mut clean: String = nickname.chars().filter(|c| !c.is_control()).collect();
                if clean.len() > 256 {
                    let mut end = 256;
                    while !clean.is_char_boundary(end) { end -= 1; }
                    clean.truncate(end);
                }
                db_guard.set_device_nickname(&dev.mac, &clean).map_err(|e| format!("set device nickname: {e}"))?;
            }
        }

        // DHCP reservations
        db_guard.conn_exec("DELETE FROM dhcp_reservations").map_err(|e| format!("delete dhcp_reservations: {e}"))?;
        for r in &config.dhcp.reservations {
            db_guard.set_dhcp_reservation(&r.mac, r.subnet_id).map_err(|e| format!("set dhcp reservation: {e}"))?;
        }

        // Port forwards (manual only -- UPnP/NAT-PMP managed separately)
        db_guard.conn_exec("DELETE FROM port_forwards WHERE source = 'manual' OR source = ''").map_err(|e| format!("delete port_forwards: {e}"))?;
        for pf in &config.firewall.port_forwards {
            let ext_end = pf.external_port_end.unwrap_or(pf.external_port);
            db_guard.add_port_forward(&pf.protocol, pf.external_port, ext_end, &pf.internal_ip, pf.internal_port, &pf.description).map_err(|e| format!("add port forward: {e}"))?;
        }

        // IPv6 pinholes
        db_guard.conn_exec("DELETE FROM ipv6_pinholes").map_err(|e| format!("delete ipv6_pinholes: {e}"))?;
        for ph in &config.firewall.ipv6_pinholes {
            let port_end = ph.port_end.unwrap_or(ph.port_start) as i64;
            db_guard.add_ipv6_pinhole(&ph.device, &ph.protocol, ph.port_start as i64, port_end, &ph.description).map_err(|e| format!("add ipv6 pinhole: {e}"))?;
        }

        // DNS config
        db_guard.set_config("ad_blocking_enabled", if config.dns.ad_blocking { "true" } else { "false" }).map_err(|e| format!("set ad_blocking: {e}"))?;
        if let Some(rl) = config.dns.ratelimit_per_second {
            db_guard.set_config("dns_ratelimit_per_client", &rl.to_string()).map_err(|e| format!("set dns_ratelimit: {e}"))?;
        }
        if let Some(ref bypass) = config.dns.bypass_allowed {
            db_guard.set_config("dns_bypass_allowed_trusted", if bypass.trusted { "true" } else { "false" }).map_err(|e| format!("set dns_bypass: {e}"))?;
            db_guard.set_config("dns_bypass_allowed_guest", if bypass.guest { "true" } else { "false" }).map_err(|e| format!("set dns_bypass: {e}"))?;
            db_guard.set_config("dns_bypass_allowed_quarantine", if bypass.quarantine { "true" } else { "false" }).map_err(|e| format!("set dns_bypass: {e}"))?;
            db_guard.set_config("dns_bypass_allowed_iot", if bypass.iot { "true" } else { "false" }).map_err(|e| format!("set dns_bypass: {e}"))?;
            db_guard.set_config("dns_bypass_allowed_servers", if bypass.servers { "true" } else { "false" }).map_err(|e| format!("set dns_bypass: {e}"))?;
        }
        db_guard.conn_exec("DELETE FROM dns_forward_zones").map_err(|e| format!("delete dns_forward_zones: {e}"))?;
        for fz in &config.dns.forward_zones {
            db_guard.add_dns_forward_zone(&fz.domain, &fz.forward_to).map_err(|e| format!("add dns forward zone: {e}"))?;
        }
        db_guard.conn_exec("DELETE FROM dns_custom_rules").map_err(|e| format!("delete dns_custom_rules: {e}"))?;
        for cr in &config.dns.custom_records {
            db_guard.add_dns_custom_rule(&cr.domain, &cr.record_type, &cr.value).map_err(|e| format!("add dns custom rule: {e}"))?;
        }
        db_guard.conn_exec("DELETE FROM dns_blocklists").map_err(|e| format!("delete dns_blocklists: {e}"))?;
        for bl in &config.dns.blocklists {
            db_guard.add_dns_blocklist(&bl.name, &bl.url, &bl.tag).map_err(|e| format!("add dns blocklist: {e}"))?;
        }

        // WireGuard settings
        db_guard.set_config("wg_enabled", if config.wireguard.enabled { "true" } else { "false" }).map_err(|e| format!("set wg_enabled: {e}"))?;
        db_guard.set_config("wg_listen_port", &config.wireguard.listen_port.to_string()).map_err(|e| format!("set wg_listen_port: {e}"))?;

        // WireGuard peers: snapshot old set, then replace all DB entries with config peers.
        old_wg_peers = db_guard.list_wg_peers().unwrap_or_default();
        db_guard.conn_exec("DELETE FROM wg_peers").map_err(|e| format!("delete wg_peers: {e}"))?;
        let (dev_base, dev_max) = nftables::device_range();
        for peer in &config.wireguard.peers {
            if let Ok(subnet_id) = db_guard.allocate_subnet_id(dev_max + 1) {
                db_guard.insert_wg_peer(&peer.public_key, &peer.name, subnet_id, &peer.device_group).map_err(|e| format!("insert wg peer: {e}"))?;
                // insert_wg_peer always sets enabled=1; disable if needed
                if !peer.enabled {
                    db_guard.set_wg_peer_enabled(&peer.public_key, false).map_err(|e| format!("set wg peer enabled: {e}"))?;
                }
                // Collect subnet data for nftables rules (applied after commit)
                if let Some(info) = subnet::compute_subnet(subnet_id, dev_base, dev_max) {
                    peer_subnets.insert(peer.public_key.clone(), (info.device_ipv4.to_string(), info.device_ipv6_ula.to_string(), peer.device_group.clone()));
                }
            }
        }

        // QoS
        db_guard.set_config("qos_enabled", if config.qos.enabled { "true" } else { "false" }).map_err(|e| format!("set qos_enabled: {e}"))?;
        db_guard.set_config("qos_upload_mbps", &config.qos.upload_mbps.to_string()).map_err(|e| format!("set qos_upload: {e}"))?;
        db_guard.set_config("qos_download_mbps", &config.qos.download_mbps.to_string()).map_err(|e| format!("set qos_download: {e}"))?;

        // Logging
        db_guard.set_config("log_format", &config.logging.format).map_err(|e| format!("set log_format: {e}"))?;
        db_guard.set_config("log_retention_days", &config.logging.retention_days.to_string()).map_err(|e| format!("set log_retention: {e}"))?;
        if let Some(ref target) = config.logging.syslog_target {
            db_guard.set_config("syslog_target", target).map_err(|e| format!("set syslog_target: {e}"))?;
        }
        if let Some(ref url) = config.logging.webhook_url {
            db_guard.set_config("webhook_url", url).map_err(|e| format!("set webhook_url: {e}"))?;
        }

        // TLS
        db_guard.set_config("tls_mode", &config.tls.mode).map_err(|e| format!("set tls_mode: {e}"))?;

        // Analysis
        db_guard.set_config("analyzer_enabled", if config.analysis.enabled { "true" } else { "false" }).map_err(|e| format!("set analyzer_enabled: {e}"))?;
        if let Some(ref rules) = config.analysis.alert_rules {
            if let Some(v) = rules.dns_beaconing { db_guard.set_config("alert_rule_dns_beaconing", if v { "true" } else { "false" }).map_err(|e| format!("set alert rule: {e}"))?; }
            if let Some(v) = rules.dns_volume_spike { db_guard.set_config("alert_rule_dns_volume_spike", if v { "true" } else { "false" }).map_err(|e| format!("set alert rule: {e}"))?; }
            if let Some(v) = rules.new_dest_spike { db_guard.set_config("alert_rule_new_dest_spike", if v { "true" } else { "false" }).map_err(|e| format!("set alert rule: {e}"))?; }
            if let Some(v) = rules.suspicious_ports { db_guard.set_config("alert_rule_suspicious_ports", if v { "true" } else { "false" }).map_err(|e| format!("set alert rule: {e}"))?; }
            if let Some(v) = rules.bandwidth_spike { db_guard.set_config("alert_rule_bandwidth_spike", if v { "true" } else { "false" }).map_err(|e| format!("set alert rule: {e}"))?; }
        }

        // DMZ
        if let Some(ref dmz) = config.firewall.dmz_host {
            db_guard.set_config("dmz_host_ip", dmz).map_err(|e| format!("set dmz_host_ip: {e}"))?;
        } else {
            db_guard.set_config("dmz_host_ip", "").map_err(|e| format!("set dmz_host_ip: {e}"))?;
        }

        // UPnP
        if let Some(upnp) = config.firewall.upnp_enabled {
            db_guard.set_config("upnp_enabled", if upnp { "true" } else { "false" }).map_err(|e| format!("set upnp_enabled: {e}"))?;
        }

        // Apply secrets if provided (bypasses BLOCKED_CONFIG_KEYS since this is a direct DB write)
        if let Some(s) = secrets {
            if let Some(ref v) = s.admin_password_hash {
                if !v.starts_with("$argon2") {
                    return Err("invalid admin_password_hash format".to_string());
                }
                db_guard.set_config("admin_password_hash", v).map_err(|e| format!("set secret: {e}"))?;
            }
            if let Some(ref v) = s.session_secret {
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("invalid session_secret format".to_string());
                }
                db_guard.set_config("session_secret", v).map_err(|e| format!("set secret: {e}"))?;
            }
            if let Some(ref v) = s.wg_private_key {
                if v.len() != 44 || !v.ends_with('=') {
                    return Err("invalid wg_private_key format".to_string());
                }
                db_guard.set_config("wg_private_key", v).map_err(|e| format!("set secret: {e}"))?;
            }
            if let Some(ref tls) = s.tls {
                if let Some(ref v) = tls.key_pem { db_guard.set_config("tls_key_pem", v).map_err(|e| format!("set secret: {e}"))?; }
                if let Some(ref v) = tls.cert_pem { db_guard.set_config("tls_cert_pem", v).map_err(|e| format!("set secret: {e}"))?; }
                if let Some(ref v) = tls.acme_cf_api_token { db_guard.set_config("acme_cf_api_token", v).map_err(|e| format!("set secret: {e}"))?; }
                if let Some(ref v) = tls.acme_account_key { db_guard.set_config("acme_account_key", v).map_err(|e| format!("set secret: {e}"))?; }
            }
            if let Some(ref integ) = s.integrations
                && let Some(ref v) = integ.runzero_token
            {
                db_guard.set_config("runzero_token", v).map_err(|e| format!("set secret: {e}"))?;
            }
        }

        // Audit log
        let peer_names: Vec<&str> = config.wireguard.peers.iter().map(|p| p.name.as_str()).collect();
        let has_secrets = secrets.is_some();
        let _ = db_guard.log_audit("config_apply", &format!(
            "devices={} port_forwards={} peers={} peer_names=[{}] secrets={}",
            config.devices.len(), config.firewall.port_forwards.len(), config.wireguard.peers.len(),
            peer_names.join(", "), has_secrets));

        Ok(())
    })();

    if let Err(e) = db_write_result {
        let _ = db_guard.rollback_transaction();
        return Err(format!("config apply failed: {}", e));
    }

    db_guard.commit_transaction().map_err(|e| {
        let _ = db_guard.rollback_transaction();
        format!("commit: {}", e)
    })?;

    // Collect data needed for reconciliation before dropping the lock
    let qos_enabled = config.qos.enabled;
    let qos_upload = config.qos.upload_mbps;
    let qos_download = config.qos.download_mbps;
    let qos_devices: Vec<(String, String)> = if qos_enabled {
        let assigned = db_guard.list_assigned_devices().unwrap_or_default();
        assigned.iter()
            .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
            .collect()
    } else {
        Vec::new()
    };

    drop(db_guard);

    // --- Full reconciliation ---

    // 0. WireGuard peer nftables rules (collected during DB writes, applied after commit)
    for (ipv4, ipv6, group) in peer_subnets.values() {
        let _ = nftables::add_device_counter(ipv4);
        let _ = nftables::add_device_counter_v6(ipv6);
        let _ = nftables::add_device_forward_rule(ipv4, group);
        let _ = nftables::add_device_forward_rule_v6(ipv6, group);
    }

    // 0b. Reconcile live wg0 interface with new peer set
    let wg_enabled = {
        let db_guard = db.lock().unwrap();
        db_guard.get_config_bool("wg_enabled", false)
    };
    if wg_enabled {
        // Build lookup maps for old and new peer sets
        let old_peer_map: std::collections::HashMap<&str, &crate::db::WgPeer> = old_wg_peers.iter()
            .map(|p| (p.public_key.as_str(), p))
            .collect();
        let new_peer_map: std::collections::HashMap<&str, &hermitshell_common::WgPeerConfig> = config.wireguard.peers.iter()
            .map(|p| (p.public_key.as_str(), p))
            .collect();
        let (dev_base, dev_max) = nftables::device_range();

        // Remove peers no longer in config from wg0
        for old_peer in &old_wg_peers {
            if !new_peer_map.contains_key(old_peer.public_key.as_str())
                && let Some(info) = subnet::compute_subnet(old_peer.subnet_id, dev_base, dev_max)
            {
                let ipv4 = info.device_ipv4.to_string();
                let ipv6 = info.device_ipv6_ula.to_string();
                let _ = nftables::remove_device_forward_rule(&ipv4);
                let _ = nftables::remove_device_forward_rule_v6(&ipv6);
                let _ = crate::wireguard::remove_peer(&old_peer.public_key, &ipv4, &ipv6);
            }
        }

        // Add new peers to wg0
        for peer in &config.wireguard.peers {
            if !peer.enabled {
                continue;
            }
            if !old_peer_map.contains_key(peer.public_key.as_str())
                && let Some((ipv4, ipv6, _)) = peer_subnets.get(&peer.public_key)
            {
                let _ = crate::wireguard::add_peer(&peer.public_key, ipv4, ipv6);
            }
        }

        // Reconcile group changes for peers in both old and new sets.
        // The post-commit nftables loop (section 0) already added the new group's
        // forward rule using the new subnet IP, but the old group's rule on the
        // old subnet IP was never removed.
        for old_peer in &old_wg_peers {
            if let Some(new_peer) = new_peer_map.get(old_peer.public_key.as_str())
                && old_peer.device_group != new_peer.device_group
                && let Some(info) = subnet::compute_subnet(old_peer.subnet_id, dev_base, dev_max)
            {
                let ipv4 = info.device_ipv4.to_string();
                let ipv6 = info.device_ipv6_ula.to_string();
                let _ = nftables::remove_device_forward_rule(&ipv4);
                let _ = nftables::remove_device_forward_rule_v6(&ipv6);
            }
        }
    }

    // 1. Port forwards + DMZ (existing)
    portmap.reapply_rules();

    // 2. QoS (existing)
    let wan_iface = portmap.wan_iface();
    if qos_enabled && qos_upload > 0 && qos_download > 0 {
        let _ = crate::qos::enable(wan_iface, qos_upload, qos_download);
        let _ = crate::qos::apply_dscp_rules(&qos_devices);
    } else {
        let _ = crate::qos::disable(wan_iface);
        let _ = crate::qos::remove_dscp_rules();
    }

    // 3. DNS reconciliation (write_config + reload unbound)
    {
        let mut mgr = unbound.lock().unwrap();
        let _ = mgr.write_config(db);
        let _ = mgr.reload();
    }

    Ok(())
}

/// Handle `set_api_key` socket command: hash a plaintext API key and store it.
pub(super) fn handle_set_api_key(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref key) = req.value else {
        return Response::err("value required (plaintext API key)");
    };
    if key.len() < 16 {
        return Response::err("API key must be at least 16 characters");
    }
    if key.len() > 256 {
        return Response::err("API key must be at most 256 characters");
    }
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(key.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return Response::err(&format!("failed to hash API key: {}", e)),
    };
    let db = db.lock().unwrap();
    match db.set_config("api_key_hash", &hash) {
        Ok(()) => {
            let _ = db.log_audit("api_key_set", "API key updated");
            Response::ok()
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_backup_database(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let backup = Db::backup_path();
    let _ = std::fs::remove_file(&backup);
    match db.vacuum_into_backup() {
        Ok(()) => {
            let mut resp = Response::ok();
            resp.config_value = Some(backup);
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
    // Validate webhook URL before storing (SSRF protection)
    if let Some(url) = parsed.get("webhook_url").and_then(|v| v.as_str())
        && !url.is_empty()
        && let Err(e) = crate::unbound::validate_outbound_url(url, false)
    {
        return Response::err(&format!("invalid webhook_url: {}", e));
    }

    let db = db.lock().unwrap();
    let allowed_keys = ["log_format", "syslog_target", "webhook_url", "webhook_secret", "log_retention_days"];
    if let Some(obj) = parsed.as_object() {
        for (key, val) in obj {
            if allowed_keys.contains(&key.as_str())
                && let Some(v) = val.as_str() {
                    let _ = db.set_config(key, v);
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
    let has_token = db.get_config("runzero_token").ok().flatten().map(|t| !Zeroizing::new(t).is_empty()).unwrap_or(false);
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
    if let Some(interval_str) = parsed.get("runzero_sync_interval").and_then(|v| v.as_str())
        && let Ok(secs) = interval_str.parse::<u64>() {
            if secs >= 60 {
                let _ = db.set_config("runzero_sync_interval", interval_str);
            } else {
                return Response::err("sync interval must be >= 60 seconds");
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
        let token = Zeroizing::new(db.get_config("runzero_token").ok().flatten().unwrap_or_default());
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
            if let Some(host) = parsed.host_str()
                && let Ok(addr) = host.parse::<std::net::IpAddr>()
                && !crate::qos::is_public_ip(&addr) {
                        return Response::err("url must not point to private/loopback address");
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

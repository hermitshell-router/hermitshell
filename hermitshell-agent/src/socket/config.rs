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

pub(super) fn handle_export_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let devices = db.list_devices().unwrap_or_default();
    let reservations = db.list_dhcp_reservations().unwrap_or_default();
    let forwards = db.list_port_forwards().unwrap_or_default();
    let peers = db.list_wg_peers().unwrap_or_default();
    let pinholes: Vec<_> = db.list_ipv6_pinholes().unwrap_or_default()
        .into_iter()
        .filter(|p| matches!(p.get("protocol").and_then(|v| v.as_str()), Some("tcp" | "udp")))
        .collect();

    let config_keys = ["ad_blocking_enabled", "wg_listen_port", "dmz_host_ip", "log_format", "syslog_target", "webhook_url", "log_retention_days", "runzero_url", "runzero_sync_interval", "runzero_enabled", "qos_enabled", "qos_upload_mbps", "qos_download_mbps", "qos_test_url"];
    let mut config_map = serde_json::Map::new();
    for key in &config_keys {
        if let Ok(Some(val)) = db.get_config(key) {
            config_map.insert(key.to_string(), serde_json::Value::String(val));
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).expect("system clock before epoch").as_secs();

    let export = serde_json::json!({
        "version": 1,
        "exported_at": now,
        "devices": devices.iter().map(|d| serde_json::json!({
            "mac": d.mac, "hostname": d.hostname, "device_group": d.device_group, "subnet_id": d.subnet_id
        })).collect::<Vec<_>>(),
        "dhcp_reservations": reservations,
        "port_forwards": forwards,
        "wg_peers": peers.iter().map(|p| serde_json::json!({
            "public_key": p.public_key, "name": p.name, "subnet_id": p.subnet_id, "device_group": p.device_group
        })).collect::<Vec<_>>(),
        "ipv6_pinholes": pinholes,
        "config": config_map,
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
    if parsed.get("version").and_then(|v| v.as_i64()) != Some(1) {
        return Response::err("unsupported config version");
    }

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
    if let Some(devices) = parsed.get("devices").and_then(|v| v.as_array()) {
        for dev in devices {
            let mac = dev.get("mac").and_then(|v| v.as_str()).unwrap_or("");
            let group = dev.get("device_group").and_then(|v| v.as_str()).unwrap_or("quarantine");
            if !mac.is_empty() {
                let _ = db.set_device_group(mac, group);
                if let Some(hostname) = dev.get("hostname").and_then(|v| v.as_str()) {
                    let _ = db.set_device_hostname(mac, hostname);
                }
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

    if let Some(config) = parsed.get("config").and_then(|v| v.as_object()) {
        for (key, val) in config {
            match key.as_str() {
                "ad_blocking_enabled" | "wg_listen_port" | "dmz_host_ip" | "log_format" | "syslog_target" | "webhook_url" | "log_retention_days" | "runzero_url" | "runzero_sync_interval" | "runzero_enabled" | "qos_enabled" | "qos_upload_mbps" | "qos_download_mbps" | "qos_test_url" => {
                    if let Some(v) = val.as_str() {
                        let _ = db.set_config(key, v);
                    }
                }
                _ => {}
            }
        }
    }

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
    let mut resp = Response::ok();
    resp.runzero_config = Some(serde_json::json!({
        "runzero_url": url,
        "runzero_sync_interval": sync_interval,
        "enabled": enabled,
        "has_token": has_token,
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

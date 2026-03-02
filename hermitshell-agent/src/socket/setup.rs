use super::*;

pub(super) fn handle_list_interfaces(_req: &Request, _db: &Arc<Mutex<Db>>) -> Response {
    let mut interfaces = Vec::new();

    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(e) => return Response::err(&format!("cannot read /sys/class/net: {}", e)),
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip virtual interfaces
        if name == "lo"
            || name.starts_with("wg")
            || name.starts_with("docker")
            || name.starts_with("veth")
            || name.starts_with("br-")
            || name.starts_with("virbr")
            || name.starts_with("bond")
        {
            continue;
        }

        let mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", name))
            .unwrap_or_default()
            .trim()
            .to_string();
        let state = std::fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
            .unwrap_or_default()
            .trim()
            .to_string();
        let carrier = std::fs::read_to_string(format!("/sys/class/net/{}/carrier", name))
            .unwrap_or_default()
            .trim()
            == "1";

        interfaces.push(hermitshell_common::NetworkInterface {
            name,
            mac,
            state,
            has_carrier: carrier,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));

    let mut resp = Response::ok();
    resp.interfaces = Some(interfaces);
    resp
}

pub(super) fn handle_set_interfaces(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref wan) = req.key else {
        return Response::err("key required (WAN interface name)");
    };
    let Some(ref lan) = req.value else {
        return Response::err("value required (LAN interface name)");
    };

    if wan == lan {
        return Response::err("WAN and LAN must be different interfaces");
    }

    // Validate interface names before acquiring lock
    if let Err(e) = nftables::validate_iface(wan) {
        return Response::err(&format!("invalid WAN interface name: {}", e));
    }
    if let Err(e) = nftables::validate_iface(lan) {
        return Response::err(&format!("invalid LAN interface name: {}", e));
    }

    // Validate interfaces exist
    if !std::path::Path::new(&format!("/sys/class/net/{}", wan)).exists() {
        return Response::err(&format!("WAN interface '{}' not found", wan));
    }
    if !std::path::Path::new(&format!("/sys/class/net/{}", lan)).exists() {
        return Response::err(&format!("LAN interface '{}' not found", lan));
    }

    // Hold lock from password check through DB writes to prevent race condition
    let db = db.lock().unwrap();
    if db.get_config("admin_password_hash").ok().flatten().is_some() {
        return Response::err("interfaces can only be set during initial setup");
    }
    if let Err(e) = db.set_config("wan_iface", wan) {
        return Response::err(&format!("failed to store WAN: {}", e));
    }
    if let Err(e) = db.set_config("lan_iface", lan) {
        return Response::err(&format!("failed to store LAN: {}", e));
    }
    let _ = db.set_config("setup_step", "2");
    let _ = db.log_audit("set_interfaces", &format!("wan={}, lan={}", wan, lan));
    Response::ok()
}

pub(super) fn handle_setup_wan_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mode) = req.value else {
        return Response::err("value required (wan_mode: dhcp or static)");
    };

    match mode.as_str() {
        "dhcp" | "static" => {}
        _ => return Response::err("wan_mode must be 'dhcp' or 'static'"),
    }

    let db = db.lock().unwrap();
    if db.get_config("setup_complete").ok().flatten().as_deref() == Some("true") {
        return Response::err("WAN config can only be set during initial setup");
    }

    if let Err(e) = db.set_config("wan_mode", mode) {
        return Response::err(&format!("failed to store wan_mode: {}", e));
    }

    if mode == "static" {
        // Validate and store static IP fields from key (IP/mask), name (gateway), description (DNS)
        if let Some(ref ip) = req.key {
            let valid = if let Some((addr, prefix)) = ip.split_once('/') {
                addr.parse::<std::net::Ipv4Addr>().is_ok()
                    && prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
            } else {
                ip.parse::<std::net::Ipv4Addr>().is_ok()
            };
            if !valid {
                return Response::err("invalid static IP address");
            }
            let _ = db.set_config("wan_static_ip", ip);
        }
        if let Some(ref gw) = req.name {
            if gw.parse::<std::net::Ipv4Addr>().is_err() {
                return Response::err("invalid gateway address");
            }
            let _ = db.set_config("wan_static_gateway", gw);
        }
        if let Some(ref dns) = req.description {
            // DNS can be comma-separated IPs
            for part in dns.split(',') {
                if part.trim().parse::<std::net::IpAddr>().is_err() {
                    return Response::err(&format!("invalid DNS address: {}", part.trim()));
                }
            }
            let _ = db.set_config("wan_static_dns", dns);
        }
    }

    let _ = db.set_config("setup_step", "3");
    let _ = db.log_audit("setup_wan_config", mode);
    Response::ok()
}

pub(super) fn handle_set_hostname(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref hostname) = req.value else {
        return Response::err("value required (hostname)");
    };

    let clean = hermitshell_common::sanitize_hostname(hostname);
    if clean.is_empty() || clean.len() > 63 {
        return Response::err("invalid hostname");
    }

    let db = db.lock().unwrap();
    if db.get_config("setup_complete").ok().flatten().as_deref() == Some("true") {
        return Response::err("hostname can only be set during initial setup");
    }

    if let Err(e) = db.set_config("router_hostname", &clean) {
        return Response::err(&format!("failed to store hostname: {}", e));
    }

    // Apply to system
    let _ = std::process::Command::new("hostnamectl")
        .args(["set-hostname", &clean])
        .status();

    let _ = db.set_config("setup_step", "4");
    let _ = db.log_audit("set_hostname", &clean);
    Response::ok()
}

pub(super) fn handle_set_timezone(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref tz) = req.value else {
        return Response::err("value required (timezone)");
    };

    // Validate: must exist in zoneinfo and contain no path traversal
    if tz.contains("..") || tz.starts_with('/') {
        return Response::err("invalid timezone");
    }
    let tz_path = format!("/usr/share/zoneinfo/{}", tz);
    if !std::path::Path::new(&tz_path).exists() {
        return Response::err(&format!("unknown timezone: {}", tz));
    }

    let db = db.lock().unwrap();
    if db.get_config("setup_complete").ok().flatten().as_deref() == Some("true") {
        return Response::err("timezone can only be set during initial setup");
    }

    if let Err(e) = db.set_config("timezone", tz) {
        return Response::err(&format!("failed to store timezone: {}", e));
    }

    // Apply to system
    let _ = std::process::Command::new("timedatectl")
        .args(["set-timezone", tz])
        .status();

    let _ = db.log_audit("set_timezone", tz);
    Response::ok()
}

pub(super) fn handle_setup_set_dns(req: &Request, db: &Arc<Mutex<Db>>, unbound: &Arc<Mutex<UnboundManager>>) -> Response {
    let db_guard = db.lock().unwrap();
    if db_guard.get_config("admin_password_hash").ok().flatten().is_some()
        && db_guard.get_config("setup_complete").ok().flatten().as_deref() == Some("true") {
            return Response::err("DNS config during setup only");
        }

    // Store upstream DNS preference
    if let Some(ref dns) = req.value {
        if dns != "auto" {
            for part in dns.split(',') {
                if part.trim().parse::<std::net::IpAddr>().is_err() {
                    return Response::err(&format!("invalid DNS address: {}", part.trim()));
                }
            }
            let _ = db_guard.set_config("upstream_dns", dns);
        } else {
            let _ = db_guard.set_config("upstream_dns", "auto");
        }
    }

    // Ad blocking toggle
    if let Some(enabled) = req.enabled {
        let _ = db_guard.set_config("ad_blocking_enabled", if enabled { "true" } else { "false" });
    }

    let _ = db_guard.set_config("setup_step", "5");
    let _ = db_guard.log_audit("setup_set_dns", req.value.as_deref().unwrap_or("auto"));
    drop(db_guard);

    // Regenerate Unbound config and reload
    let mut mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();

    Response::ok()
}

pub(super) fn handle_get_setup_state(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let complete = db.get_config("setup_complete").ok().flatten().as_deref() == Some("true");
    let step: u32 = db.get_config("setup_step").ok().flatten()
        .and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::json!({"complete": complete, "step": step}).to_string());
    resp
}

pub(super) fn handle_setup_get_summary(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let wan_iface = db.get_config("wan_iface").ok().flatten().unwrap_or_default();
    let lan_iface = db.get_config("lan_iface").ok().flatten().unwrap_or_default();
    let wan_mode = db.get_config("wan_mode").ok().flatten().unwrap_or_else(|| "dhcp".to_string());
    let hostname = db.get_config("router_hostname").ok().flatten().unwrap_or_else(|| "hermitshell".to_string());
    let timezone = db.get_config("timezone").ok().flatten().unwrap_or_else(|| "UTC".to_string());
    let upstream_dns = db.get_config("upstream_dns").ok().flatten().unwrap_or_else(|| "auto".to_string());
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);

    let wan_static_ip = db.get_config("wan_static_ip").ok().flatten().unwrap_or_default();
    let wan_static_gateway = db.get_config("wan_static_gateway").ok().flatten().unwrap_or_default();
    let wan_static_dns = db.get_config("wan_static_dns").ok().flatten().unwrap_or_default();

    let summary = serde_json::json!({
        "wan_iface": wan_iface,
        "lan_iface": lan_iface,
        "wan_mode": wan_mode,
        "wan_static_ip": wan_static_ip,
        "wan_static_gateway": wan_static_gateway,
        "wan_static_dns": wan_static_dns,
        "hostname": hostname,
        "timezone": timezone,
        "upstream_dns": upstream_dns,
        "ad_blocking": ad_blocking,
    });

    let mut resp = Response::ok();
    resp.config_value = Some(summary.to_string());
    resp
}

pub(super) fn handle_finalize_setup(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    if db.get_config("admin_password_hash").ok().flatten().is_none() {
        return Response::err("password must be set before finalizing");
    }
    if let Err(e) = db.set_config("setup_complete", "true") {
        return Response::err(&format!("failed to finalize: {}", e));
    }
    let _ = db.set_config("setup_step", "8");
    let _ = db.log_audit("finalize_setup", "complete");
    Response::ok()
}

pub(super) fn handle_update_hostname(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref hostname) = req.value else {
        return Response::err("value required (hostname)");
    };

    let clean = hermitshell_common::sanitize_hostname(hostname);
    if clean.is_empty() || clean.len() > 63 {
        return Response::err("invalid hostname");
    }

    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("router_hostname", &clean) {
        return Response::err(&format!("failed to store hostname: {}", e));
    }

    let _ = std::process::Command::new("hostnamectl")
        .args(["set-hostname", &clean])
        .status();

    let _ = db.log_audit("update_hostname", &clean);
    Response::ok()
}

pub(super) fn handle_update_timezone(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref tz) = req.value else {
        return Response::err("value required (timezone)");
    };

    if tz.contains("..") || tz.starts_with('/') {
        return Response::err("invalid timezone");
    }
    let tz_path = format!("/usr/share/zoneinfo/{}", tz);
    if !std::path::Path::new(&tz_path).exists() {
        return Response::err(&format!("unknown timezone: {}", tz));
    }

    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("timezone", tz) {
        return Response::err(&format!("failed to store timezone: {}", e));
    }

    let _ = std::process::Command::new("timedatectl")
        .args(["set-timezone", tz])
        .status();

    let _ = db.log_audit("update_timezone", tz);
    Response::ok()
}

pub(super) fn handle_update_upstream_dns(req: &Request, db: &Arc<Mutex<Db>>, unbound: &Arc<Mutex<UnboundManager>>) -> Response {
    let Some(ref dns) = req.value else {
        return Response::err("value required (upstream DNS or 'auto')");
    };

    if dns != "auto" {
        for part in dns.split(',') {
            if part.trim().parse::<std::net::IpAddr>().is_err() {
                return Response::err(&format!("invalid DNS address: {}", part.trim()));
            }
        }
    }

    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_config("upstream_dns", dns) {
        return Response::err(&format!("failed to store upstream_dns: {}", e));
    }
    let _ = db_guard.log_audit("update_upstream_dns", dns);
    drop(db_guard);

    let mut mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();

    Response::ok()
}

pub(super) fn handle_update_wan_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mode) = req.value else {
        return Response::err("value required (wan_mode: dhcp or static)");
    };

    match mode.as_str() {
        "dhcp" | "static" => {}
        _ => return Response::err("wan_mode must be 'dhcp' or 'static'"),
    }

    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("wan_mode", mode) {
        return Response::err(&format!("failed to store wan_mode: {}", e));
    }

    if mode == "static" {
        if let Some(ref ip) = req.key {
            let valid = if let Some((addr, prefix)) = ip.split_once('/') {
                addr.parse::<std::net::Ipv4Addr>().is_ok()
                    && prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
            } else {
                ip.parse::<std::net::Ipv4Addr>().is_ok()
            };
            if !valid {
                return Response::err("invalid static IP address");
            }
            let _ = db.set_config("wan_static_ip", ip);
        }
        if let Some(ref gw) = req.name {
            if gw.parse::<std::net::Ipv4Addr>().is_err() {
                return Response::err("invalid gateway address");
            }
            let _ = db.set_config("wan_static_gateway", gw);
        }
        if let Some(ref dns) = req.description {
            for part in dns.split(',') {
                if part.trim().parse::<std::net::IpAddr>().is_err() {
                    return Response::err(&format!("invalid DNS address: {}", part.trim()));
                }
            }
            let _ = db.set_config("wan_static_dns", dns);
        }
    }

    let _ = db.log_audit("update_wan_config", mode);
    Response::ok()
}

pub(super) fn handle_update_interfaces(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref wan) = req.key else {
        return Response::err("key required (WAN interface name)");
    };
    let Some(ref lan) = req.value else {
        return Response::err("value required (LAN interface name)");
    };

    if wan == lan {
        return Response::err("WAN and LAN must be different interfaces");
    }

    if let Err(e) = nftables::validate_iface(wan) {
        return Response::err(&format!("invalid WAN interface name: {}", e));
    }
    if let Err(e) = nftables::validate_iface(lan) {
        return Response::err(&format!("invalid LAN interface name: {}", e));
    }

    if !std::path::Path::new(&format!("/sys/class/net/{}", wan)).exists() {
        return Response::err(&format!("WAN interface '{}' not found", wan));
    }
    if !std::path::Path::new(&format!("/sys/class/net/{}", lan)).exists() {
        return Response::err(&format!("LAN interface '{}' not found", lan));
    }

    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("wan_iface", wan) {
        return Response::err(&format!("failed to store WAN: {}", e));
    }
    if let Err(e) = db.set_config("lan_iface", lan) {
        return Response::err(&format!("failed to store LAN: {}", e));
    }
    let _ = db.log_audit("update_interfaces", &format!("wan={}, lan={}", wan, lan));
    Response::ok()
}

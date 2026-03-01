use super::*;

pub(super) fn handle_get_dns_config(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let per_client = db
        .get_config("dns_ratelimit_per_client")
        .ok()
        .flatten()
        .unwrap_or_else(|| "0".to_string());
    let per_domain = db
        .get_config("dns_ratelimit_per_domain")
        .ok()
        .flatten()
        .unwrap_or_else(|| "0".to_string());
    let upstream = db
        .get_config("upstream_dns")
        .ok()
        .flatten()
        .unwrap_or_else(|| "auto".to_string());
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);

    let config = serde_json::json!({
        "ratelimit_per_client": per_client,
        "ratelimit_per_domain": per_domain,
        "upstream_dns": upstream,
        "ad_blocking_enabled": ad_blocking,
    });
    let mut resp = Response::ok();
    resp.dns_config = Some(config);
    resp
}

pub(super) fn handle_set_dns_config(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(ref value) = req.value else {
        return Response::err("value required (JSON object)");
    };
    let parsed: serde_json::Value = match serde_json::from_str(value) {
        Ok(v) => v,
        Err(e) => return Response::err(&format!("invalid JSON: {}", e)),
    };

    let db_guard = db.lock().unwrap();
    if let Some(v) = parsed
        .get("ratelimit_per_client")
        .and_then(|v| v.as_str())
    {
        if v.parse::<u32>().is_err() {
            return Response::err("ratelimit_per_client must be a non-negative integer");
        }
        let _ = db_guard.set_config("dns_ratelimit_per_client", v);
    }
    if let Some(v) = parsed
        .get("ratelimit_per_domain")
        .and_then(|v| v.as_str())
    {
        if v.parse::<u32>().is_err() {
            return Response::err("ratelimit_per_domain must be a non-negative integer");
        }
        let _ = db_guard.set_config("dns_ratelimit_per_domain", v);
    }
    drop(db_guard);

    let mgr = unbound.lock().unwrap();
    if let Err(e) = mgr.write_config(db) {
        return Response::err(&format!("failed to write config: {}", e));
    }
    let _ = mgr.reload();
    Response::ok()
}

pub(super) fn handle_list_dns_forwards(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let zones = db.list_dns_forward_zones().unwrap_or_default();
    let mut resp = Response::ok();
    resp.dns_forward_zones = Some(zones);
    resp
}

pub(super) fn handle_add_dns_forward(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(ref domain) = req.name else {
        return Response::err("name required (domain)");
    };
    let Some(ref forward_addr) = req.value else {
        return Response::err("value required (forward_addr IP)");
    };

    if let Err(e) = crate::unbound::validate_domain(domain) {
        return Response::err(&format!("invalid domain: {}", e));
    }
    if forward_addr.parse::<std::net::IpAddr>().is_err() {
        return Response::err("invalid forward address (must be IP)");
    }

    let db_guard = db.lock().unwrap();
    match db_guard.add_dns_forward_zone(domain, forward_addr) {
        Ok(id) => {
            drop(db_guard);
            let mgr = unbound.lock().unwrap();
            let _ = mgr.write_config(db);
            let _ = mgr.reload();
            let mut resp = Response::ok();
            resp.id = Some(id);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_remove_dns_forward(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.remove_dns_forward_zone(id) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);
    let mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}

pub(super) fn handle_list_dns_rules(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let rules = db.list_dns_custom_rules().unwrap_or_default();
    let mut resp = Response::ok();
    resp.dns_custom_rules = Some(rules);
    resp
}

pub(super) fn handle_add_dns_rule(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(ref domain) = req.name else {
        return Response::err("name required (domain)");
    };
    let record_type = req.key.as_deref().unwrap_or("A");
    let Some(ref value) = req.value else {
        return Response::err("value required (record value)");
    };

    if let Err(e) = crate::unbound::validate_domain(domain) {
        return Response::err(&format!("invalid domain: {}", e));
    }

    let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT"];
    if !valid_types.contains(&record_type) {
        return Response::err("record type must be A, AAAA, CNAME, MX, or TXT");
    }

    // Validate value based on type
    match record_type {
        "A" => {
            if value.parse::<std::net::Ipv4Addr>().is_err() {
                return Response::err("A record value must be a valid IPv4 address");
            }
        }
        "AAAA" => {
            if value.parse::<std::net::Ipv6Addr>().is_err() {
                return Response::err("AAAA record value must be a valid IPv6 address");
            }
        }
        "CNAME" | "MX" => {
            if let Err(e) = crate::unbound::validate_domain(value) {
                return Response::err(&format!("invalid target domain: {}", e));
            }
        }
        _ => {} // TXT can be any string
    }

    let db_guard = db.lock().unwrap();
    match db_guard.add_dns_custom_rule(domain, record_type, value) {
        Ok(id) => {
            drop(db_guard);
            let mgr = unbound.lock().unwrap();
            let _ = mgr.write_config(db);
            let _ = mgr.reload();
            let mut resp = Response::ok();
            resp.id = Some(id);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_remove_dns_rule(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.remove_dns_custom_rule(id) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);
    let mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}

pub(super) fn handle_list_dns_blocklists(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let lists = db.list_dns_blocklists().unwrap_or_default();
    let mut resp = Response::ok();
    resp.dns_blocklists = Some(lists);
    resp
}

pub(super) fn handle_add_dns_blocklist(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let Some(ref url) = req.url else {
        return Response::err("url required");
    };
    let tag = req.key.as_deref().unwrap_or("ads");

    // Validate URL: require HTTPS, reject internal IPs (SSRF protection)
    if let Err(e) = crate::unbound::validate_outbound_url(url, false) {
        return Response::err(&format!("invalid blocklist URL: {}", e));
    }

    // Validate tag
    let valid_tags = ["ads", "custom", "strict"];
    if !valid_tags.contains(&tag) {
        return Response::err("tag must be ads, custom, or strict");
    }

    if name.len() > 128 {
        return Response::err("name too long (max 128 chars)");
    }

    let db_guard = db.lock().unwrap();
    match db_guard.add_dns_blocklist(name, url, tag) {
        Ok(id) => {
            drop(db_guard);
            let mgr = unbound.lock().unwrap();
            // Download the new blocklist and rebuild config
            let _ = mgr.download_blocklists(db);
            let _ = mgr.write_config(db);
            let _ = mgr.reload();
            let mut resp = Response::ok();
            resp.id = Some(id);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_remove_dns_blocklist(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.remove_dns_blocklist(id) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);

    // Remove the blocklist file
    let path = format!(
        "{}/{}.conf",
        crate::paths::blocklist_dir(), id
    );
    let _ = std::fs::remove_file(&path);

    let mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}

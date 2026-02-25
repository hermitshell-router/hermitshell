use super::*;

pub(super) fn handle_list_port_forwards(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_port_forwards() {
        Ok(forwards) => {
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let mut resp = Response::ok();
            resp.port_forwards = Some(forwards);
            resp.dmz_ip = Some(dmz);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_add_port_forward(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str, lan_iface: &str) -> Response {
    let Some(ref protocol) = req.protocol else { return Response::err("protocol required"); };
    let Some(ext_start) = req.external_port_start else { return Response::err("external_port_start required"); };
    let Some(ext_end) = req.external_port_end else { return Response::err("external_port_end required"); };
    let Some(ref internal_ip) = req.internal_ip else { return Response::err("internal_ip required"); };
    let Some(int_port) = req.internal_port else { return Response::err("internal_port required"); };
    let desc = req.description.as_deref().unwrap_or("");
    match protocol.as_str() {
        "tcp" | "udp" | "both" => {}
        _ => return Response::err("protocol must be tcp, udp, or both"),
    }
    if ext_start == 0 || ext_end == 0 || int_port == 0 {
        return Response::err("ports must be 1-65535");
    }
    if ext_end < ext_start {
        return Response::err("external_port_end must be >= external_port_start");
    }
    if let Err(e) = nftables::validate_ip(internal_ip) {
        return Response::err(&e.to_string());
    }
    let db = db.lock().unwrap();
    // Check for overlapping external port ranges on same protocol
    if let Ok(existing) = db.list_port_forwards() {
        for fwd in &existing {
            let protocols_overlap = protocol == &fwd.protocol
                || protocol == "both"
                || fwd.protocol == "both";
            let ports_overlap = ext_start <= fwd.external_port_end
                && ext_end >= fwd.external_port_start;
            if protocols_overlap && ports_overlap {
                return Response::err(&format!(
                    "external ports {}-{} overlap with existing forward '{}' (ports {}-{})",
                    ext_start, ext_end, fwd.description,
                    fwd.external_port_start, fwd.external_port_end
                ));
            }
        }
    }
    match db.add_port_forward(protocol, ext_start, ext_end, internal_ip, int_port, desc) {
        Ok(_id) => {
            let forwards = db.list_enabled_port_forwards().unwrap_or_default();
            let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
            let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
            if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                return Response::err(&format!("failed to apply rules: {}", e));
            }
            Response::ok()
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_remove_port_forward(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str, lan_iface: &str) -> Response {
    let Some(id) = req.id else { return Response::err("id required"); };
    let db = db.lock().unwrap();
    if let Err(e) = db.remove_port_forward(id) {
        return Response::err(&e.to_string());
    }
    let forwards = db.list_enabled_port_forwards().unwrap_or_default();
    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
    let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
    if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
        return Response::err(&format!("failed to apply rules: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_set_port_forward_enabled(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str, lan_iface: &str) -> Response {
    let Some(id) = req.id else { return Response::err("id required"); };
    let Some(enabled) = req.enabled else { return Response::err("enabled required"); };
    let db = db.lock().unwrap();
    if let Err(e) = db.set_port_forward_enabled(id, enabled) {
        return Response::err(&e.to_string());
    }
    let forwards = db.list_enabled_port_forwards().unwrap_or_default();
    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
    let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
    if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
        return Response::err(&format!("failed to apply rules: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_get_dmz(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let dmz = db.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
    let mut resp = Response::ok();
    resp.dmz_ip = Some(dmz);
    resp
}

pub(super) fn handle_set_dmz(req: &Request, db: &Arc<Mutex<Db>>, wan_iface: &str, lan_iface: &str) -> Response {
    let Some(ref ip) = req.internal_ip else { return Response::err("internal_ip required (empty string to clear)"); };
    if !ip.is_empty() {
        if let Err(e) = nftables::validate_ip(ip) {
            return Response::err(&e.to_string());
        }
    }
    let db = db.lock().unwrap();
    if let Err(e) = db.set_config("dmz_host_ip", ip) {
        return Response::err(&e.to_string());
    }
    let forwards = db.list_enabled_port_forwards().unwrap_or_default();
    let dmz_ref = if ip.is_empty() { None } else { Some(ip.as_str()) };
    if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
        return Response::err(&format!("failed to apply rules: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_add_ipv6_pinhole(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else { return Response::err("mac required"); };
    let Some(ref protocol) = req.protocol else { return Response::err("protocol required"); };
    let Some(port_start) = req.port_start else { return Response::err("port_start required"); };
    let Some(port_end) = req.port_end else { return Response::err("port_end required"); };
    let desc = req.description.as_deref().unwrap_or("");
    match protocol.as_str() {
        "tcp" | "udp" => {}
        _ => return Response::err("protocol must be tcp or udp"),
    }
    if port_start == 0 || port_end == 0 {
        return Response::err("ports must be 1-65535");
    }
    if port_end < port_start {
        return Response::err("port_end must be >= port_start");
    }
    let db = db.lock().unwrap();
    let device = match db.get_device(mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    let Some(ref ipv6_global) = device.ipv6_global else {
        return Response::err("device has no global IPv6 address (no prefix delegation)");
    };
    if let Err(e) = nftables::add_ipv6_pinhole(ipv6_global, protocol, port_start, port_end) {
        return Response::err(&format!("failed to add nftables rule: {}", e));
    }
    match db.add_ipv6_pinhole(mac, protocol, port_start as i64, port_end as i64, desc) {
        Ok(id) => {
            let mut resp = Response::ok();
            resp.config_value = Some(id.to_string());
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_remove_ipv6_pinhole(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(id) = req.id else { return Response::err("id required"); };
    let db = db.lock().unwrap();
    let pinhole = match db.get_ipv6_pinhole(id) {
        Ok(Some(p)) => p,
        Ok(None) => return Response::err("pinhole not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    let (mac, protocol, port_start, port_end) = pinhole;
    let device = match db.get_device(&mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    if let Some(ref ipv6_global) = device.ipv6_global {
        if let Err(e) = nftables::remove_ipv6_pinhole(ipv6_global, &protocol, port_start as u16, port_end as u16) {
            return Response::err(&format!("failed to remove nftables rule: {}", e));
        }
    }
    match db.remove_ipv6_pinhole(id) {
        Ok(true) => Response::ok(),
        Ok(false) => Response::err("pinhole not found"),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_list_ipv6_pinholes(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_ipv6_pinholes() {
        Ok(pinholes) => {
            let mut resp = Response::ok();
            resp.ipv6_pinholes = Some(pinholes);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

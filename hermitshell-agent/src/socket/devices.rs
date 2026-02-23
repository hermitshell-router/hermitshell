use super::*;

pub(super) fn handle_list_devices(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_devices() {
        Ok(devices) => {
            let mut resp = Response::ok();
            resp.devices = Some(devices);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_get_device(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    match db.get_device(mac) {
        Ok(Some(device)) => {
            let mut resp = Response::ok();
            resp.device = Some(device);
            resp
        }
        Ok(None) => Response::err("device not found"),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_get_status(_req: &Request, db: &Arc<Mutex<Db>>, start_time: std::time::Instant) -> Response {
    let db = db.lock().unwrap();
    let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);
    let mut resp = Response::ok();
    resp.status = Some(Status {
        uptime_secs: start_time.elapsed().as_secs(),
        device_count,
        ad_blocking_enabled: ad_blocking,
    });
    resp
}

pub(super) fn handle_set_device_group(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let Some(ref group) = req.group else {
        return Response::err("group required");
    };
    if !USER_ASSIGNABLE_GROUPS.contains(&group.as_str()) {
        return Response::err("invalid group: must be quarantine, trusted, iot, guest, or servers");
    }
    let db = db.lock().unwrap();
    let device = match db.get_device(mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    let Some(subnet_id) = device.subnet_id else {
        return Response::err("device has no subnet assignment");
    };
    let Some(info) = subnet::compute_subnet(subnet_id) else {
        return Response::err("invalid subnet_id");
    };
    let ipv4 = info.device_ipv4.to_string();
    let ipv6 = info.device_ipv6_ula.to_string();
    if let Err(e) = nftables::remove_device_forward_rule(&ipv4) {
        return Response::err(&format!("failed to remove old rule: {}", e));
    }
    // best-effort: IPv6 rule may not exist yet
    let _ = nftables::remove_device_forward_rule_v6(&ipv6);
    if let Err(e) = db.set_device_group(mac, group) {
        return Response::err(&format!("failed to update group: {}", e));
    }
    if let Err(e) = nftables::add_device_forward_rule(&ipv4, group) {
        return Response::err(&format!("failed to add new rule: {}", e));
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    let _ = nftables::add_device_forward_rule_v6(&ipv6, group);
    let qos_enabled = db.get_config_bool("qos_enabled", false);
    if qos_enabled {
        let assigned = db.list_assigned_devices().unwrap_or_default();
        let devices: Vec<(String, String)> = assigned.iter()
            .filter_map(|d| d.ipv4.as_ref().map(|ip| (ip.clone(), d.device_group.clone())))
            .collect();
        // best-effort: QoS failure should not block group change
        let _ = crate::qos::apply_dscp_rules(&devices);
    }
    match db.get_device(mac) {
        Ok(Some(device)) => {
            let mut resp = Response::ok();
            resp.device = Some(device);
            resp
        }
        Ok(None) => Response::err("device not found after update"),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_block_device(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    let device = match db.get_device(mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    if let Some(ref ip) = device.ipv4 {
        if let Err(e) = nftables::remove_device_forward_rule(ip) {
            return Response::err(&format!("failed to remove forward rule: {}", e));
        }
        if let Err(e) = nftables::add_device_forward_rule(ip, "blocked") {
            return Response::err(&format!("failed to add blocked rule: {}", e));
        }
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    if let Some(ref ipv6) = device.ipv6_ula {
        let _ = nftables::remove_device_forward_rule_v6(ipv6);
        let _ = nftables::add_device_forward_rule_v6(ipv6, "blocked");
    }
    if let Err(e) = db.block_device(mac) {
        return Response::err(&format!("failed to block device: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_unblock_device(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    let device = match db.get_device(mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    if let Err(e) = db.unblock_device(mac) {
        return Response::err(&format!("failed to unblock device: {}", e));
    }
    if let Some(ref ip) = device.ipv4 {
        if let Err(e) = nftables::remove_device_forward_rule(ip) {
            return Response::err(&format!("failed to remove blocked rule: {}", e));
        }
        if let Err(e) = nftables::add_device_forward_rule(ip, "quarantine") {
            return Response::err(&format!("failed to add forward rule: {}", e));
        }
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    if let Some(ref ipv6) = device.ipv6_ula {
        let _ = nftables::remove_device_forward_rule_v6(ipv6);
        let _ = nftables::add_device_forward_rule_v6(ipv6, "quarantine");
    }
    Response::ok()
}

pub(super) fn handle_set_device_nickname(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let nickname = req.nickname.as_deref().unwrap_or("");
    let db = db.lock().unwrap();
    match db.set_device_nickname(mac, nickname) {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_list_dhcp_reservations(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.list_dhcp_reservations() {
        Ok(reservations) => {
            let mut resp = Response::ok();
            resp.dhcp_reservations = Some(reservations);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_set_dhcp_reservation(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    let subnet_id = match req.subnet_id {
        Some(sid) => sid,
        None => {
            match db.get_device(mac) {
                Ok(Some(dev)) if dev.subnet_id.is_some() => dev.subnet_id.unwrap(),
                Ok(_) => return Response::err("device has no subnet assignment; provide subnet_id"),
                Err(e) => return Response::err(&e.to_string()),
            }
        }
    };
    if subnet::compute_subnet(subnet_id).is_none() {
        return Response::err("subnet_id out of range");
    }
    if let Err(e) = db.set_dhcp_reservation(mac, subnet_id) {
        return Response::err(&format!("failed to set reservation: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_remove_dhcp_reservation(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref mac) = req.mac else {
        return Response::err("mac required");
    };
    let db = db.lock().unwrap();
    if let Err(e) = db.remove_dhcp_reservation(mac) {
        return Response::err(&format!("failed to remove reservation: {}", e));
    }
    Response::ok()
}

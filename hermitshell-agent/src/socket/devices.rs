use super::*;

/// Suggest a device group based on runZero device type.
pub fn suggest_group(runzero_device_type: Option<&str>) -> Option<&'static str> {
    match runzero_device_type? {
        "phone" | "laptop" | "tablet" | "desktop" | "workstation" => Some("trusted"),
        "printer" | "media player" | "speaker" | "camera" | "iot"
        | "smart tv" | "streaming" | "display" | "nas" | "server" => Some("iot"),
        _ => None,
    }
}

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

pub(super) fn handle_get_status(
    _req: &Request,
    db: &Arc<Mutex<Db>>,
    start_time: std::time::Instant,
    wan_lease: &crate::wan::SharedWanLease,
) -> Response {
    let db = db.lock().unwrap();
    let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);
    let lease_guard = wan_lease.lock().unwrap();
    let (wan_ip, wan_gateway, wan_dns) = match lease_guard.as_ref() {
        Some(l) => (
            Some(l.ip.to_string()),
            Some(l.gateway.to_string()),
            Some(l.dns_servers.iter().map(|d| d.to_string()).collect()),
        ),
        None => (None, None, None),
    };
    drop(lease_guard);
    let mut resp = Response::ok();
    resp.status = Some(Status {
        uptime_secs: start_time.elapsed().as_secs(),
        device_count,
        ad_blocking_enabled: ad_blocking,
        wan_ip,
        wan_gateway,
        wan_dns,
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
    let Some(ref ipv4) = device.ipv4 else {
        return Response::err("device has no IPv4 address");
    };
    let ipv6 = device.ipv6_ula.clone().unwrap_or_default();
    if let Err(e) = nftables::remove_device_forward_rule(ipv4) {
        return Response::err(&format!("failed to remove old rule: {}", e));
    }
    // best-effort: IPv6 rule may not exist yet
    let _ = nftables::remove_device_forward_rule_v6(&ipv6);
    if let Err(e) = db.set_device_group(mac, group) {
        return Response::err(&format!("failed to update group: {}", e));
    }
    if let Err(e) = nftables::add_device_forward_rule(ipv4, group) {
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
    // VLAN reassignment: when VLAN mode is enabled, log the intent.
    // The actual switch port VLAN change happens via:
    // 1. Next switch polling cycle (60s) detects mismatch
    // 2. Manual switch_provision_vlans command
    // 3. Device gets new IP on next DHCP renewal in new VLAN subnet
    let vlan_enabled = db.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled");
    if vlan_enabled
        && let Ok(Some(vlan_cfg)) = db.get_vlan_for_group(group) {
            info!(
                mac = %mac, group = %group, vlan_id = vlan_cfg.vlan_id,
                switch_port = ?device.switch_port,
                "device group changed, VLAN reassignment pending"
            );
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
    let raw = req.nickname.as_deref().unwrap_or("");
    let nickname: String = raw.chars()
        .filter(|c| !c.is_control())
        .collect();
    if nickname.len() > 256 {
        return Response::err("nickname too long (max 256 bytes)");
    }
    let db = db.lock().unwrap();
    match db.set_device_nickname(mac, &nickname) {
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
    let (dev_base, dev_max) = nftables::device_range();
    if subnet::compute_subnet(subnet_id, dev_base, dev_max).is_none() {
        return Response::err("subnet_id out of range");
    }
    if let Err(e) = db.set_dhcp_reservation(mac, subnet_id) {
        return Response::err(&format!("failed to set reservation: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_list_mdns_services(req: &Request, db: &Arc<Mutex<Db>>, registry: &crate::mdns::SharedRegistry) -> Response {
    let mac = match req.mac.as_ref() {
        Some(m) => m,
        None => return Response::err("mac required"),
    };
    let db_guard = db.lock().unwrap();
    let _device = match db_guard.get_device(mac) {
        Ok(Some(d)) => d,
        Ok(None) => return Response::err("device not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    let reg = registry.lock().unwrap();
    let services = reg.services_for_device(mac);
    Response {
        ok: true,
        mdns_services: Some(services),
        ..Default::default()
    }
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

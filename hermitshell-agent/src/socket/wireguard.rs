use super::*;
use zeroize::Zeroizing;

pub(super) fn handle_get_wireguard(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    let enabled = db.get_config_bool("wg_enabled", false);
    let public_key = if enabled {
        db.get_config("wg_private_key").ok().flatten().and_then(|privkey| {
            let privkey = Zeroizing::new(privkey);
            crate::wireguard::pubkey_from_private(&privkey).ok()
        })
    } else {
        None
    };
    let listen_port: u16 = db.get_config("wg_listen_port")
        .ok().flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(51820);
    let (dev_base, dev_max) = nftables::device_range();
    let peers = db.list_wg_peers().unwrap_or_default();
    let peer_infos: Vec<WgPeerInfo> = peers.iter().filter_map(|p| {
        let info = subnet::compute_subnet(p.subnet_id, dev_base, dev_max)?;
        Some(WgPeerInfo {
            public_key: p.public_key.clone(),
            name: p.name.clone(),
            ipv4: info.device_ipv4.to_string(),
            ipv6_ula: info.device_ipv6_ula.to_string(),
            device_group: p.device_group.clone(),
            enabled: p.enabled,
        })
    }).collect();
    let mut resp = Response::ok();
    resp.wireguard = Some(WireguardInfo {
        enabled,
        public_key,
        listen_port,
        peers: peer_infos,
    });
    resp
}

pub(super) fn handle_set_wireguard_enabled(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required");
    };
    let db = db.lock().unwrap();
    let (dev_base, dev_max) = nftables::device_range();
    if enabled {
        let private_key = match db.get_config("wg_private_key").ok().flatten() {
            Some(key) => Zeroizing::new(key),
            None => {
                let (privkey, _pubkey) = match crate::wireguard::generate_keypair() {
                    Ok(kp) => kp,
                    Err(e) => return Response::err(&format!("keygen failed: {}", e)),
                };
                if let Err(e) = db.set_config("wg_private_key", &privkey) {
                    return Response::err(&format!("failed to store key: {}", e));
                }
                Zeroizing::new(privkey)
            }
        };
        let listen_port: u16 = db.get_config("wg_listen_port")
            .ok().flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(51820);
        let lan_ip = db.get_config("lan_ip").ok().flatten().unwrap_or_else(|| "10.0.0.1".into());
        let lan_ip_v6 = db.get_config("lan_ip_v6").ok().flatten().unwrap_or_else(|| "fd00::1".into());
        if let Err(e) = crate::wireguard::create_interface(&private_key, listen_port, &lan_ip, &lan_ip_v6) {
            return Response::err(&format!("failed to create wg0: {}", e));
        }
        if let Err(e) = crate::wireguard::open_listen_port(listen_port) {
            return Response::err(&format!("failed to open port: {}", e));
        }
        // Re-add all enabled peers after creating the interface.
        // Individual failures are non-fatal: remaining peers should still be provisioned.
        let peers = db.list_wg_peers().unwrap_or_default();
        for peer in &peers {
            if !peer.enabled { continue; }
            if let Some(info) = subnet::compute_subnet(peer.subnet_id, dev_base, dev_max) {
                let ipv4 = info.device_ipv4.to_string();
                let ipv6 = info.device_ipv6_ula.to_string();
                let _ = crate::wireguard::add_peer(&peer.public_key, &ipv4, &ipv6);
                let _ = nftables::add_device_counter(&ipv4);
                let _ = nftables::add_device_counter_v6(&ipv6);
                let _ = nftables::add_device_forward_rule(&ipv4, &peer.device_group);
                let _ = nftables::add_device_forward_rule_v6(&ipv6, &peer.device_group);
            }
        }
        if let Err(e) = db.set_config("wg_enabled", "true") {
            return Response::err(&format!("failed to save config: {}", e));
        }
    } else {
        // Tear down WireGuard: clean up all peers then destroy the interface.
        // best-effort throughout: partial cleanup is acceptable on disable.
        let peers = db.list_wg_peers().unwrap_or_default();
        for peer in &peers {
            if let Some(info) = subnet::compute_subnet(peer.subnet_id, dev_base, dev_max) {
                let ipv4 = info.device_ipv4.to_string();
                let ipv6 = info.device_ipv6_ula.to_string();
                let _ = nftables::remove_device_forward_rule(&ipv4);
                let _ = nftables::remove_device_forward_rule_v6(&ipv6);
                let _ = crate::wireguard::remove_peer(&peer.public_key, &ipv4, &ipv6);
            }
        }
        let _ = crate::wireguard::close_listen_port();
        let _ = crate::wireguard::destroy_interface();
        if let Err(e) = db.set_config("wg_enabled", "false") {
            return Response::err(&format!("failed to save config: {}", e));
        }
    }
    Response::ok()
}

pub(super) fn handle_add_wg_peer(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    if name.is_empty() || sanitize_hostname(name) != *name {
        return Response::err("invalid peer name (alphanumeric, hyphens, dots, underscores; max 63 chars)");
    }
    let Some(ref public_key) = req.public_key else {
        return Response::err("public_key required");
    };
    let group = req.group.as_deref().unwrap_or("quarantine");
    if !USER_ASSIGNABLE_GROUPS.contains(&group) {
        return Response::err("invalid group");
    }
    let db = db.lock().unwrap();
    let wg_enabled = db.get_config_bool("wg_enabled", false);
    if !wg_enabled {
        return Response::err("WireGuard is not enabled");
    }
    if let Ok(Some(_)) = db.get_wg_peer(public_key) {
        return Response::err("peer already exists");
    }
    let (dev_base, dev_max) = nftables::device_range();
    let subnet_id = match db.allocate_subnet_id(dev_max + 1) {
        Ok(s) => s,
        Err(e) => return Response::err(&format!("subnet allocation failed: {}", e)),
    };
    let Some(info) = subnet::compute_subnet(subnet_id, dev_base, dev_max) else {
        return Response::err("subnet address space exhausted");
    };
    let ipv4 = info.device_ipv4.to_string();
    let ipv6 = info.device_ipv6_ula.to_string();
    if let Err(e) = crate::wireguard::add_peer(public_key, &ipv4, &ipv6) {
        return Response::err(&format!("failed to add peer: {}", e));
    }
    if let Err(e) = nftables::add_device_counter(&ipv4) {
        return Response::err(&format!("failed to add counter: {}", e));
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    let _ = nftables::add_device_counter_v6(&ipv6);
    if let Err(e) = nftables::add_device_forward_rule(&ipv4, group) {
        return Response::err(&format!("failed to add forward rule: {}", e));
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    let _ = nftables::add_device_forward_rule_v6(&ipv6, group);
    if let Err(e) = db.insert_wg_peer(public_key, name, subnet_id, group) {
        return Response::err(&format!("failed to save peer: {}", e));
    }
    let server_pubkey = db.get_config("wg_private_key")
        .ok().flatten()
        .and_then(|k| {
            let k = zeroize::Zeroizing::new(k);
            crate::wireguard::pubkey_from_private(&k).ok()
        })
        .unwrap_or_default();
    let listen_port: u16 = db.get_config("wg_listen_port")
        .ok().flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(51820);
    let mut resp = Response::ok();
    resp.device_ipv4 = Some(ipv4);
    resp.device_ipv6_ula = Some(ipv6);
    resp.wireguard = Some(WireguardInfo {
        enabled: true,
        public_key: Some(server_pubkey),
        listen_port,
        peers: vec![],
    });
    resp
}

pub(super) fn handle_remove_wg_peer(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref public_key) = req.public_key else {
        return Response::err("public_key required");
    };
    let db = db.lock().unwrap();
    let peer = match db.get_wg_peer(public_key) {
        Ok(Some(p)) => p,
        Ok(None) => return Response::err("peer not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    // best-effort cleanup: peer/rules may already be gone
    let (dev_base, dev_max) = nftables::device_range();
    if let Some(info) = subnet::compute_subnet(peer.subnet_id, dev_base, dev_max) {
        let ipv4 = info.device_ipv4.to_string();
        let ipv6 = info.device_ipv6_ula.to_string();
        let _ = nftables::remove_device_forward_rule(&ipv4);
        let _ = nftables::remove_device_forward_rule_v6(&ipv6);
        let _ = crate::wireguard::remove_peer(public_key, &ipv4, &ipv6);
    }
    if let Err(e) = db.remove_wg_peer(public_key) {
        return Response::err(&format!("failed to remove peer: {}", e));
    }
    Response::ok()
}

pub(super) fn handle_set_wg_peer_group(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref public_key) = req.public_key else {
        return Response::err("public_key required");
    };
    let Some(ref group) = req.group else {
        return Response::err("group required");
    };
    if !USER_ASSIGNABLE_GROUPS.contains(&group.as_str()) {
        return Response::err("invalid group");
    }
    let db = db.lock().unwrap();
    let peer = match db.get_wg_peer(public_key) {
        Ok(Some(p)) => p,
        Ok(None) => return Response::err("peer not found"),
        Err(e) => return Response::err(&e.to_string()),
    };
    let (dev_base, dev_max) = nftables::device_range();
    let Some(info) = subnet::compute_subnet(peer.subnet_id, dev_base, dev_max) else {
        return Response::err("invalid subnet_id");
    };
    let ipv4 = info.device_ipv4.to_string();
    let ipv6 = info.device_ipv6_ula.to_string();
    if let Err(e) = nftables::remove_device_forward_rule(&ipv4) {
        return Response::err(&format!("failed to remove old rule: {}", e));
    }
    // best-effort: IPv6 rule may not exist yet
    let _ = nftables::remove_device_forward_rule_v6(&ipv6);
    if let Err(e) = db.set_wg_peer_group(public_key, group) {
        return Response::err(&format!("failed to update group: {}", e));
    }
    if let Err(e) = nftables::add_device_forward_rule(&ipv4, group) {
        return Response::err(&format!("failed to add new rule: {}", e));
    }
    // best-effort: IPv6 mirrors IPv4 but is not fatal
    let _ = nftables::add_device_forward_rule_v6(&ipv6, group);
    Response::ok()
}

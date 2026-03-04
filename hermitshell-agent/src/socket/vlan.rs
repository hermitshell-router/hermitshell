use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::db::Db;
use crate::nftables;
use crate::vlan;
use super::{Request, Response};

pub(super) fn handle_vlan_enable(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();

    // Get VLAN configs
    let configs = match db_guard.get_vlan_config() {
        Ok(c) => c,
        Err(e) => return Response::err(&format!("failed to get VLAN config: {}", e)),
    };

    // Get interface names from DB
    let lan_iface = db_guard.get_config("lan_iface").ok().flatten()
        .unwrap_or_else(|| "eth2".into());
    let wan_iface = db_guard.get_config("wan_iface").ok().flatten()
        .unwrap_or_else(|| "eth1".into());
    let lan_ip = db_guard.get_config("lan_ip").ok().flatten()
        .unwrap_or_else(|| "10.0.0.1".into());

    drop(db_guard); // Release lock before shelling out

    // Create VLAN subinterfaces
    if let Err(e) = vlan::create_vlan_interfaces(&lan_iface, &configs) {
        return Response::err(&format!("failed to create VLAN interfaces: {}", e));
    }

    // Apply VLAN-mode nftables rules
    let vlan_ifaces: Vec<String> = configs.iter()
        .map(|c| format!("{}.{}", lan_iface, c.vlan_id))
        .collect();
    if let Err(e) = nftables::apply_base_rules_vlan(&wan_iface, &lan_iface, &lan_ip, &vlan_ifaces) {
        return Response::err(&format!("failed to apply VLAN nftables: {}", e));
    }

    // Save mode to DB
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_config("vlan_mode", "enabled") {
        return Response::err(&format!("failed to save VLAN mode: {}", e));
    }

    info!("VLAN mode enabled");
    Response::ok()
}

pub(super) fn handle_vlan_disable(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();

    let configs = db_guard.get_vlan_config().unwrap_or_default();
    let lan_iface = db_guard.get_config("lan_iface").ok().flatten()
        .unwrap_or_else(|| "eth2".into());
    let wan_iface = db_guard.get_config("wan_iface").ok().flatten()
        .unwrap_or_else(|| "eth1".into());
    let lan_ip = db_guard.get_config("lan_ip").ok().flatten()
        .unwrap_or_else(|| "10.0.0.1".into());

    drop(db_guard);

    // Remove VLAN subinterfaces
    let vlan_ids: Vec<u16> = configs.iter().map(|c| c.vlan_id).collect();
    if let Err(e) = vlan::teardown_vlan_interfaces(&lan_iface, &vlan_ids) {
        warn!(error = %e, "failed to teardown VLAN interfaces");
    }

    // Reapply non-VLAN nftables rules
    if let Err(e) = nftables::apply_base_rules(&wan_iface, &lan_iface, &lan_ip) {
        return Response::err(&format!("failed to apply base nftables: {}", e));
    }

    // Save mode to DB
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_config("vlan_mode", "disabled") {
        return Response::err(&format!("failed to save VLAN mode: {}", e));
    }

    info!("VLAN mode disabled");
    Response::ok()
}

pub(super) fn handle_vlan_update_config(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(group) = req.group.as_deref() else {
        return Response::err("group required");
    };
    let Some(vlan_id) = req.vlan_id else {
        return Response::err("vlan_id required");
    };
    if vlan_id < 1 || vlan_id > 4094 {
        return Response::err("vlan_id must be 1-4094");
    }

    let db_guard = db.lock().unwrap();

    // Check for duplicate VLAN IDs
    let configs = match db_guard.get_vlan_config() {
        Ok(c) => c,
        Err(e) => return Response::err(&format!("failed to get VLAN config: {}", e)),
    };
    for c in &configs {
        if c.vlan_id == vlan_id && c.group_name != group {
            return Response::err(&format!("VLAN ID {} already used by group {}", vlan_id, c.group_name));
        }
    }

    // Get the old config for this group (needed for teardown)
    let old_vlan_ids: Vec<u16> = configs.iter()
        .filter(|c| c.group_name == group)
        .map(|c| c.vlan_id)
        .collect();

    if let Err(e) = db_guard.update_vlan_id(group, vlan_id) {
        return Response::err(&format!("failed to update VLAN ID: {}", e));
    }

    // If VLAN mode is enabled, tear down old subinterface and recreate with new config
    let vlan_enabled = db_guard.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled");
    if vlan_enabled {
        let lan_iface = db_guard.get_config("lan_iface").ok().flatten()
            .unwrap_or_else(|| "eth2".into());
        let wan_iface = db_guard.get_config("wan_iface").ok().flatten()
            .unwrap_or_else(|| "eth1".into());
        let lan_ip = db_guard.get_config("lan_ip").ok().flatten()
            .unwrap_or_else(|| "10.0.0.1".into());

        // Reload configs after update
        let new_configs = match db_guard.get_vlan_config() {
            Ok(c) => c,
            Err(e) => return Response::err(&format!("failed to reload VLAN config: {}", e)),
        };

        drop(db_guard);

        // Tear down old subinterface
        if let Err(e) = vlan::teardown_vlan_interfaces(&lan_iface, &old_vlan_ids) {
            warn!(error = %e, "failed to teardown old VLAN interfaces");
        }

        // Recreate all subinterfaces with updated config
        if let Err(e) = vlan::create_vlan_interfaces(&lan_iface, &new_configs) {
            return Response::err(&format!("failed to create VLAN interfaces: {}", e));
        }

        // Reapply VLAN-mode nftables rules
        let vlan_ifaces: Vec<String> = new_configs.iter()
            .map(|c| format!("{}.{}", lan_iface, c.vlan_id))
            .collect();
        if let Err(e) = nftables::apply_base_rules_vlan(&wan_iface, &lan_iface, &lan_ip, &vlan_ifaces) {
            return Response::err(&format!("failed to apply VLAN nftables: {}", e));
        }
    }

    info!(group = group, vlan_id = vlan_id, "VLAN config updated");
    Response::ok()
}

pub(super) fn handle_vlan_status(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();
    let enabled = db_guard.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled");
    let configs = db_guard.get_vlan_config().unwrap_or_default();

    let config_json: Vec<serde_json::Value> = configs.iter().map(|c| {
        serde_json::json!({
            "group": c.group_name,
            "vlan_id": c.vlan_id,
            "subnet": c.subnet,
            "gateway": c.gateway,
        })
    }).collect();

    let mut resp = Response::ok();
    resp.config_value = Some(serde_json::json!({
        "enabled": enabled,
        "vlans": config_json,
    }).to_string());
    resp
}

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
    let _ = db.log_audit("set_interfaces", &format!("wan={}, lan={}", wan, lan));
    Response::ok()
}

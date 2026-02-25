use super::*;

pub(super) fn handle_list_connection_logs(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let limit = req.limit.unwrap_or(100).min(1000);
    let offset = req.offset.unwrap_or(0);
    let device_ip = req.internal_ip.as_deref();
    let db = db.lock().unwrap();
    match db.list_connection_logs(device_ip, limit, offset) {
        Ok(logs) => {
            let mut resp = Response::ok();
            resp.connection_logs = Some(logs);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_list_dns_logs(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let limit = req.limit.unwrap_or(100).min(1000);
    let offset = req.offset.unwrap_or(0);
    let device_ip = req.internal_ip.as_deref();
    let db = db.lock().unwrap();
    match db.list_dns_logs(device_ip, limit, offset) {
        Ok(logs) => {
            let mut resp = Response::ok();
            resp.dns_logs = Some(logs);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_list_alerts(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let limit = req.limit.unwrap_or(100).min(1000);
    let offset = req.offset.unwrap_or(0);
    let device_mac = req.mac.as_deref();
    let rule = req.rule.as_deref();
    let severity = req.severity.as_deref();
    let acknowledged = req.acknowledged;
    let db = db.lock().unwrap();
    match db.list_alerts(device_mac, rule, severity, acknowledged, limit, offset) {
        Ok(alerts) => {
            let mut resp = Response::ok();
            resp.alerts = Some(alerts);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_get_alert(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let id = match req.id {
        Some(id) => id,
        None => return Response::err("id required"),
    };
    let db = db.lock().unwrap();
    match db.get_alert(id) {
        Ok(Some(alert)) => {
            let mut resp = Response::ok();
            resp.alert = Some(alert);
            resp
        }
        Ok(None) => Response::err("alert not found"),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_acknowledge_alert(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let id = match req.id {
        Some(id) => id,
        None => return Response::err("id required"),
    };
    let db = db.lock().unwrap();
    match db.acknowledge_alert(id) {
        Ok(true) => Response::ok(),
        Ok(false) => Response::err("alert not found"),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_acknowledge_all_alerts(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.acknowledge_all_alerts(req.mac.as_deref()) {
        Ok(count) => {
            let mut resp = Response::ok();
            resp.config_value = Some(count.to_string());
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_log_audit(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref action) = req.value else {
        return Response::err("value required (action name)");
    };
    if action.len() > 64 {
        return Response::err("action too long (max 64 characters)");
    }
    let detail = req.key.as_deref().unwrap_or("");
    if detail.len() > 512 {
        return Response::err("detail too long (max 512 characters)");
    }
    let db = db.lock().unwrap();
    match db.log_audit(action, detail) {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_list_audit_logs(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let limit = req.limit.unwrap_or(200).min(1000);
    let db = db.lock().unwrap();
    match db.list_audit_logs(limit) {
        Ok(entries) => {
            let mut resp = Response::ok();
            resp.audit_logs = Some(entries);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_ingest_dns_logs(_req: &Request, db: &Arc<Mutex<Db>>, log_tx: &tokio::sync::mpsc::UnboundedSender<LogEvent>) -> Response {
    crate::dns_log::ingest_once(db, log_tx);
    Response::ok()
}

pub(super) fn handle_run_analysis(_req: &Request, db: &Arc<Mutex<Db>>, log_tx: &tokio::sync::mpsc::UnboundedSender<LogEvent>) -> Response {
    crate::analyzer::run_analysis_cycle(db, log_tx);
    Response::ok()
}

pub(super) fn handle_get_bandwidth_history(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let period = req.period.as_deref().unwrap_or("24h");
    if !matches!(period, "24h" | "7d" | "30d" | "1y") {
        return Response::err("invalid period: must be 24h, 7d, 30d, or 1y");
    }
    let device_mac = req.device_mac.as_deref().or(req.mac.as_deref());
    if let Some(mac) = device_mac {
        if let Err(e) = crate::nftables::validate_mac(mac) {
            return Response::err(&e.to_string());
        }
    }
    let db = db.lock().unwrap();
    match db.get_bandwidth_history(device_mac, period) {
        Ok(points) => {
            let mut resp = Response::ok();
            resp.bandwidth_history = Some(points);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_get_bandwidth_realtime(_req: &Request, db: &Arc<Mutex<Db>>, bandwidth_rt: &super::BandwidthRealtimeMap) -> Response {
    let db = db.lock().unwrap();
    let devices = db.list_assigned_devices().unwrap_or_default();
    let rt = bandwidth_rt.lock().unwrap();
    let mut results = Vec::new();
    for dev in &devices {
        if let Some(ref ip) = dev.ipv4 {
            if let Some((prev_rx, prev_tx, curr_rx, curr_tx, poll_time)) = rt.get(ip.as_str()) {
                let elapsed = poll_time.elapsed().as_secs_f64();
                if elapsed < 30.0 {
                    let delta_rx = curr_rx - prev_rx;
                    let delta_tx = curr_tx - prev_tx;
                    let interval = 10.0_f64; // POLL_INTERVAL_SECS
                    results.push(crate::db::BandwidthRealtime {
                        mac: dev.mac.clone(),
                        ip: ip.clone(),
                        rx_bps: if delta_rx > 0 { (delta_rx as f64 / interval) as i64 } else { 0 },
                        tx_bps: if delta_tx > 0 { (delta_tx as f64 / interval) as i64 } else { 0 },
                    });
                }
            }
        }
    }
    let mut resp = Response::ok();
    resp.bandwidth_realtime = Some(results);
    resp
}

pub(super) fn handle_get_top_destinations(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let device_mac = match req.device_mac.as_deref().or(req.mac.as_deref()) {
        Some(mac) => mac,
        None => return Response::err("device_mac required"),
    };
    if let Err(e) = crate::nftables::validate_mac(device_mac) {
        return Response::err(&e.to_string());
    }
    let period = req.period.as_deref().unwrap_or("24h");
    if !matches!(period, "24h" | "7d" | "30d" | "1y") {
        return Response::err("invalid period: must be 24h, 7d, 30d, or 1y");
    }
    let limit = req.limit.unwrap_or(10).min(50);
    let db = db.lock().unwrap();
    match db.get_top_destinations(device_mac, period, limit) {
        Ok(tops) => {
            let mut resp = Response::ok();
            resp.top_destinations = Some(tops);
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

pub(super) fn handle_run_bandwidth_rollup(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db = db.lock().unwrap();
    match db.rollup_all_pending() {
        Ok((h, d)) => {
            let mut resp = Response::ok();
            resp.config_value = Some(format!("hourly:{},daily:{}", h, d));
            resp
        }
        Err(e) => Response::err(&e.to_string()),
    }
}

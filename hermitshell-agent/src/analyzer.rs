use crate::db::Db;
use crate::log_export::LogEvent;

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};

const COOLDOWN_SECS: i64 = 3600;
const BASELINE_HOURS: i64 = 168;
const BEACONING_MIN_QUERIES: i64 = 10;
const BEACONING_MAX_JITTER: f64 = 0.3;

pub fn run_analysis_cycle(db: &Arc<Mutex<Db>>, log_tx: &UnboundedSender<LogEvent>) {
    let db_guard = db.lock().unwrap();

    let analyzer_enabled = db_guard
        .get_config("analyzer_enabled")
        .ok()
        .flatten()
        .unwrap_or_else(|| "true".to_string());
    if analyzer_enabled != "true" {
        return;
    }

    let devices = match db_guard.list_assigned_devices() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "analyzer: failed to list devices");
            return;
        }
    };

    for dev in &devices {
        let Some(ref ip) = dev.ipv4 else { continue };

        if is_rule_enabled(&db_guard, "dns_beaconing") {
            check_dns_beaconing(&db_guard, &dev.mac, ip, log_tx);
        }
        if is_rule_enabled(&db_guard, "dns_volume_spike") {
            check_dns_volume_spike(&db_guard, &dev.mac, ip, log_tx);
        }
        if is_rule_enabled(&db_guard, "new_dest_spike") {
            check_new_dest_spike(&db_guard, &dev.mac, ip, log_tx);
        }
        if is_rule_enabled(&db_guard, "suspicious_ports") {
            check_suspicious_ports(&db_guard, &dev.mac, ip, log_tx);
        }
        if is_rule_enabled(&db_guard, "bandwidth_spike") {
            check_bandwidth_spike(&db_guard, &dev.mac, ip, log_tx);
        }
        if is_rule_enabled(&db_guard, "dhcp_fingerprint_change") {
            check_dhcp_fingerprint_change(&db_guard, &dev.mac, ip, log_tx);
        }
    }

    for dev in &devices {
        let Some(ref ip) = dev.ipv4 else { continue };
        compute_baselines(&db_guard, &dev.mac, ip);
    }

    debug!("analyzer: cycle complete, checked {} devices", devices.len());
}

fn is_rule_enabled(db: &Db, rule: &str) -> bool {
    let key = format!("alert_rule_{rule}");
    db.get_config(&key)
        .ok()
        .flatten()
        .unwrap_or_else(|| "enabled".to_string()) == "enabled"
}

fn fire_alert(db: &Db, device_mac: &str, rule: &str, severity: &str, message: &str, details: Option<&str>, log_tx: &UnboundedSender<LogEvent>) {
    match db.has_recent_alert(device_mac, rule, COOLDOWN_SECS) {
        Ok(true) => return,
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "analyzer: cooldown check failed");
            return;
        }
    }

    match db.insert_alert(device_mac, rule, severity, message, details) {
        Ok(id) => {
            info!(id, device_mac, rule, severity, "analyzer: alert fired");
            let _ = log_tx.send(LogEvent::Alert {
                device_mac: device_mac.to_string(),
                rule: rule.to_string(),
                severity: severity.to_string(),
                message: message.to_string(),
                details: details.map(|s| s.to_string()),
            });
        }
        Err(e) => warn!(error = %e, "analyzer: failed to insert alert"),
    }
}

fn compute_baselines(db: &Db, mac: &str, ip: &str) {
    if let Ok(hourly) = db.count_unique_dns_domains_hourly(ip, BASELINE_HOURS) {
        if hourly.len() >= 24 {
            let (avg, stddev) = mean_stddev(&hourly.iter().map(|(_, c)| *c as f64).collect::<Vec<_>>());
            let _ = db.upsert_baseline(mac, "unique_dns_domains", avg, stddev);
        }
    }

    if let Ok(hourly) = db.count_unique_dest_ips_hourly(ip, BASELINE_HOURS) {
        if hourly.len() >= 24 {
            let (avg, stddev) = mean_stddev(&hourly.iter().map(|(_, c)| *c as f64).collect::<Vec<_>>());
            let _ = db.upsert_baseline(mac, "unique_dest_ips", avg, stddev);
        }
    }

    if let Ok(hourly) = db.get_device_tx_bytes_hourly(ip, BASELINE_HOURS) {
        if hourly.len() >= 24 {
            let (avg, stddev) = mean_stddev(&hourly.iter().map(|(_, c)| *c as f64).collect::<Vec<_>>());
            let _ = db.upsert_baseline(mac, "tx_bytes", avg, stddev);
        }
    }
}

fn check_dns_beaconing(db: &Db, mac: &str, ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    let candidates = match db.get_dns_beaconing_candidates(ip, BEACONING_MIN_QUERIES) {
        Ok(c) => c,
        Err(_) => return,
    };

    for (domain, timestamps) in &candidates {
        if timestamps.len() < BEACONING_MIN_QUERIES as usize {
            continue;
        }
        let intervals: Vec<f64> = timestamps.windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .collect();

        if intervals.is_empty() {
            continue;
        }

        let (avg_interval, stddev_interval) = mean_stddev(&intervals);
        if avg_interval <= 0.0 {
            continue;
        }

        let cv = stddev_interval / avg_interval;
        if cv < BEACONING_MAX_JITTER && avg_interval >= 5.0 {
            let details = serde_json::json!({
                "domain": domain,
                "query_count": timestamps.len(),
                "avg_interval_secs": avg_interval as i64,
                "coefficient_of_variation": format!("{cv:.2}"),
            });
            fire_alert(
                db, mac, "dns_beaconing", "high",
                &format!("DNS beaconing detected: {} queried {} times at ~{}s intervals", domain, timestamps.len(), avg_interval as i64),
                Some(&details.to_string()),
                log_tx,
            );
        }
    }
}

fn check_baseline_spike(
    db: &Db,
    mac: &str,
    ip: &str,
    log_tx: &UnboundedSender<LogEvent>,
    metric: &str,
    rule: &str,
    severity: &str,
    threshold_multiplier: f64,
    min_baseline: f64,
    query_fn: impl Fn(&Db, &str, i64) -> anyhow::Result<Vec<(i64, i64)>>,
    format_msg: impl Fn(i64, i64) -> String,
    format_details: impl Fn(i64, i64) -> serde_json::Value,
) {
    let baseline = match db.get_baseline(mac, metric) {
        Ok(Some(b)) => b,
        _ => return,
    };
    let (avg, _stddev) = baseline;
    if avg < min_baseline {
        return;
    }

    let hourly = match query_fn(db, ip, 1) {
        Ok(h) => h,
        Err(_) => return,
    };
    let current: i64 = hourly.iter().map(|(_, c)| c).sum();

    if current as f64 > avg * threshold_multiplier {
        let details = format_details(current, avg as i64);
        fire_alert(
            db, mac, rule, severity,
            &format_msg(current, avg as i64),
            Some(&details.to_string()),
            log_tx,
        );
    }
}

fn check_dns_volume_spike(db: &Db, mac: &str, ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    check_baseline_spike(
        db, mac, ip, log_tx,
        "unique_dns_domains", "dns_volume_spike", "high",
        3.0, 1.0,
        |db, ip, hours| db.count_unique_dns_domains_hourly(ip, hours),
        |current, avg| format!("Device queried {} unique domains in the last hour (baseline: {})", current, avg),
        |current, avg| serde_json::json!({"current": current, "baseline_avg": avg}),
    );
}

fn check_new_dest_spike(db: &Db, mac: &str, ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    check_baseline_spike(
        db, mac, ip, log_tx,
        "unique_dest_ips", "new_dest_spike", "medium",
        3.0, 1.0,
        |db, ip, hours| db.count_unique_dest_ips_hourly(ip, hours),
        |current, avg| format!("Device contacted {} unique IPs in the last hour (baseline: {})", current, avg),
        |current, avg| serde_json::json!({"current": current, "baseline_avg": avg}),
    );
}

fn check_suspicious_ports(db: &Db, mac: &str, ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    let conns = match db.get_suspicious_port_connections(ip) {
        Ok(c) => c,
        Err(_) => return,
    };

    if conns.is_empty() {
        return;
    }

    let details = serde_json::json!({
        "connections": conns.iter().map(|(dest_ip, port, proto)| {
            serde_json::json!({"dest_ip": dest_ip, "port": port, "protocol": proto})
        }).collect::<Vec<_>>(),
    });

    fire_alert(
        db, mac, "suspicious_ports", "medium",
        &format!("Device made {} connections to suspicious ports (23/445/3389/5900/high-LAN)", conns.len()),
        Some(&details.to_string()),
        log_tx,
    );
}

fn check_bandwidth_spike(db: &Db, mac: &str, ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    check_baseline_spike(
        db, mac, ip, log_tx,
        "tx_bytes", "bandwidth_spike", "low",
        5.0, 1024.0,
        |db, ip, hours| db.get_device_tx_bytes_hourly(ip, hours),
        |current, avg| format!("Device uploaded {} bytes in the last hour (baseline: {})", current, avg),
        |current, avg| serde_json::json!({"current_bytes": current, "baseline_avg_bytes": avg}),
    );
}

fn check_dhcp_fingerprint_change(db: &Db, mac: &str, _ip: &str, log_tx: &UnboundedSender<LogEvent>) {
    let dev = match db.get_device(mac) {
        Ok(Some(d)) => d,
        _ => return,
    };

    let Some(ref current_fp) = dev.dhcp_fingerprint else { return };
    if current_fp.is_empty() { return; }

    let baseline_key = format!("dhcp_fp_{}", mac);
    match db.get_config(&baseline_key) {
        Ok(Some(ref stored_fp)) if !stored_fp.is_empty() => {
            if stored_fp != current_fp {
                let details = serde_json::json!({
                    "previous_fingerprint": stored_fp,
                    "current_fingerprint": current_fp,
                });
                fire_alert(
                    db, mac, "dhcp_fingerprint_change", "high",
                    &format!("DHCP fingerprint changed — possible MAC spoofing (was: {}, now: {})", stored_fp, current_fp),
                    Some(&details.to_string()),
                    log_tx,
                );
                let _ = db.set_config(&baseline_key, current_fp);
            }
        }
        Ok(Some(_)) | Ok(None) => {
            let _ = db.set_config(&baseline_key, current_fp);
        }
        Err(_) => {}
    }
}

fn mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    (mean, variance.sqrt())
}

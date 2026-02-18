mod blocky;
mod conntrack;
mod db;
mod dns_log;
mod log_export;
mod nftables;
mod socket;
mod wireguard;

use hermitshell_common::subnet;

use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

/// Read nameservers from WAN DHCP lease, then /etc/resolv.conf, falling back to public DNS.
fn read_upstream_dns(wan_iface: &str) -> Vec<Ipv4Addr> {
    // Prefer DNS from WAN DHCP lease (most accurate for a router)
    let lease_path = format!("/var/lib/dhcp/dhclient.{}.leases", wan_iface);
    if let Ok(content) = std::fs::read_to_string(&lease_path) {
        // Parse last "option domain-name-servers" line (most recent lease)
        if let Some(line) = content.lines().rev().find(|l| l.contains("option domain-name-servers")) {
            let servers: Vec<Ipv4Addr> = line
                .split("domain-name-servers")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_end_matches(';')
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !servers.is_empty() {
                return servers;
            }
        }
    }

    // Fall back to /etc/resolv.conf
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let servers: Vec<Ipv4Addr> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver") {
                let ip: Ipv4Addr = line.split_whitespace().nth(1)?.parse().ok()?;
                // Skip systemd-resolved stub
                if ip == Ipv4Addr::new(127, 0, 0, 53) {
                    None
                } else {
                    Some(ip)
                }
            } else {
                None
            }
        })
        .collect();
    if servers.is_empty() {
        vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
    } else {
        servers
    }
}

const DB_PATH: &str = "/data/hermitshell/db/hermitshell.db";
const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";
const POLL_INTERVAL_SECS: u64 = 10;
const LAN_ADDR: &str = "10.0.0.1/32";
const LAN_ADDR_V6: &str = "fd00::1/128";

#[tokio::main]
async fn main() -> Result<()> {
    let use_json = db::Db::open(DB_PATH)
        .ok()
        .and_then(|d| d.get_config("log_format").ok().flatten())
        .map(|v| v == "json")
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
    }

    info!("hermitshell-agent starting");
    let start_time = std::time::Instant::now();

    let wan_iface = "eth1";
    let lan_iface = "eth2";

    // Ensure LAN interface has the base IPv4 address
    let status = std::process::Command::new("/usr/sbin/ip")
        .args(["addr", "add", LAN_ADDR, "dev", lan_iface])
        .status();
    match status {
        Ok(s) if s.success() || s.code() == Some(2) => {} // 2 = already exists
        Ok(s) => warn!(addr = LAN_ADDR, iface = lan_iface, code = ?s.code(), "ip addr add exited unexpectedly"),
        Err(e) => warn!(error = %e, "failed to add LAN address"),
    }

    // Ensure LAN interface has the base IPv6 ULA address
    let status_v6 = std::process::Command::new("/usr/sbin/ip")
        .args(["-6", "addr", "add", LAN_ADDR_V6, "dev", lan_iface])
        .status();
    match status_v6 {
        Ok(s) if s.success() || s.code() == Some(2) => {}
        Ok(s) => warn!(addr = LAN_ADDR_V6, iface = lan_iface, code = ?s.code(), "ip -6 addr add exited unexpectedly"),
        Err(e) => warn!(error = %e, "failed to add LAN v6 address"),
    }

    // Apply base nftables rules
    nftables::apply_base_rules(wan_iface, lan_iface)?;

    // Open database
    let db = Arc::new(Mutex::new(db::Db::open(DB_PATH)?));
    info!(path = DB_PATH, "database opened");

    // Restore state for previously assigned devices
    {
        let db_guard = db.lock().unwrap();
        let assigned = db_guard.list_assigned_devices()?;
        for dev in &assigned {
            if let (Some(ip), Some(sid)) = (&dev.ipv4, dev.subnet_id) {
                if let Some(info) = subnet::compute_subnet(sid) {
                    // Re-add /32 device route
                    let _ = nftables::add_device_route(ip, lan_iface);
                    // Re-add nftables counter
                    let _ = nftables::add_device_counter(ip);
                    // Re-add nftables forward rule
                    let _ = nftables::add_device_forward_rule(ip, &dev.device_group);
                    // Re-add IPv6 route, counter, forward rule
                    let ipv6 = info.device_ipv6_ula.to_string();
                    let _ = nftables::add_device_route_v6(&ipv6, lan_iface);
                    let _ = nftables::add_device_counter_v6(&ipv6);
                    let _ = nftables::add_device_forward_rule_v6(&ipv6, &dev.device_group);
                    info!(mac = %dev.mac, ip = %ip, subnet_id = sid, group = %dev.device_group, "device restored");
                }
            }
        }
    }

    // Restore port forwarding rules
    {
        let db_guard = db.lock().unwrap();
        let forwards = db_guard.list_enabled_port_forwards().unwrap_or_default();
        let dmz = db_guard.get_config("dmz_host_ip").ok().flatten().unwrap_or_default();
        let dmz_ref = if dmz.is_empty() { None } else { Some(dmz.as_str()) };
        if !forwards.is_empty() || dmz_ref.is_some() {
            if let Err(e) = nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref) {
                error!(error = %e, "failed to restore port forwards");
            } else {
                info!(count = forwards.len(), "port forwards restored");
            }
        }
    }

    // Restore WireGuard state if enabled
    {
        let db_guard = db.lock().unwrap();
        let wg_enabled = db_guard.get_config("wg_enabled")
            .ok().flatten()
            .map(|v| v == "true")
            .unwrap_or(false);
        if wg_enabled {
            if let Some(private_key) = db_guard.get_config("wg_private_key").ok().flatten() {
                let listen_port: u16 = db_guard.get_config("wg_listen_port")
                    .ok().flatten()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(51820);
                if let Err(e) = wireguard::create_interface(&private_key, listen_port) {
                    error!(error = %e, "failed to restore wg0");
                } else {
                    let _ = wireguard::open_listen_port(listen_port);
                    let peers = db_guard.list_wg_peers().unwrap_or_default();
                    for peer in &peers {
                        if !peer.enabled { continue; }
                        if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                            let ipv4 = info.device_ipv4.to_string();
                            let ipv6 = info.device_ipv6_ula.to_string();
                            let _ = wireguard::add_peer(&peer.public_key, &ipv4, &ipv6);
                            let _ = nftables::add_device_counter(&ipv4);
                            let _ = nftables::add_device_counter_v6(&ipv6);
                            let _ = nftables::add_device_forward_rule(&ipv4, &peer.device_group);
                            let _ = nftables::add_device_forward_rule_v6(&ipv6, &peer.device_group);
                            info!(peer = %peer.name, ipv4 = %ipv4, ipv6 = %ipv6, "wireguard peer restored");
                        }
                    }
                }
            }
        }
    }

    // Start blocky DNS server
    let upstream_dns = read_upstream_dns(wan_iface);
    info!(servers = ?upstream_dns, "upstream DNS");

    let blocky_mgr = {
        let dns_strings: Vec<String> = upstream_dns.iter().map(|ip| ip.to_string()).collect();
        let mut mgr = blocky::BlockyManager::new(
            dns_strings,
            "10.0.0.1:53,[fd00::1]:53".to_string(),
            "/data/hermitshell/blocky".to_string(),
            "/opt/hermitshell/blocky".to_string(),
        );
        if let Err(e) = mgr.start() {
            error!(error = %e, "failed to start blocky");
        } else {
            if !mgr.wait_for_ready(10) {
                error!("blocky did not become ready within 10s");
            }
            // Check ad_blocking_enabled setting
            let db_guard = db.lock().unwrap();
            let enabled = db_guard
                .get_config("ad_blocking_enabled")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(true);
            drop(db_guard);
            if !enabled {
                if let Err(e) = mgr.set_blocking_enabled(false) {
                    error!(error = %e, "failed to disable blocking");
                }
            }
        }
        Arc::new(Mutex::new(mgr))
    };

    // Start conntrack event listener
    conntrack::enable_accounting();
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<log_export::LogEvent>();
    let _conntrack_child = conntrack::start(db.clone(), log_tx.clone());

    let db_dns = db.clone();
    let log_tx_dns = log_tx.clone();
    tokio::spawn(async move {
        dns_log::start(db_dns, log_tx_dns).await;
    });

    let db_export = db.clone();
    tokio::spawn(async move {
        log_export::start(db_export, log_rx).await;
    });

    // Spawn socket server
    let db_clone = db.clone();
    let blocky_clone = blocky_mgr.clone();
    let wan_for_socket = wan_iface.to_string();
    let lan_for_socket = lan_iface.to_string();
    tokio::spawn(async move {
        if let Err(e) = socket::run_server(SOCKET_PATH, db_clone, start_time, blocky_clone, wan_for_socket, lan_for_socket).await {
            error!(error = %e, "socket server error");
        }
    });

    // Spawn DHCP IPC socket
    const DHCP_SOCKET_PATH: &str = "/run/hermitshell/dhcp.sock";
    let db_dhcp = db.clone();
    let lan_iface_dhcp = lan_iface.to_string();
    tokio::spawn(async move {
        if let Err(e) = socket::run_dhcp_socket(DHCP_SOCKET_PATH, db_dhcp, lan_iface_dhcp).await {
            error!(error = %e, "DHCP socket error");
        }
    });

    // Spawn DHCP server as child process
    let db_for_counters = db.clone();
    std::process::Command::new("/opt/hermitshell/hermitshell-dhcp")
        .arg(lan_iface)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    // Main polling loop: update traffic counters for assigned devices
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(POLL_INTERVAL_SECS));

    info!("agent initialized, entering main loop");

    // Run log rotation once on startup
    {
        let db_guard = db_for_counters.lock().unwrap();
        let retention_days: i64 = db_guard
            .get_config("log_retention_days")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let _ = db_guard.rotate_logs(retention_days * 86400);
    }

    let mut rotation_counter: u64 = 0;

    loop {
        interval.tick().await;

        let db_guard = db_for_counters.lock().unwrap();
        let devices = match db_guard.list_assigned_devices() {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "failed to list devices");
                continue;
            }
        };

        for dev in &devices {
            if let Some(ref ip) = dev.ipv4 {
                match nftables::get_device_counters(ip) {
                    Ok((rx, tx)) => {
                        if let Err(e) = db_guard.update_counters(ip, rx, tx) {
                            error!(ip = %ip, error = %e, "failed to update counters");
                        }
                    }
                    Err(e) => debug!(ip = %ip, error = %e, "failed to get counters"),
                }
            }
        }

        // Hourly log rotation (360 ticks * 10s = 1 hour)
        rotation_counter += 1;
        if rotation_counter % 360 == 0 {
            let retention_days: i64 = db_guard
                .get_config("log_retention_days")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7);
            match db_guard.rotate_logs(retention_days * 86400) {
                Ok((conn, dns)) => {
                    if conn > 0 || dns > 0 {
                        info!(connection_logs = conn, dns_logs = dns, "rotated old logs");
                    }
                }
                Err(e) => error!(error = %e, "log rotation failed"),
            }
        }
    }
}

mod blocky;
mod db;
mod nftables;
mod socket;
mod wireguard;

use hermitshell_common::subnet;

use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

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

#[tokio::main]
async fn main() -> Result<()> {
    println!("hermitshell-agent starting...");
    let start_time = std::time::Instant::now();

    let wan_iface = "eth1";
    let lan_iface = "eth2";

    // Ensure LAN interface has the base address (each device gets its own /30)
    let status = std::process::Command::new("/usr/sbin/ip")
        .args(["addr", "add", LAN_ADDR, "dev", lan_iface])
        .status();
    match status {
        Ok(s) if s.success() || s.code() == Some(2) => {} // 2 = already exists
        Ok(s) => eprintln!("Warning: ip addr add {} dev {} exited {:?}", LAN_ADDR, lan_iface, s.code()),
        Err(e) => eprintln!("Warning: failed to add LAN address: {}", e),
    }

    // Apply base nftables rules
    nftables::apply_base_rules(wan_iface, lan_iface)?;

    // Open database
    let db = Arc::new(Mutex::new(db::Db::open(DB_PATH)?));
    println!("Database opened at {}", DB_PATH);

    // Restore state for previously assigned devices
    {
        let db_guard = db.lock().unwrap();
        let assigned = db_guard.list_assigned_devices()?;
        for dev in &assigned {
            if let (Some(ip), Some(sid)) = (&dev.ip, dev.subnet_id) {
                if let Some(info) = subnet::compute_subnet(sid) {
                    // Re-add gateway address
                    let addr_cidr = format!("{}/30", info.gateway);
                    let _ = std::process::Command::new("/usr/sbin/ip")
                        .args(["addr", "add", &addr_cidr, "dev", lan_iface])
                        .status();
                    // Re-add nftables counter
                    let _ = nftables::add_device_counter(ip);
                    // Re-add nftables forward rule
                    let _ = nftables::add_device_forward_rule(ip, &dev.device_group);
                    println!("Restored device {} -> {} (subnet {}, group {})", dev.mac, ip, sid, dev.device_group);
                }
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
                    eprintln!("Failed to restore wg0: {}", e);
                } else {
                    let _ = wireguard::open_listen_port(listen_port);
                    let peers = db_guard.list_wg_peers().unwrap_or_default();
                    for peer in &peers {
                        if !peer.enabled { continue; }
                        if let Some(info) = subnet::compute_subnet(peer.subnet_id) {
                            let _ = wireguard::add_peer(&peer.public_key, &info.device_ip);
                            let _ = nftables::add_device_counter(&info.device_ip);
                            let _ = nftables::add_device_forward_rule(&info.device_ip, &peer.device_group);
                            println!("Restored WireGuard peer {} -> {}", peer.name, info.device_ip);
                        }
                    }
                }
            }
        }
    }

    // Start blocky DNS server
    let upstream_dns = read_upstream_dns(wan_iface);
    println!("Upstream DNS: {:?}", upstream_dns);

    let blocky_mgr = {
        let dns_strings: Vec<String> = upstream_dns.iter().map(|ip| ip.to_string()).collect();
        let mut mgr = blocky::BlockyManager::new(
            dns_strings,
            "10.0.0.1:53".to_string(),
            "/data/hermitshell/blocky".to_string(),
            "/opt/hermitshell/blocky".to_string(),
        );
        if let Err(e) = mgr.start() {
            eprintln!("Failed to start blocky: {}", e);
        } else {
            // Wait for blocky to be ready
            std::thread::sleep(std::time::Duration::from_secs(2));
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
                    eprintln!("Failed to disable blocking: {}", e);
                }
            }
        }
        Arc::new(Mutex::new(mgr))
    };

    // Spawn socket server
    let db_clone = db.clone();
    let blocky_clone = blocky_mgr.clone();
    tokio::spawn(async move {
        if let Err(e) = socket::run_server(SOCKET_PATH, db_clone, start_time, blocky_clone).await {
            eprintln!("Socket server error: {}", e);
        }
    });

    // Spawn DHCP IPC socket
    const DHCP_SOCKET_PATH: &str = "/run/hermitshell/dhcp.sock";
    let db_dhcp = db.clone();
    let lan_iface_dhcp = lan_iface.to_string();
    tokio::spawn(async move {
        if let Err(e) = socket::run_dhcp_socket(DHCP_SOCKET_PATH, db_dhcp, lan_iface_dhcp).await {
            eprintln!("DHCP socket error: {}", e);
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

    println!("Agent initialized, entering main loop");

    loop {
        interval.tick().await;

        let db_guard = db_for_counters.lock().unwrap();
        let devices = match db_guard.list_assigned_devices() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to list devices: {}", e);
                continue;
            }
        };

        for dev in &devices {
            if let Some(ref ip) = dev.ip {
                match nftables::get_device_counters(ip) {
                    Ok((rx, tx)) => {
                        if let Err(e) = db_guard.update_counters(ip, rx, tx) {
                            eprintln!("Failed to update counters: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Failed to get counters for {}: {}", ip, e),
                }
            }
        }
    }
}

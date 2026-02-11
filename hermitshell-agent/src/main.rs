mod db;
mod dhcp;
mod nftables;
mod socket;
mod subnet;

use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// Read nameservers from /etc/resolv.conf, falling back to public DNS.
fn read_upstream_dns() -> Vec<Ipv4Addr> {
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

#[tokio::main]
async fn main() -> Result<()> {
    println!("hermitshell-agent starting...");
    let start_time = std::time::Instant::now();

    // Apply base nftables rules
    let wan_iface = "eth1";
    let lan_iface = "eth2";
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
                    let _ = std::process::Command::new("ip")
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

    // Spawn socket server
    let db_clone = db.clone();
    tokio::spawn(async move {
        if let Err(e) = socket::run_server(SOCKET_PATH, db_clone, start_time).await {
            eprintln!("Socket server error: {}", e);
        }
    });

    // Spawn DHCP server
    let upstream_dns = read_upstream_dns();
    println!("Upstream DNS: {:?}", upstream_dns);
    let dhcp_server = dhcp::DhcpServer::new(
        db.clone(),
        lan_iface.to_string(),
        upstream_dns,
    );
    let db_for_counters = db.clone();
    tokio::spawn(async move {
        if let Err(e) = dhcp_server.run().await {
            eprintln!("DHCP server error: {}", e);
        }
    });

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

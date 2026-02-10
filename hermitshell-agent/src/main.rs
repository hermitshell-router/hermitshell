mod db;
mod dhcp;
mod nftables;
mod socket;

use anyhow::Result;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const DB_PATH: &str = "/data/hermitshell/db/hermitshell.db";
const SOCKET_PATH: &str = "/run/hermitshell/agent.sock";
const LEASE_PATH: &str = "/var/lib/misc/dnsmasq.leases";
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

    // Track which IPs have counters
    let tracked_ips: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // Spawn socket server
    let db_clone = db.clone();
    tokio::spawn(async move {
        if let Err(e) = socket::run_server(SOCKET_PATH, db_clone, start_time).await {
            eprintln!("Socket server error: {}", e);
        }
    });

    // Main polling loop
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(POLL_INTERVAL_SECS));

    println!("Agent initialized, entering main loop");

    loop {
        interval.tick().await;

        // Parse DHCP leases
        let leases = match dhcp::parse_leases(LEASE_PATH) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to parse leases: {}", e);
                continue;
            }
        };

        // Update database and add counters for new devices
        {
            let db = db.lock().unwrap();
            let mut tracked = tracked_ips.lock().unwrap();

            for lease in &leases {
                if let Err(e) = db.upsert_device(&lease.mac, Some(&lease.ip), lease.hostname.as_deref()) {
                    eprintln!("Failed to upsert device: {}", e);
                }

                // Add counter if not already tracking this IP
                if !tracked.contains(&lease.ip) {
                    if let Err(e) = nftables::add_device_counter(&lease.ip) {
                        eprintln!("Failed to add counter for {}: {}", lease.ip, e);
                    } else {
                        tracked.insert(lease.ip.clone());
                    }
                }
            }

            // Update counters from nftables
            for lease in &leases {
                match nftables::get_device_counters(&lease.ip) {
                    Ok((rx, tx)) => {
                        if let Err(e) = db.update_counters(&lease.ip, rx, tx) {
                            eprintln!("Failed to update counters: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Failed to get counters for {}: {}", lease.ip, e),
                }
            }
        }
    }
}

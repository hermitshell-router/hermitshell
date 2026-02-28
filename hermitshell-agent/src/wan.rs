use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use tracing::{error, info, warn};

use crate::db;

/// Represents a WAN lease obtained via DHCP or configured statically.
#[derive(Debug, Clone)]
pub struct WanLease {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub renew_at: Instant,
    pub rebind_at: Instant,
    pub delegated_prefix: Option<String>,
    pub prefix_valid_lifetime: Option<u32>,
}

pub type SharedWanLease = Arc<Mutex<Option<WanLease>>>;

/// Spawn the WAN management task. Returns the shared lease handle.
pub fn start(wan_iface: String, db: Arc<Mutex<db::Db>>) -> SharedWanLease {
    let lease: SharedWanLease = Arc::new(Mutex::new(None));
    let lease_clone = lease.clone();
    tokio::spawn(async move {
        if let Err(e) = run_wan(&wan_iface, &db, &lease_clone).await {
            error!(error = %e, "WAN management task failed");
        }
    });
    lease
}

/// Read wan_mode from DB and dispatch to the appropriate handler.
async fn run_wan(
    wan_iface: &str,
    db: &Arc<Mutex<db::Db>>,
    lease: &SharedWanLease,
) -> Result<()> {
    let wan_mode = {
        let db_guard = db.lock().unwrap();
        db_guard
            .get_config("wan_mode")
            .ok()
            .flatten()
            .unwrap_or_else(|| "dhcp".into())
    };

    info!(mode = %wan_mode, iface = %wan_iface, "WAN mode selected");

    match wan_mode.as_str() {
        "static" => run_static(wan_iface, db, lease).await,
        "dhcp" | _ => run_dhcp(wan_iface, db, lease).await,
    }
}

/// Apply static WAN configuration from DB settings.
async fn run_static(
    wan_iface: &str,
    db: &Arc<Mutex<db::Db>>,
    lease: &SharedWanLease,
) -> Result<()> {
    let (ip_str, gateway_str, dns_str) = {
        let db_guard = db.lock().unwrap();
        let ip = db_guard
            .get_config("wan_static_ip")
            .ok()
            .flatten()
            .unwrap_or_default();
        let gw = db_guard
            .get_config("wan_static_gateway")
            .ok()
            .flatten()
            .unwrap_or_default();
        let dns = db_guard
            .get_config("wan_static_dns")
            .ok()
            .flatten()
            .unwrap_or_default();
        (ip, gw, dns)
    };

    if ip_str.is_empty() || gateway_str.is_empty() {
        anyhow::bail!("wan_static_ip and wan_static_gateway must be set for static mode");
    }

    // Parse IP — may include CIDR prefix (e.g. "192.168.1.100/24")
    let (ip_addr, cidr) = if let Some((addr, prefix)) = ip_str.split_once('/') {
        (addr.parse::<Ipv4Addr>()?, format!("{}/{}", addr, prefix))
    } else {
        (ip_str.parse::<Ipv4Addr>()?, format!("{}/24", ip_str))
    };

    let gateway: Ipv4Addr = gateway_str.parse()?;

    let dns_servers: Vec<Ipv4Addr> = if dns_str.is_empty() {
        vec![gateway]
    } else {
        dns_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    };

    // Flush existing addresses on WAN interface
    let _ = Command::new("/usr/sbin/ip")
        .args(["addr", "flush", "dev", wan_iface])
        .status();

    // Add static IP
    let status = Command::new("/usr/sbin/ip")
        .args(["addr", "add", &cidr, "dev", wan_iface])
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to add address {} to {}", cidr, wan_iface);
    }

    // Bring interface up
    let _ = Command::new("/usr/sbin/ip")
        .args(["link", "set", wan_iface, "up"])
        .status();

    // Add default route via gateway
    let _ = Command::new("/usr/sbin/ip")
        .args(["route", "del", "default"])
        .status();
    let status = Command::new("/usr/sbin/ip")
        .args(["route", "add", "default", "via", &gateway_str, "dev", wan_iface])
        .status()?;
    if !status.success() {
        warn!(gateway = %gateway_str, "failed to add default route");
    }

    // Derive subnet mask from prefix length
    let prefix_len: u32 = if let Some((_, p)) = ip_str.split_once('/') {
        p.parse().unwrap_or(24)
    } else {
        24
    };
    let mask_bits = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let subnet_mask = Ipv4Addr::from(mask_bits);

    let now = Instant::now();
    let wan_lease = WanLease {
        ip: ip_addr,
        subnet_mask,
        gateway,
        dns_servers: dns_servers.clone(),
        lease_time: u32::MAX, // static — never expires
        renew_at: now + std::time::Duration::from_secs(u64::MAX / 2),
        rebind_at: now + std::time::Duration::from_secs(u64::MAX / 2),
        delegated_prefix: None,
        prefix_valid_lifetime: None,
    };

    {
        let mut guard = lease.lock().unwrap();
        *guard = Some(wan_lease);
    }

    info!(
        ip = %ip_addr,
        gateway = %gateway,
        dns = ?dns_servers,
        "static WAN configured"
    );

    Ok(())
}

/// Run DHCP client on the WAN interface. (placeholder — implemented in a later task)
async fn run_dhcp(
    _wan_iface: &str,
    _db: &Arc<Mutex<db::Db>>,
    _lease: &SharedWanLease,
) -> Result<()> {
    Ok(())
}

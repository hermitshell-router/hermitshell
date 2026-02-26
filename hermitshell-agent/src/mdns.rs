use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use simple_dns::{Packet, PacketFlag};
use tracing::{debug, error, info, warn};

use crate::db::Db;
use hermitshell_common::MdnsService;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const LAN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const EXPIRY_SWEEP_SECS: u64 = 60;

/// Internal service record tracking an mDNS service announcement.
#[derive(Debug, Clone)]
struct ServiceRecord {
    device_mac: String,
    service_type: String,
    service_name: String,
    port: u16,
    txt_records: Vec<(String, String)>,
    host_ipv4: Ipv4Addr,
    ttl_secs: u32,
    expires_at: Instant,
}

/// Registry of mDNS service announcements, keyed by device MAC.
pub struct ServiceRegistry {
    records: HashMap<String, Vec<ServiceRecord>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Insert or update a service record. The (service_type, service_name) pair
    /// is treated as the unique key within a device's record list.
    pub fn upsert(
        &mut self,
        mac: &str,
        service_type: &str,
        service_name: &str,
        port: u16,
        txt: Vec<(String, String)>,
        host_ipv4: Ipv4Addr,
        ttl_secs: u32,
    ) {
        let expires_at = Instant::now() + std::time::Duration::from_secs(ttl_secs as u64);
        let record = ServiceRecord {
            device_mac: mac.to_string(),
            service_type: service_type.to_string(),
            service_name: service_name.to_string(),
            port,
            txt_records: txt,
            host_ipv4,
            ttl_secs,
            expires_at,
        };

        let entries = self.records.entry(mac.to_string()).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|r| r.service_type == service_type && r.service_name == service_name)
        {
            *existing = record;
        } else {
            entries.push(record);
        }
    }

    /// Remove all expired service records.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.records.retain(|_mac, entries| {
            entries.retain(|r| r.expires_at > now);
            !entries.is_empty()
        });
    }

    /// Query visible services based on the querier's device group.
    /// - "trusted" sees: trusted, iot, servers
    /// - "iot"/"servers" sees: trusted only
    /// - guest/quarantine/blocked sees: nothing
    pub fn query(
        &self,
        querier_group: &str,
        service_type_filter: Option<&str>,
        db: &Db,
    ) -> Vec<MdnsService> {
        let allowed_groups: &[&str] = match querier_group {
            "trusted" => &["trusted", "iot", "servers"],
            "iot" | "servers" => &["trusted"],
            _ => return Vec::new(),
        };

        let mut result = Vec::new();
        for (mac, entries) in &self.records {
            // Look up the device's group
            let group = match db.get_device(mac) {
                Ok(Some(dev)) => dev.device_group,
                _ => continue,
            };
            if !allowed_groups.contains(&group.as_str()) {
                continue;
            }
            for rec in entries {
                if let Some(filter) = service_type_filter {
                    if rec.service_type != filter {
                        continue;
                    }
                }
                result.push(MdnsService {
                    service_type: rec.service_type.clone(),
                    service_name: rec.service_name.clone(),
                    port: rec.port,
                    txt_records: rec.txt_records.clone(),
                });
            }
        }
        result
    }

    /// Return all services for a specific device (for the UI).
    pub fn services_for_device(&self, mac: &str) -> Vec<MdnsService> {
        self.records
            .get(mac)
            .map(|entries| {
                entries
                    .iter()
                    .map(|r| MdnsService {
                        service_type: r.service_type.clone(),
                        service_name: r.service_name.clone(),
                        port: r.port,
                        txt_records: r.txt_records.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub type SharedRegistry = Arc<Mutex<ServiceRegistry>>;

/// Resolve an IPv4 address to a MAC address by scanning the device list.
fn ip_to_mac(db: &Db, ip: &Ipv4Addr) -> Option<String> {
    let ip_str = ip.to_string();
    let devices = db.list_devices().ok()?;
    devices
        .iter()
        .find(|d| d.ipv4.as_deref() == Some(&ip_str))
        .map(|d| d.mac.clone())
}

/// Create a UDP socket bound to 0.0.0.0:5353 with multicast membership on the LAN interface.
fn create_mdns_socket(lan_iface: &str) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = format!("0.0.0.0:{}", MDNS_PORT).parse()?;
    socket.bind(&addr.into())?;

    // Join multicast group on 10.0.0.1 (the LAN gateway address)
    socket.join_multicast_v4(&MDNS_ADDR, &LAN_ADDR)?;

    // Bind socket to the LAN interface (safe wrapper around SO_BINDTODEVICE)
    socket.bind_device(Some(lan_iface.as_bytes()))?;

    Ok(socket.into())
}

/// Handle an mDNS announcement (response packet).
fn handle_announcement(
    _src: SocketAddr,
    _packet: &Packet<'_>,
    _db: &Arc<Mutex<Db>>,
    _registry: &SharedRegistry,
) {
    // TODO: Parse SRV/TXT/A records from answers, resolve source IP to MAC,
    // and upsert service records into the registry.
    debug!("mDNS announcement received");
}

/// Handle an mDNS query.
fn handle_query(
    _src: SocketAddr,
    _packet: &Packet<'_>,
    _db: &Arc<Mutex<Db>>,
    _registry: &SharedRegistry,
    _socket: &UdpSocket,
) {
    // TODO: Look up matching services in the registry (filtered by querier's
    // device group) and send unicast or multicast response.
    debug!("mDNS query received");
}

/// Main mDNS proxy loop. Listens for multicast mDNS traffic on the LAN interface,
/// records service announcements, and proxies queries across isolated subnets.
pub async fn run(db: Arc<Mutex<Db>>, lan_iface: String, registry: SharedRegistry) {
    let socket = match create_mdns_socket(&lan_iface) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to create mDNS socket");
            return;
        }
    };
    info!(iface = %lan_iface, "mDNS proxy started");

    // Spawn periodic expiry sweep
    let registry_sweep = registry.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(EXPIRY_SWEEP_SECS));
        loop {
            interval.tick().await;
            let mut reg = registry_sweep.lock().unwrap();
            reg.evict_expired();
        }
    });

    let socket = Arc::new(socket);
    let mut buf = [0u8; 9000];

    loop {
        // Yield to tokio between recv attempts on the nonblocking socket
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                warn!(error = %e, "mDNS recv error");
                continue;
            }
        };

        // Ignore packets from the router itself
        if let SocketAddr::V4(addr) = src {
            if *addr.ip() == LAN_ADDR {
                continue;
            }
        }

        let data = &buf[..len];
        let packet = match Packet::parse(data) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "failed to parse mDNS packet");
                continue;
            }
        };

        if packet.has_flags(PacketFlag::RESPONSE) {
            handle_announcement(src, &packet, &db, &registry);
        } else {
            handle_query(src, &packet, &db, &registry, &socket);
        }
    }
}

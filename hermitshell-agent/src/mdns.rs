use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use simple_dns::rdata::{RData, SRV, TXT, A};
use simple_dns::{Name, Packet, PacketFlag, ResourceRecord, CLASS};
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

    /// Query visible services with full internal data for response building.
    fn query_full(
        &self,
        querier_group: &str,
        service_type_filter: Option<&str>,
        db: &Db,
    ) -> Vec<&ServiceRecord> {
        let allowed_groups: &[&str] = match querier_group {
            "trusted" => &["trusted", "iot", "servers"],
            "iot" | "servers" => &["trusted"],
            _ => return Vec::new(),
        };

        let mut result = Vec::new();
        for (mac, entries) in &self.records {
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
                result.push(rec);
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
    src: SocketAddr,
    packet: &Packet<'_>,
    db: &Arc<Mutex<Db>>,
    registry: &SharedRegistry,
) {
    let src_ip = match src {
        SocketAddr::V4(addr) => *addr.ip(),
        _ => return,
    };

    let db_guard = db.lock().unwrap();
    let mac = match ip_to_mac(&db_guard, &src_ip) {
        Some(m) => m,
        None => {
            debug!(ip = %src_ip, "mDNS announcement from unknown device");
            return;
        }
    };

    // First pass: collect records by type.
    // A records: hostname -> IP
    let mut a_records: HashMap<String, Ipv4Addr> = HashMap::new();
    // SRV records: instance name -> (port, target hostname)
    let mut srv_records: HashMap<String, (u16, String)> = HashMap::new();
    // TXT records: instance name -> key-value pairs
    let mut txt_records: HashMap<String, Vec<(String, String)>> = HashMap::new();
    // PTR records: service type -> list of instance names
    let mut ptr_records: HashMap<String, Vec<String>> = HashMap::new();
    // Track TTLs per instance name (use SRV TTL when available)
    let mut ttl_map: HashMap<String, u32> = HashMap::new();

    let all_records = packet.answers.iter().chain(packet.additional_records.iter());

    for rr in all_records {
        let name = rr.name.to_string();
        match &rr.rdata {
            RData::A(a) => {
                let ip = Ipv4Addr::from(a.address);
                a_records.insert(name, ip);
            }
            RData::SRV(srv) => {
                let target = srv.target.to_string();
                srv_records.insert(name.clone(), (srv.port, target));
                ttl_map.insert(name, rr.ttl);
            }
            RData::TXT(txt) => {
                let attrs = txt.attributes();
                let pairs: Vec<(String, String)> = attrs
                    .into_iter()
                    .map(|(k, v)| (k, v.unwrap_or_default()))
                    .collect();
                txt_records.insert(name, pairs);
            }
            RData::PTR(ptr) => {
                let instance = ptr.0.to_string();
                ptr_records.entry(name).or_default().push(instance);
            }
            _ => {}
        }
    }

    // Second pass: combine records. Walk PTR records to discover services,
    // then correlate with SRV/TXT/A for each instance.
    let mut registry_guard = registry.lock().unwrap();

    for (service_type, instances) in &ptr_records {
        for instance_name in instances {
            let (port, target) = match srv_records.get(instance_name) {
                Some(s) => s.clone(),
                None => continue, // No SRV record for this instance
            };

            let txt = txt_records
                .get(instance_name)
                .cloned()
                .unwrap_or_default();

            // Look up A record for the SRV target hostname
            let host_ip = a_records
                .get(&target)
                .copied()
                .unwrap_or(src_ip); // Fall back to source IP if no A record

            let ttl = ttl_map.get(instance_name).copied().unwrap_or(120);

            debug!(
                mac = %mac,
                service_type = %service_type,
                instance = %instance_name,
                port = port,
                host = %host_ip,
                "mDNS service discovered"
            );

            registry_guard.upsert(
                &mac,
                service_type,
                instance_name,
                port,
                txt,
                host_ip,
                ttl,
            );
        }
    }

    // Also handle announcements that only have SRV records without PTR.
    // In this case, derive the service type from the instance name.
    for (instance_name, (port, target)) in &srv_records {
        // Skip instances already handled via PTR records
        let already_handled = ptr_records
            .values()
            .any(|instances| instances.contains(instance_name));
        if already_handled {
            continue;
        }

        // Derive service type: "Living Room._googlecast._tcp.local" -> "_googlecast._tcp.local"
        let service_type = match instance_name.find("._") {
            Some(pos) => &instance_name[pos + 1..],
            None => continue,
        };

        let txt = txt_records
            .get(instance_name)
            .cloned()
            .unwrap_or_default();

        let host_ip = a_records
            .get(target)
            .copied()
            .unwrap_or(src_ip);

        let ttl = ttl_map.get(instance_name).copied().unwrap_or(120);

        debug!(
            mac = %mac,
            service_type = %service_type,
            instance = %instance_name,
            port = port,
            host = %host_ip,
            "mDNS service discovered (no PTR)"
        );

        registry_guard.upsert(
            &mac,
            service_type,
            instance_name,
            *port,
            txt,
            host_ip,
            ttl,
        );
    }
}

/// Handle an mDNS query.
fn handle_query(
    src: SocketAddr,
    packet: &Packet<'_>,
    db: &Arc<Mutex<Db>>,
    registry: &SharedRegistry,
    socket: &UdpSocket,
) {
    let src_ip = match src {
        SocketAddr::V4(addr) => *addr.ip(),
        _ => return,
    };

    let db_guard = db.lock().unwrap();

    // Resolve querier IP to MAC and get device group
    let mac = match ip_to_mac(&db_guard, &src_ip) {
        Some(m) => m,
        None => {
            debug!(ip = %src_ip, "mDNS query from unknown device");
            return;
        }
    };

    let group = match db_guard.get_device(&mac) {
        Ok(Some(dev)) => dev.device_group,
        _ => return,
    };

    let registry_guard = registry.lock().unwrap();

    for question in &packet.questions {
        let qname = question.qname.to_string();
        debug!(from = %src_ip, name = %qname, "mDNS query");

        let records = registry_guard.query_full(&group, Some(&qname), &db_guard);
        if records.is_empty() {
            continue;
        }

        // Collect owned data from registry before building the packet, so all
        // Name/TXT values can be constructed from owned strings.
        struct OwnedEntry {
            service_type: String,
            service_name: String,
            hostname: String,
            port: u16,
            ttl: u32,
            txt_pairs: Vec<(String, String)>,
            host_ipv4: Ipv4Addr,
        }

        let entries: Vec<OwnedEntry> = records
            .iter()
            .map(|rec| {
                let hostname = format!(
                    "{}.local",
                    rec.service_name
                        .split('.')
                        .next()
                        .unwrap_or("unknown")
                        .replace(' ', "-")
                        .to_lowercase()
                );
                OwnedEntry {
                    service_type: rec.service_type.clone(),
                    service_name: rec.service_name.clone(),
                    hostname,
                    port: rec.port,
                    ttl: rec.ttl_secs,
                    txt_pairs: rec.txt_records.clone(),
                    host_ipv4: rec.host_ipv4,
                }
            })
            .collect();

        // Release the registry lock before building the response
        drop(records);

        let mut response = Packet::new_reply(0);
        response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

        for entry in &entries {
            let service_type_name = match Name::new(&entry.service_type) {
                Ok(n) => n.into_owned(),
                Err(_) => continue,
            };
            let instance_name = match Name::new(&entry.service_name) {
                Ok(n) => n.into_owned(),
                Err(_) => continue,
            };
            let host_name = match Name::new(&entry.hostname) {
                Ok(n) => n.into_owned(),
                Err(_) => continue,
            };

            // 1. PTR record: service_type -> instance_name
            response.answers.push(ResourceRecord::new(
                service_type_name,
                CLASS::IN,
                entry.ttl,
                RData::PTR(simple_dns::rdata::PTR(instance_name.clone())),
            ));

            // 2. SRV record: instance_name -> port + target hostname
            response.additional_records.push(ResourceRecord::new(
                instance_name.clone(),
                CLASS::IN,
                entry.ttl,
                RData::SRV(SRV {
                    priority: 0,
                    weight: 0,
                    port: entry.port,
                    target: host_name.clone(),
                }),
            ));

            // 3. TXT record: instance_name -> key-value pairs
            let mut txt = TXT::new();
            if entry.txt_pairs.is_empty() {
                // mDNS requires at least one TXT string, even if empty
                txt.add_char_string(
                    simple_dns::CharacterString::new(b"").unwrap_or_else(|_| {
                        // Fallback: shouldn't happen for empty string
                        unreachable!()
                    }),
                );
            } else {
                for (k, v) in &entry.txt_pairs {
                    let s = if v.is_empty() {
                        k.clone()
                    } else {
                        format!("{}={}", k, v)
                    };
                    match simple_dns::CharacterString::try_from(s) {
                        Ok(cs) => txt.add_char_string(cs),
                        Err(e) => {
                            debug!(error = %e, key = %k, "failed to add TXT attribute");
                        }
                    }
                }
            }
            response.additional_records.push(ResourceRecord::new(
                instance_name,
                CLASS::IN,
                entry.ttl,
                RData::TXT(txt),
            ));

            // 4. A record: target hostname -> IP
            response.additional_records.push(ResourceRecord::new(
                host_name,
                CLASS::IN,
                entry.ttl,
                RData::A(A::from(entry.host_ipv4)),
            ));
        }

        match response.build_bytes_vec_compressed() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, src) {
                    debug!(error = %e, dest = %src, "failed to send mDNS response");
                }
            }
            Err(e) => {
                debug!(error = %e, "failed to build mDNS response packet");
            }
        }
    }
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

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use simple_dns::rdata::{RData, SRV, TXT, A};
use simple_dns::{Name, Packet, PacketFlag, ResourceRecord, CLASS};
use tracing::{debug, error, info, warn};

use crate::db::Db;
use hermitshell_common::MdnsService;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const EXPIRY_SWEEP_SECS: u64 = 60;
/// Maximum TTL for mDNS records (75 minutes, per RFC 6762 recommendation).
const MAX_TTL_SECS: u32 = 4500;
/// Maximum number of service records per device.
const MAX_RECORDS_PER_DEVICE: usize = 50;
/// Maximum total service records across all devices.
const MAX_TOTAL_RECORDS: usize = 10_000;

/// Internal service record tracking an mDNS service announcement.
#[derive(Debug, Clone)]
struct ServiceRecord {
    #[allow(dead_code)]
    device_mac: String,
    service_type: String,
    service_name: String,
    port: u16,
    txt_records: Vec<(String, String)>,
    host_ipv4: Ipv4Addr,
    /// The SRV target hostname from the original announcement (e.g., "chromecast-xxx.local").
    target_hostname: String,
    #[allow(dead_code)]
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
    ///
    /// TTL is clamped to `MAX_TTL_SECS`. New records (not updates) are rejected
    /// if per-device or total registry limits are exceeded.
    ///
    /// A TTL of 0 is a goodbye packet (RFC 6762 Section 10.1) — the matching
    /// record is removed immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        &mut self,
        mac: &str,
        service_type: &str,
        service_name: &str,
        port: u16,
        txt: Vec<(String, String)>,
        host_ipv4: Ipv4Addr,
        target_hostname: &str,
        ttl_secs: u32,
    ) {
        // H7: TTL=0 is a goodbye — remove the record immediately
        if ttl_secs == 0 {
            if let Some(entries) = self.records.get_mut(mac) {
                entries.retain(|r| {
                    !(r.service_type == service_type && r.service_name == service_name)
                });
                if entries.is_empty() {
                    self.records.remove(mac);
                }
            }
            debug!(service = %service_name, "mDNS goodbye: removed record");
            return;
        }

        let clamped_ttl = ttl_secs.min(MAX_TTL_SECS);
        let expires_at = Instant::now() + std::time::Duration::from_secs(clamped_ttl as u64);
        let record = ServiceRecord {
            device_mac: mac.to_string(),
            service_type: service_type.to_string(),
            service_name: service_name.to_string(),
            port,
            txt_records: txt,
            host_ipv4,
            target_hostname: target_hostname.to_string(),
            ttl_secs: clamped_ttl,
            expires_at,
        };

        // Check whether this is an update of an existing record.
        let is_update = self
            .records
            .get(mac)
            .is_some_and(|entries| {
                entries.iter().any(|r| r.service_type == service_type && r.service_name == service_name)
            });

        if !is_update {
            // New record — enforce limits before inserting.
            let device_count = self.records.get(mac).map_or(0, |v| v.len());
            if device_count >= MAX_RECORDS_PER_DEVICE {
                warn!(
                    mac,
                    service_type, "mDNS: per-device record limit reached, dropping announcement"
                );
                return;
            }
            let total: usize = self.records.values().map(|v| v.len()).sum();
            if total >= MAX_TOTAL_RECORDS {
                warn!(
                    mac,
                    service_type, "mDNS: total registry limit reached, dropping announcement"
                );
                return;
            }
        }

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
    #[allow(dead_code)]
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
                if let Some(filter) = service_type_filter
                    && rec.service_type != filter {
                        continue;
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
    /// L8: Matches service_type (PTR), service_name (SRV/TXT), or target_hostname (A).
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
                    // L8: Match service_type (PTR), service_name (SRV/TXT), or target_hostname (A)
                    if rec.service_type != filter
                        && rec.service_name != filter
                        && rec.target_hostname != filter
                    {
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
fn create_mdns_socket(lan_iface: &str, lan_ip: Ipv4Addr) -> anyhow::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = format!("0.0.0.0:{}", MDNS_PORT).parse()?;
    socket.bind(&addr.into())?;

    // Join multicast group on the LAN gateway address
    socket.join_multicast_v4(&MDNS_ADDR, &lan_ip)?;

    // Bind socket to the LAN interface (safe wrapper around SO_BINDTODEVICE)
    socket.bind_device(Some(lan_iface.as_bytes()))?;

    // L11: Convert to tokio async socket
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

/// M20: Create an IPv6 mDNS socket bound to [::]:5353 with ff02::fb multicast membership.
fn create_mdns_socket_v6(lan_iface: &str) -> anyhow::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let addr: SocketAddr = "[::]:5353".parse()?;
    socket.bind(&addr.into())?;

    // Read interface index from sysfs
    let ifindex_str = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", lan_iface))
        .map_err(|e| anyhow::anyhow!("failed to read ifindex for {}: {}", lan_iface, e))?;
    let ifindex: u32 = ifindex_str
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse ifindex: {}", e))?;

    let mcast: std::net::Ipv6Addr = "ff02::fb".parse()?;
    socket.join_multicast_v6(&mcast, ifindex)?;
    socket.bind_device(Some(lan_iface.as_bytes()))?;

    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
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
                &target,
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
            target,
            ttl,
        );
    }
}

/// Handle an mDNS query. Returns a list of (response_bytes, destination) pairs to send.
fn handle_query(
    src: SocketAddr,
    packet: &Packet<'_>,
    db: &Arc<Mutex<Db>>,
    registry: &SharedRegistry,
) -> Vec<(Vec<u8>, SocketAddr)> {
    let mut responses = Vec::new();

    let src_ip = match src {
        SocketAddr::V4(addr) => *addr.ip(),
        _ => return responses,
    };

    let db_guard = db.lock().unwrap();

    // Resolve querier IP to MAC and get device group
    let mac = match ip_to_mac(&db_guard, &src_ip) {
        Some(m) => m,
        None => {
            debug!(ip = %src_ip, "mDNS query from unknown device");
            return responses;
        }
    };

    let group = match db_guard.get_device(&mac) {
        Ok(Some(dev)) => dev.device_group,
        _ => return responses,
    };

    let registry_guard = registry.lock().unwrap();

    // H6: Detect legacy unicast queries (source port != 5353)
    let is_legacy = src.port() != MDNS_PORT;

    for question in &packet.questions {
        let qname = question.qname.to_string();
        debug!(from = %src_ip, name = %qname, "mDNS query");

        // Always unicast responses to the querier to preserve device isolation.
        // RFC 6762 §6.3 says multicast for QU=0 queries, but multicast leaks
        // response packets to all LAN devices, undermining group-based isolation.
        // Documented in SECURITY.md.
        let dest = src;

        // L8: Meta-query support for _services._dns-sd._udp.local
        if qname == "_services._dns-sd._udp.local" {
            let all_records = registry_guard.query_full(&group, None, &db_guard);
            let mut service_types: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for rec in &all_records {
                service_types.insert(rec.service_type.clone());
            }
            // H6: Legacy queries use query ID; standard queries use 0
            let mut response =
                Packet::new_reply(if is_legacy { packet.id() } else { 0 });
            response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
            let meta_name = Name::new("_services._dns-sd._udp.local")
                .unwrap()
                .into_owned();
            for stype in &service_types {
                if let Ok(stype_name) = Name::new(stype) {
                    let ttl = if is_legacy { MAX_TTL_SECS.min(10) } else { MAX_TTL_SECS };
                    response.answers.push(ResourceRecord::new(
                        meta_name.clone(),
                        CLASS::IN,
                        ttl,
                        RData::PTR(simple_dns::rdata::PTR(stype_name.into_owned())),
                    ));
                }
            }
            if let Ok(bytes) = response.build_bytes_vec_compressed() {
                responses.push((bytes, dest));
            }
            continue;
        }

        let records = registry_guard.query_full(&group, Some(&qname), &db_guard);
        if records.is_empty() {
            continue;
        }

        // L10: Known-answer suppression — filter out records the querier already
        // has with >= 50% remaining TTL.
        let records: Vec<_> = records
            .into_iter()
            .filter(|rec| {
                let remaining = rec
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs() as u32;
                !packet.answers.iter().any(|ans| {
                    ans.name.to_string() == rec.service_name && ans.ttl >= remaining / 2
                })
            })
            .collect();

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

        // L9: Use remaining TTL instead of original TTL
        let entries: Vec<OwnedEntry> = records
            .iter()
            .map(|rec| {
                let remaining_ttl = rec
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs() as u32;
                OwnedEntry {
                    service_type: rec.service_type.clone(),
                    service_name: rec.service_name.clone(),
                    hostname: rec.target_hostname.clone(),
                    port: rec.port,
                    ttl: remaining_ttl.max(1), // at least 1 second
                    txt_pairs: rec.txt_records.clone(),
                    host_ipv4: rec.host_ipv4,
                }
            })
            .collect();

        // Release the registry lock is not needed here since we still hold registry_guard;
        // the owned data is already cloned above.
        drop(records);

        // H6: Legacy queries use query ID; standard mDNS replies use 0
        let mut response = Packet::new_reply(if is_legacy { packet.id() } else { 0 });
        response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

        for entry in &entries {
            // H6: Legacy queries clamp TTL to 10 seconds
            let effective_ttl = if is_legacy { entry.ttl.min(10) } else { entry.ttl };

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
                effective_ttl,
                RData::PTR(simple_dns::rdata::PTR(instance_name.clone())),
            ));

            // 2. SRV record: instance_name -> port + target hostname
            response.additional_records.push(ResourceRecord::new(
                instance_name.clone(),
                CLASS::IN,
                effective_ttl,
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
                effective_ttl,
                RData::TXT(txt),
            ));

            // 4. A record: target hostname -> IP
            response.additional_records.push(ResourceRecord::new(
                host_name,
                CLASS::IN,
                effective_ttl,
                RData::A(A::from(entry.host_ipv4)),
            ));
        }

        match response.build_bytes_vec_compressed() {
            Ok(bytes) => {
                responses.push((bytes, dest));
            }
            Err(e) => {
                debug!(error = %e, "failed to build mDNS response packet");
            }
        }
    }

    responses
}

/// Main mDNS proxy loop. Listens for multicast mDNS traffic on the LAN interface,
/// records service announcements, and proxies queries across isolated subnets.
pub async fn run(db: Arc<Mutex<Db>>, lan_iface: String, registry: SharedRegistry, lan_ip_str: String) {
    let lan_ip: Ipv4Addr = lan_ip_str.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
    let socket = match create_mdns_socket(&lan_iface, lan_ip) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to create mDNS socket");
            return;
        }
    };

    // M20: Create IPv6 mDNS socket (ff02::fb), fall back to IPv4-only on failure
    let socket_v6 = match create_mdns_socket_v6(&lan_iface) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "failed to create IPv6 mDNS socket, continuing with IPv4 only");
            None
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

    let mut buf = [0u8; 9000];
    let mut buf_v6 = [0u8; 9000];

    loop {
        // L11: Async I/O instead of 50ms polling loop
        let (len, src, data_ref) = tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => (len, src, &buf as &[u8; 9000]),
                    Err(e) => {
                        warn!(error = %e, "mDNS recv error");
                        continue;
                    }
                }
            }
            result = async {
                match &socket_v6 {
                    Some(s) => s.recv_from(&mut buf_v6).await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok((len, src)) => (len, src, &buf_v6 as &[u8; 9000]),
                    Err(e) => {
                        warn!(error = %e, "mDNS v6 recv error");
                        continue;
                    }
                }
            }
        };

        // Ignore packets from the router itself
        if let SocketAddr::V4(addr) = src
            && *addr.ip() == lan_ip {
                continue;
            }

        let data = &data_ref[..len];
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
            let responses = handle_query(src, &packet, &db, &registry);
            for (bytes, dest) in responses {
                // Send via the appropriate socket (v4 or v6) based on destination
                let send_result = if dest.is_ipv4() {
                    socket.send_to(&bytes, dest).await
                } else if let Some(ref s6) = socket_v6 {
                    s6.send_to(&bytes, dest).await
                } else {
                    continue;
                };
                if let Err(e) = send_result {
                    debug!(error = %e, dest = %dest, "failed to send mDNS response");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_upsert(reg: &mut ServiceRegistry, mac: &str, stype: &str, sname: &str, ttl: u32) {
        reg.upsert(
            mac,
            stype,
            sname,
            80,
            vec![],
            Ipv4Addr::new(10, 0, 0, 2),
            "host.local",
            ttl,
        );
    }

    #[test]
    fn ttl_clamped_to_max() {
        let mut reg = ServiceRegistry::new();
        dummy_upsert(&mut reg, "AA:BB:CC:DD:EE:01", "_http._tcp.local", "web", 999_999);
        let entries = &reg.records["AA:BB:CC:DD:EE:01"];
        assert_eq!(entries[0].ttl_secs, MAX_TTL_SECS);
    }

    #[test]
    fn ttl_below_max_unchanged() {
        let mut reg = ServiceRegistry::new();
        dummy_upsert(&mut reg, "AA:BB:CC:DD:EE:01", "_http._tcp.local", "web", 120);
        let entries = &reg.records["AA:BB:CC:DD:EE:01"];
        assert_eq!(entries[0].ttl_secs, 120);
    }

    #[test]
    fn per_device_limit_enforced() {
        let mut reg = ServiceRegistry::new();
        let mac = "AA:BB:CC:DD:EE:01";
        for i in 0..MAX_RECORDS_PER_DEVICE {
            dummy_upsert(&mut reg, mac, &format!("_svc{}._tcp.local", i), "name", 120);
        }
        assert_eq!(reg.records[mac].len(), MAX_RECORDS_PER_DEVICE);

        // One more should be dropped
        dummy_upsert(&mut reg, mac, "_extra._tcp.local", "name", 120);
        assert_eq!(reg.records[mac].len(), MAX_RECORDS_PER_DEVICE);
    }

    #[test]
    fn update_existing_bypasses_limit() {
        let mut reg = ServiceRegistry::new();
        let mac = "AA:BB:CC:DD:EE:01";
        for i in 0..MAX_RECORDS_PER_DEVICE {
            dummy_upsert(&mut reg, mac, &format!("_svc{}._tcp.local", i), "name", 120);
        }

        // Updating an existing record should succeed even at the limit
        dummy_upsert(&mut reg, mac, "_svc0._tcp.local", "name", 300);
        assert_eq!(reg.records[mac][0].ttl_secs, 300);
    }

    #[test]
    fn total_registry_limit_enforced() {
        let mut reg = ServiceRegistry::new();
        // Fill with records spread across many devices
        for d in 0..(MAX_TOTAL_RECORDS / MAX_RECORDS_PER_DEVICE) {
            let mac = format!("AA:BB:CC:{:02X}:{:02X}:01", d / 256, d % 256);
            for s in 0..MAX_RECORDS_PER_DEVICE {
                dummy_upsert(&mut reg, &mac, &format!("_s{}._tcp.local", s), "n", 120);
            }
        }
        let total: usize = reg.records.values().map(|v| v.len()).sum();
        assert_eq!(total, MAX_TOTAL_RECORDS);

        // One more from a new device should be dropped
        dummy_upsert(&mut reg, "FF:FF:FF:FF:FF:FF", "_new._tcp.local", "n", 120);
        let total: usize = reg.records.values().map(|v| v.len()).sum();
        assert_eq!(total, MAX_TOTAL_RECORDS);
    }

    #[test]
    fn goodbye_removes_record() {
        let mut reg = ServiceRegistry::new();
        let mac = "AA:BB:CC:DD:EE:01";
        dummy_upsert(&mut reg, mac, "_http._tcp.local", "web", 120);
        assert_eq!(reg.records[mac].len(), 1);

        // TTL=0 goodbye should remove the record
        dummy_upsert(&mut reg, mac, "_http._tcp.local", "web", 0);
        assert!(!reg.records.contains_key(mac));
    }

    #[test]
    fn goodbye_only_removes_matching_record() {
        let mut reg = ServiceRegistry::new();
        let mac = "AA:BB:CC:DD:EE:01";
        dummy_upsert(&mut reg, mac, "_http._tcp.local", "web", 120);
        dummy_upsert(&mut reg, mac, "_ssh._tcp.local", "ssh", 120);
        assert_eq!(reg.records[mac].len(), 2);

        // Goodbye for just the HTTP service
        dummy_upsert(&mut reg, mac, "_http._tcp.local", "web", 0);
        assert_eq!(reg.records[mac].len(), 1);
        assert_eq!(reg.records[mac][0].service_type, "_ssh._tcp.local");
    }

    #[test]
    fn goodbye_for_nonexistent_record_is_noop() {
        let mut reg = ServiceRegistry::new();
        let mac = "AA:BB:CC:DD:EE:01";
        // Goodbye for a record that doesn't exist should not panic or error
        dummy_upsert(&mut reg, mac, "_http._tcp.local", "web", 0);
        assert!(!reg.records.contains_key(mac));
    }
}

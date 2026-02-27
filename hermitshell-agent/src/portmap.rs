use std::fmt;
use std::sync::{Arc, Mutex};

use tracing::info;

use crate::db::{Db, PortForward};
use crate::nftables;

/// Maximum automatic (non-manual) mappings per requesting IP.
const MAX_MAPPINGS_PER_IP: i64 = 20;

/// Maximum total automatic (non-manual) mappings across all IPs.
const MAX_AUTOMATIC_TOTAL: i64 = 128;

/// Minimum lease duration in seconds.
const MIN_LEASE_SECS: u32 = 120;

/// Maximum lease duration in seconds (24 hours).
const MAX_LEASE_SECS: u32 = 86400;

/// Lowest external port that automatic mappings may use.
const MIN_EXTERNAL_PORT: u16 = 1024;

/// Errors returned by port mapping operations.
#[derive(Debug)]
pub enum MappingError {
    /// Requesting device is not in the "trusted" group.
    NotTrusted,
    /// Secure mode: internal_ip must equal requesting_ip.
    SecureMode,
    /// External port is below MIN_EXTERNAL_PORT.
    PrivilegedPort,
    /// Per-IP mapping limit exceeded.
    PerIpLimit,
    /// Global automatic mapping limit exceeded.
    GlobalLimit,
    /// Port/protocol already mapped by another device.
    Conflict(String),
    /// Internal error (DB, nftables, etc.).
    Internal(String),
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MappingError::NotTrusted => write!(f, "device is not in the trusted group"),
            MappingError::SecureMode => {
                write!(f, "internal_ip must match requesting_ip (secure mode)")
            }
            MappingError::PrivilegedPort => {
                write!(f, "external port must be >= {}", MIN_EXTERNAL_PORT)
            }
            MappingError::PerIpLimit => {
                write!(f, "per-IP mapping limit ({}) exceeded", MAX_MAPPINGS_PER_IP)
            }
            MappingError::GlobalLimit => {
                write!(
                    f,
                    "global automatic mapping limit ({}) exceeded",
                    MAX_AUTOMATIC_TOTAL
                )
            }
            MappingError::Conflict(msg) => write!(f, "port conflict: {}", msg),
            MappingError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

/// A request to create or renew a port mapping.
pub struct MappingRequest {
    /// "tcp" or "udp"
    pub protocol: String,
    /// External port on the WAN side.
    pub external_port: u16,
    /// LAN IP to forward to.
    pub internal_ip: String,
    /// Internal port on the LAN device.
    pub internal_port: u16,
    /// Human-readable description.
    pub description: String,
    /// Origin: "upnp", "natpmp", or "pcp".
    pub source: String,
    /// IP of the device making the request.
    pub requesting_ip: String,
    /// Requested lease duration in seconds (0 = use default).
    pub lease_secs: u32,
}

/// Response after a successful mapping creation/renewal.
pub struct MappingResponse {
    /// The external port that was mapped.
    pub external_port: u16,
    /// The actual lease lifetime granted, in seconds.
    pub lifetime: u32,
}

/// Central coordinator for port mappings from all entry points
/// (UPnP SOAP, NAT-PMP, PCP, and the manual socket API).
pub struct PortMapRegistry {
    db: Arc<Mutex<Db>>,
    wan_iface: String,
    lan_iface: String,
    lan_ip: String,
}

impl PortMapRegistry {
    pub fn new(db: Arc<Mutex<Db>>, wan_iface: String, lan_iface: String, lan_ip: String) -> Self {
        Self {
            db,
            wan_iface,
            lan_iface,
            lan_ip,
        }
    }

    /// The WAN interface name used for nftables rules.
    pub fn wan_iface(&self) -> &str {
        &self.wan_iface
    }

    /// Check whether `ip` belongs to a device in the "trusted" group.
    fn is_trusted(ip: &str, db: &Db) -> bool {
        let devices = match db.list_assigned_devices() {
            Ok(d) => d,
            Err(_) => return false,
        };
        devices.iter().any(|d| {
            d.ipv4.as_deref() == Some(ip) && d.device_group == "trusted"
        })
    }

    /// Create or renew an automatic port mapping.
    ///
    /// Enforces:
    /// - Requesting device must be trusted
    /// - Secure mode (internal_ip == requesting_ip)
    /// - External port >= 1024
    /// - Per-IP and global automatic mapping limits
    /// - Lease clamping (0 -> 3600, otherwise 120..86400)
    /// - Conflict detection with renewal support
    pub fn add_mapping(&self, req: &MappingRequest) -> Result<MappingResponse, MappingError> {
        // 0. Validate protocol and internal IP before acquiring lock
        if !matches!(req.protocol.as_str(), "tcp" | "udp" | "both") {
            return Err(MappingError::Internal(
                "protocol must be tcp, udp, or both".into(),
            ));
        }
        nftables::validate_ip(&req.internal_ip)
            .map_err(|e| MappingError::Internal(e.to_string()))?;

        let db = self.db.lock().unwrap();

        // 1. Check trust
        if !Self::is_trusted(&req.requesting_ip, &db) {
            return Err(MappingError::NotTrusted);
        }

        // 2. Secure mode: internal_ip must match requesting_ip
        if req.internal_ip != req.requesting_ip {
            return Err(MappingError::SecureMode);
        }

        // 3. Privileged port check
        if req.external_port < MIN_EXTERNAL_PORT {
            return Err(MappingError::PrivilegedPort);
        }

        // 4. Per-IP limit
        let ip_count = db
            .count_port_forwards_by_ip(&req.requesting_ip)
            .map_err(|e| MappingError::Internal(e.to_string()))?;
        if ip_count >= MAX_MAPPINGS_PER_IP {
            return Err(MappingError::PerIpLimit);
        }

        // 5. Global automatic limit
        let total_count = db
            .count_automatic_port_forwards()
            .map_err(|e| MappingError::Internal(e.to_string()))?;
        if total_count >= MAX_AUTOMATIC_TOTAL {
            return Err(MappingError::GlobalLimit);
        }

        // 6. Clamp lease: 0 -> 3600, otherwise clamp to [120, 86400]
        let lifetime = if req.lease_secs == 0 {
            3600
        } else {
            req.lease_secs.clamp(MIN_LEASE_SECS, MAX_LEASE_SECS)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expires_at = now + lifetime as i64;

        // 7. Check for existing mapping on same (protocol, external_port)
        if let Some(existing) = db
            .find_port_forward(&req.protocol, req.external_port)
            .map_err(|e| MappingError::Internal(e.to_string()))?
        {
            // Same requesting IP and automatic source? Treat as renewal.
            if existing.requesting_ip.as_deref() == Some(&req.requesting_ip)
                && existing.source != "manual"
            {
                // Delete old, will insert new below
                db.remove_port_forward(existing.id)
                    .map_err(|e| MappingError::Internal(e.to_string()))?;
            } else {
                return Err(MappingError::Conflict(format!(
                    "{} port {} already mapped to {}:{} ({})",
                    existing.protocol,
                    req.external_port,
                    existing.internal_ip,
                    existing.internal_port,
                    existing.description,
                )));
            }
        }

        // 8. Check overlap with all existing forwards (protocol cross-matching)
        let all_forwards = db
            .list_port_forwards()
            .map_err(|e| MappingError::Internal(e.to_string()))?;
        for fwd in &all_forwards {
            let protocols_overlap = req.protocol == fwd.protocol
                || req.protocol == "both"
                || fwd.protocol == "both";
            let ports_overlap =
                req.external_port <= fwd.external_port_end
                    && req.external_port >= fwd.external_port_start;
            if protocols_overlap && ports_overlap {
                return Err(MappingError::Conflict(format!(
                    "{} port {} overlaps with '{}' (ports {}-{})",
                    fwd.protocol,
                    req.external_port,
                    fwd.description,
                    fwd.external_port_start,
                    fwd.external_port_end,
                )));
            }
        }

        // 9. Insert
        db.add_port_forward_ext(
            &req.protocol,
            req.external_port,
            req.external_port,
            &req.internal_ip,
            req.internal_port,
            &req.description,
            &req.source,
            Some(expires_at),
            &req.requesting_ip,
        )
        .map_err(|e| MappingError::Internal(e.to_string()))?;

        // 10. Reapply nftables
        Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip)?;

        info!(
            protocol = %req.protocol,
            external_port = req.external_port,
            internal = %format!("{}:{}", req.internal_ip, req.internal_port),
            source = %req.source,
            lifetime = lifetime,
            requesting_ip = %req.requesting_ip,
            "port mapping added"
        );

        Ok(MappingResponse {
            external_port: req.external_port,
            lifetime,
        })
    }

    /// Remove an automatic mapping. Only the original requesting IP may remove it.
    pub fn remove_mapping(
        &self,
        protocol: &str,
        ext_port: u16,
        requesting_ip: &str,
    ) -> Result<(), MappingError> {
        let db = self.db.lock().unwrap();

        let existing = db
            .find_port_forward(protocol, ext_port)
            .map_err(|e| MappingError::Internal(e.to_string()))?;

        match existing {
            Some(fwd)
                if fwd.source != "manual"
                    && fwd.requesting_ip.as_deref() == Some(requesting_ip) =>
            {
                db.remove_port_forward(fwd.id)
                    .map_err(|e| MappingError::Internal(e.to_string()))?;
                Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip)?;
                info!(
                    protocol = %protocol,
                    external_port = ext_port,
                    requesting_ip = %requesting_ip,
                    "port mapping removed"
                );
                Ok(())
            }
            Some(_) => Err(MappingError::Conflict(
                "mapping belongs to another device or is manual".into(),
            )),
            None => Ok(()), // Already gone; idempotent
        }
    }

    /// Remove all automatic mappings for a given protocol and requesting IP.
    pub fn remove_all_by_source(&self, protocol: &str, requesting_ip: &str) -> Result<(), MappingError> {
        let db = self.db.lock().unwrap();
        db.remove_auto_port_forwards_by_source(protocol, requesting_ip)
            .map_err(|e| MappingError::Internal(e.to_string()))?;
        Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip)?;
        info!(protocol = %protocol, requesting_ip = %requesting_ip, "bulk port mappings removed");
        Ok(())
    }

    /// Look up a mapping by protocol and external port.
    pub fn get_mapping(&self, protocol: &str, ext_port: u16) -> Option<PortForward> {
        let db = self.db.lock().unwrap();
        db.find_port_forward(protocol, ext_port).ok().flatten()
    }

    /// List all enabled port forwards (manual and automatic).
    pub fn list_mappings(&self) -> Vec<PortForward> {
        let db = self.db.lock().unwrap();
        db.list_enabled_port_forwards().unwrap_or_default()
    }

    /// Delete expired leases and reapply nftables if any were removed.
    /// Returns the number of expired mappings deleted.
    pub fn expire_leases(&self) -> usize {
        let db = self.db.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let deleted = db.delete_expired_port_forwards(now).unwrap_or(0);
        if deleted > 0 {
            info!(count = deleted, "expired port mappings removed");
            let _ = Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip);
        }
        deleted
    }

    /// Delete all automatic (non-manual) mappings and reapply nftables.
    pub fn clear_automatic(&self) {
        let db = self.db.lock().unwrap();
        let deleted = db.delete_automatic_port_forwards().unwrap_or(0);
        if deleted > 0 {
            info!(count = deleted, "automatic port mappings cleared");
        }
        let _ = Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip);
    }

    /// Reapply nftables port forwarding rules from the current DB state.
    /// Public so socket handlers can call it after manual forward changes.
    pub fn reapply_rules(&self) {
        let db = self.db.lock().unwrap();
        let _ = Self::apply_rules(&db, &self.wan_iface, &self.lan_iface, &self.lan_ip);
    }

    /// Read enabled forwards + DMZ from DB, then call nftables::apply_port_forwards.
    fn apply_rules(db: &Db, wan_iface: &str, lan_iface: &str, lan_ip: &str) -> Result<(), MappingError> {
        let forwards = db
            .list_enabled_port_forwards()
            .map_err(|e| MappingError::Internal(e.to_string()))?;
        let dmz = db
            .get_config("dmz_host_ip")
            .ok()
            .flatten()
            .unwrap_or_default();
        let dmz_ref = if dmz.is_empty() {
            None
        } else {
            Some(dmz.as_str())
        };
        nftables::apply_port_forwards(wan_iface, lan_iface, &forwards, dmz_ref, lan_ip)
            .map_err(|e| MappingError::Internal(e.to_string()))
    }
}

/// Shared registry handle for use across async tasks and socket handlers.
pub type SharedRegistry = Arc<PortMapRegistry>;

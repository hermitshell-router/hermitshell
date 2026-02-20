use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

/// Hard limit from 10.0.0.0/8 address space: 16,580,355 /32 addresses.
/// Practical bottlenecks before hitting this:
/// - Counter polling: main loop dumps full nft sets per device every 10s.
///   Fix: single dump parsed once, or nft get element for individual lookups.
/// - Restart restore: list_assigned_devices is a full table scan, each device
///   re-adds a /32 route + verdict map element + counter set element.
const MAX_DEVICES: i64 = 16_580_355;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ipv4 TEXT,
    ipv6_ula TEXT,
    ipv6_global TEXT,
    hostname TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    device_group TEXT NOT NULL DEFAULT 'quarantine',
    subnet_id INTEGER
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO config (key, value) VALUES ('next_subnet_id', '0');
INSERT OR IGNORE INTO config (key, value) VALUES ('ad_blocking_enabled', 'true');

CREATE TABLE IF NOT EXISTS wg_peers (
    public_key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subnet_id INTEGER NOT NULL,
    device_group TEXT NOT NULL DEFAULT 'quarantine',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS port_forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL DEFAULT 'both',
    external_port_start INTEGER NOT NULL,
    external_port_end INTEGER NOT NULL,
    internal_ip TEXT NOT NULL,
    internal_port INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dhcp_reservations (
    mac TEXT PRIMARY KEY,
    subnet_id INTEGER NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    bytes_recv INTEGER NOT NULL DEFAULT 0,
    started_at INTEGER NOT NULL,
    ended_at INTEGER
);

CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ipv6_pinholes (
    id INTEGER PRIMARY KEY,
    device_mac TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port_start INTEGER NOT NULL,
    port_end INTEGER NOT NULL,
    description TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_baselines (
    mac TEXT NOT NULL,
    metric TEXT NOT NULL,
    window_avg REAL NOT NULL,
    window_stddev REAL NOT NULL,
    last_computed INTEGER NOT NULL,
    PRIMARY KEY (mac, metric)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    created_at INTEGER NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_mac);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_conn_logs_device_started ON connection_logs(device_ip, started_at);
CREATE INDEX IF NOT EXISTS idx_dns_logs_device_ts ON dns_logs(device_ip, ts);
"#;

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub mac: String,
    pub ipv4: Option<String>,
    pub ipv6_ula: Option<String>,
    pub ipv6_global: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub device_group: String,
    pub subnet_id: Option<i64>,
    pub runzero_os: Option<String>,
    pub runzero_hw: Option<String>,
    pub runzero_device_type: Option<String>,
    pub runzero_manufacturer: Option<String>,
    pub runzero_last_sync: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WgPeer {
    pub public_key: String,
    pub name: String,
    pub subnet_id: i64,
    pub device_group: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortForward {
    pub id: i64,
    pub protocol: String,
    pub external_port_start: u16,
    pub external_port_end: u16,
    pub internal_ip: String,
    pub internal_port: u16,
    pub enabled: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpReservation {
    pub mac: String,
    pub subnet_id: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionLog {
    pub id: i64,
    pub device_ip: String,
    pub dest_ip: String,
    pub dest_port: i64,
    pub protocol: String,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsLogEntry {
    pub id: i64,
    pub device_ip: String,
    pub domain: String,
    pub query_type: String,
    pub ts: i64,
}

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap())?;
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        for col in &[
            "runzero_os TEXT",
            "runzero_hw TEXT",
            "runzero_device_type TEXT",
            "runzero_manufacturer TEXT",
            "runzero_last_sync INTEGER",
        ] {
            let _ = conn.execute_batch(&format!("ALTER TABLE devices ADD COLUMN {col}"));
        }
        // Behavioral analysis tables (idempotent)
        let _ = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS device_baselines (
                mac TEXT NOT NULL,
                metric TEXT NOT NULL,
                window_avg REAL NOT NULL,
                window_stddev REAL NOT NULL,
                last_computed INTEGER NOT NULL,
                PRIMARY KEY (mac, metric)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                created_at INTEGER NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_mac);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_conn_logs_device_started ON connection_logs(device_ip, started_at);
            CREATE INDEX IF NOT EXISTS idx_dns_logs_device_ts ON dns_logs(device_ip, ts);"
        );
        Ok(())
    }

    pub fn update_counters(&self, ip: &str, rx_bytes: i64, tx_bytes: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET rx_bytes = ?1, tx_bytes = ?2 WHERE ipv4 = ?3",
            (rx_bytes, tx_bytes, ip),
        )?;
        Ok(())
    }

    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync FROM devices"
        )?;
        let devices = stmt.query_map([], |row| {
            Ok(Device {
                mac: row.get(0)?,
                ipv4: row.get(1)?,
                ipv6_ula: row.get(2)?,
                ipv6_global: row.get(3)?,
                hostname: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                rx_bytes: row.get(7)?,
                tx_bytes: row.get(8)?,
                device_group: row.get(9)?,
                subnet_id: row.get(10)?,
                runzero_os: row.get(11)?,
                runzero_hw: row.get(12)?,
                runzero_device_type: row.get(13)?,
                runzero_manufacturer: row.get(14)?,
                runzero_last_sync: row.get(15)?,
            })
        })?;
        Ok(devices.filter_map(|d| d.ok()).collect())
    }

    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync FROM devices WHERE mac = ?1"
        )?;
        let mut rows = stmt.query([mac])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Device {
                mac: row.get(0)?,
                ipv4: row.get(1)?,
                ipv6_ula: row.get(2)?,
                ipv6_global: row.get(3)?,
                hostname: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                rx_bytes: row.get(7)?,
                tx_bytes: row.get(8)?,
                device_group: row.get(9)?,
                subnet_id: row.get(10)?,
                runzero_os: row.get(11)?,
                runzero_hw: row.get(12)?,
                runzero_device_type: row.get(13)?,
                runzero_manufacturer: row.get(14)?,
                runzero_last_sync: row.get(15)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Allocate next subnet_id atomically: read current value, increment, return old value.
    /// Refuses to allocate beyond MAX_DEVICES to prevent resource exhaustion.
    pub fn allocate_subnet_id(&self) -> Result<i64> {
        let id: i64 = self.conn.query_row(
            "SELECT value FROM config WHERE key = 'next_subnet_id'",
            [],
            |row| row.get::<_, String>(0),
        )?.parse()?;
        if id >= MAX_DEVICES {
            anyhow::bail!("device limit reached ({} max)", MAX_DEVICES);
        }
        self.conn.execute(
            "UPDATE config SET value = ?1 WHERE key = 'next_subnet_id'",
            [(id + 1).to_string()],
        )?;
        Ok(id)
    }

    /// Insert new device with subnet assignment (called from DHCP server on first DISCOVER)
    pub fn insert_new_device(&self, mac: &str, subnet_id: i64, ip: &str, ipv6_ula: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT OR IGNORE INTO devices (mac, ipv4, ipv6_ula, first_seen, last_seen, device_group, subnet_id)
             VALUES (?1, ?2, ?3, ?4, ?4, 'quarantine', ?5)",
            (mac, ip, ipv6_ula, now, subnet_id),
        )?;
        Ok(())
    }

    /// Change device group
    pub fn set_device_group(&self, mac: &str, group: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET device_group = ?1 WHERE mac = ?2",
            (group, mac),
        )?;
        Ok(())
    }

    /// Block device
    pub fn block_device(&self, mac: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET device_group = 'blocked' WHERE mac = ?1",
            [mac],
        )?;
        Ok(())
    }

    /// Unblock device (back to quarantine)
    pub fn unblock_device(&self, mac: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET device_group = 'quarantine' WHERE mac = ?1",
            [mac],
        )?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM config WHERE key = ?1")?;
        let mut rows = stmt.query([key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            (key, value),
        )?;
        Ok(())
    }

    /// List all devices that have subnet_id set (for state restoration on startup)
    pub fn list_assigned_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync FROM devices WHERE subnet_id IS NOT NULL"
        )?;
        let devices = stmt.query_map([], |row| {
            Ok(Device {
                mac: row.get(0)?,
                ipv4: row.get(1)?,
                ipv6_ula: row.get(2)?,
                ipv6_global: row.get(3)?,
                hostname: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                rx_bytes: row.get(7)?,
                tx_bytes: row.get(8)?,
                device_group: row.get(9)?,
                subnet_id: row.get(10)?,
                runzero_os: row.get(11)?,
                runzero_hw: row.get(12)?,
                runzero_device_type: row.get(13)?,
                runzero_manufacturer: row.get(14)?,
                runzero_last_sync: row.get(15)?,
            })
        })?;
        Ok(devices.filter_map(|d| d.ok()).collect())
    }

    pub fn insert_wg_peer(&self, public_key: &str, name: &str, subnet_id: i64, group: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO wg_peers (public_key, name, subnet_id, device_group, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            (public_key, name, subnet_id, group, now),
        )?;
        Ok(())
    }

    pub fn remove_wg_peer(&self, public_key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM wg_peers WHERE public_key = ?1", [public_key])?;
        Ok(())
    }

    pub fn get_wg_peer(&self, public_key: &str) -> Result<Option<WgPeer>> {
        let mut stmt = self.conn.prepare(
            "SELECT public_key, name, subnet_id, device_group, enabled, created_at FROM wg_peers WHERE public_key = ?1"
        )?;
        let mut rows = stmt.query([public_key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(WgPeer {
                public_key: row.get(0)?,
                name: row.get(1)?,
                subnet_id: row.get(2)?,
                device_group: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_wg_peers(&self) -> Result<Vec<WgPeer>> {
        let mut stmt = self.conn.prepare(
            "SELECT public_key, name, subnet_id, device_group, enabled, created_at FROM wg_peers"
        )?;
        let peers = stmt.query_map([], |row| {
            Ok(WgPeer {
                public_key: row.get(0)?,
                name: row.get(1)?,
                subnet_id: row.get(2)?,
                device_group: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })?;
        Ok(peers.filter_map(|p| p.ok()).collect())
    }

    pub fn set_wg_peer_group(&self, public_key: &str, group: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE wg_peers SET device_group = ?1 WHERE public_key = ?2",
            (group, public_key),
        )?;
        Ok(())
    }

    // Port forwarding methods

    pub fn list_port_forwards(&self) -> Result<Vec<PortForward>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, protocol, external_port_start, external_port_end, internal_ip, internal_port, enabled, description FROM port_forwards"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PortForward {
                id: row.get(0)?,
                protocol: row.get(1)?,
                external_port_start: row.get(2)?,
                external_port_end: row.get(3)?,
                internal_ip: row.get(4)?,
                internal_port: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                description: row.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn add_port_forward(
        &self, protocol: &str, ext_start: u16, ext_end: u16,
        internal_ip: &str, internal_port: u16, description: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO port_forwards (protocol, external_port_start, external_port_end, internal_ip, internal_port, description) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (protocol, ext_start, ext_end, internal_ip, internal_port, description),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_port_forward(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM port_forwards WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn set_port_forward_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE port_forwards SET enabled = ?1 WHERE id = ?2",
            (if enabled { 1 } else { 0 }, id),
        )?;
        Ok(())
    }

    pub fn list_enabled_port_forwards(&self) -> Result<Vec<PortForward>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, protocol, external_port_start, external_port_end, internal_ip, internal_port, enabled, description FROM port_forwards WHERE enabled = 1"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PortForward {
                id: row.get(0)?,
                protocol: row.get(1)?,
                external_port_start: row.get(2)?,
                external_port_end: row.get(3)?,
                internal_ip: row.get(4)?,
                internal_port: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                description: row.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // DHCP reservation methods

    pub fn list_dhcp_reservations(&self) -> Result<Vec<DhcpReservation>> {
        let mut stmt = self.conn.prepare("SELECT mac, subnet_id FROM dhcp_reservations")?;
        let rows = stmt.query_map([], |row| {
            Ok(DhcpReservation {
                mac: row.get(0)?,
                subnet_id: row.get(1)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_dhcp_reservation(&self, mac: &str) -> Result<Option<DhcpReservation>> {
        let mut stmt = self.conn.prepare("SELECT mac, subnet_id FROM dhcp_reservations WHERE mac = ?1")?;
        let mut rows = stmt.query([mac])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DhcpReservation { mac: row.get(0)?, subnet_id: row.get(1)? }))
        } else {
            Ok(None)
        }
    }

    pub fn set_dhcp_reservation(&self, mac: &str, subnet_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO dhcp_reservations (mac, subnet_id) VALUES (?1, ?2) ON CONFLICT(mac) DO UPDATE SET subnet_id = ?2",
            (mac, subnet_id),
        )?;
        Ok(())
    }

    pub fn remove_dhcp_reservation(&self, mac: &str) -> Result<()> {
        self.conn.execute("DELETE FROM dhcp_reservations WHERE mac = ?1", [mac])?;
        Ok(())
    }

    pub fn set_device_hostname(&self, mac: &str, hostname: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "UPDATE devices SET hostname = ?1, last_seen = ?2 WHERE mac = ?3",
            (hostname, now, mac),
        )?;
        Ok(())
    }

    pub fn update_runzero_data(&self, mac: &str, os: Option<&str>, hw: Option<&str>, device_type: Option<&str>, manufacturer: Option<&str>) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "UPDATE devices SET runzero_os = ?1, runzero_hw = ?2, runzero_device_type = ?3, runzero_manufacturer = ?4, runzero_last_sync = ?5 WHERE mac = ?6",
            (os, hw, device_type, manufacturer, now, mac),
        )?;
        Ok(())
    }

    pub fn conn_exec(&self, sql: &str) -> Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    pub fn vacuum_into(&self, path: &str) -> Result<()> {
        self.conn.execute(&format!("VACUUM INTO '{}'", path), [])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    // Connection log methods

    pub fn insert_connection(&self, device_ip: &str, dest_ip: &str, dest_port: i64, protocol: &str, started_at: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO connection_logs (device_ip, dest_ip, dest_port, protocol, started_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            (device_ip, dest_ip, dest_port, protocol, started_at),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_connection_end(&self, device_ip: &str, dest_ip: &str, dest_port: i64, protocol: &str, bytes_sent: i64, bytes_recv: i64, ended_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE connection_logs SET bytes_sent = ?5, bytes_recv = ?6, ended_at = ?7
             WHERE rowid = (SELECT rowid FROM connection_logs WHERE device_ip = ?1 AND dest_ip = ?2 AND dest_port = ?3 AND protocol = ?4 AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1)",
            (device_ip, dest_ip, dest_port, protocol, bytes_sent, bytes_recv, ended_at),
        )?;
        Ok(())
    }

    pub fn list_connection_logs(&self, device_ip: Option<&str>, limit: i64, offset: i64) -> Result<Vec<ConnectionLog>> {
        if let Some(ip) = device_ip {
            let mut stmt = self.conn.prepare(
                "SELECT id, device_ip, dest_ip, dest_port, protocol, bytes_sent, bytes_recv, started_at, ended_at
                 FROM connection_logs WHERE device_ip = ?1 ORDER BY started_at DESC LIMIT ?2 OFFSET ?3"
            )?;
            let rows = stmt.query_map(rusqlite::params![ip, limit, offset], |row| {
                Ok(ConnectionLog {
                    id: row.get(0)?, device_ip: row.get(1)?, dest_ip: row.get(2)?,
                    dest_port: row.get(3)?, protocol: row.get(4)?, bytes_sent: row.get(5)?,
                    bytes_recv: row.get(6)?, started_at: row.get(7)?, ended_at: row.get(8)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, device_ip, dest_ip, dest_port, protocol, bytes_sent, bytes_recv, started_at, ended_at
                 FROM connection_logs ORDER BY started_at DESC LIMIT ?1 OFFSET ?2"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit, offset], |row| {
                Ok(ConnectionLog {
                    id: row.get(0)?, device_ip: row.get(1)?, dest_ip: row.get(2)?,
                    dest_port: row.get(3)?, protocol: row.get(4)?, bytes_sent: row.get(5)?,
                    bytes_recv: row.get(6)?, started_at: row.get(7)?, ended_at: row.get(8)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        }
    }

    // DNS log methods

    pub fn insert_dns_log(&self, device_ip: &str, domain: &str, query_type: &str, ts: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO dns_logs (device_ip, domain, query_type, ts) VALUES (?1, ?2, ?3, ?4)",
            (device_ip, domain, query_type, ts),
        )?;
        Ok(())
    }

    pub fn list_dns_logs(&self, device_ip: Option<&str>, limit: i64, offset: i64) -> Result<Vec<DnsLogEntry>> {
        if let Some(ip) = device_ip {
            let mut stmt = self.conn.prepare(
                "SELECT id, device_ip, domain, query_type, ts FROM dns_logs WHERE device_ip = ?1 ORDER BY ts DESC LIMIT ?2 OFFSET ?3"
            )?;
            let rows = stmt.query_map(rusqlite::params![ip, limit, offset], |row| {
                Ok(DnsLogEntry {
                    id: row.get(0)?, device_ip: row.get(1)?, domain: row.get(2)?,
                    query_type: row.get(3)?, ts: row.get(4)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, device_ip, domain, query_type, ts FROM dns_logs ORDER BY ts DESC LIMIT ?1 OFFSET ?2"
            )?;
            let rows = stmt.query_map(rusqlite::params![limit, offset], |row| {
                Ok(DnsLogEntry {
                    id: row.get(0)?, device_ip: row.get(1)?, domain: row.get(2)?,
                    query_type: row.get(3)?, ts: row.get(4)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        }
    }

    // IPv6 pinhole methods

    pub fn add_ipv6_pinhole(&self, mac: &str, protocol: &str, port_start: i64, port_end: i64, description: &str) -> Result<i64> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO ipv6_pinholes (device_mac, protocol, port_start, port_end, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![mac, protocol, port_start, port_end, description, ts],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_ipv6_pinhole(&self, id: i64) -> Result<bool> {
        let rows = self.conn.execute("DELETE FROM ipv6_pinholes WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }

    pub fn list_ipv6_pinholes(&self) -> Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.device_mac, p.protocol, p.port_start, p.port_end, p.description, p.created_at, d.hostname, d.ipv6_global
             FROM ipv6_pinholes p LEFT JOIN devices d ON p.device_mac = d.mac"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "device_mac": row.get::<_, String>(1)?,
                "protocol": row.get::<_, String>(2)?,
                "port_start": row.get::<_, i64>(3)?,
                "port_end": row.get::<_, i64>(4)?,
                "description": row.get::<_, Option<String>>(5)?,
                "created_at": row.get::<_, i64>(6)?,
                "device_name": row.get::<_, Option<String>>(7)?,
                "device_ipv6_global": row.get::<_, Option<String>>(8)?,
            }))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn get_ipv6_pinhole(&self, id: i64) -> Result<Option<(String, String, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_mac, protocol, port_start, port_end FROM ipv6_pinholes WHERE id = ?1"
        )?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            Ok(Some((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            )))
        } else {
            Ok(None)
        }
    }

    // Log rotation

    pub fn rotate_logs(&self, retention_secs: i64) -> Result<(usize, usize)> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - retention_secs;
        let conn_deleted = self.conn.execute(
            "DELETE FROM connection_logs WHERE ended_at IS NOT NULL AND ended_at < ?1",
            [cutoff],
        )?;
        let conn_stale = self.conn.execute(
            "DELETE FROM connection_logs WHERE ended_at IS NULL AND started_at < ?1",
            [cutoff],
        )?;
        let dns_deleted = self.conn.execute(
            "DELETE FROM dns_logs WHERE ts < ?1",
            [cutoff],
        )?;
        Ok((conn_deleted + conn_stale, dns_deleted))
    }
}

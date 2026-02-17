use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

/// Hard limit from 10.0.0.0/8 address space: 4,194,240 /30 subnets.
/// Practical bottlenecks before hitting this:
/// - Counter polling: main loop dumps full nft sets per device every 10s.
///   Fix: single dump parsed once, or nft get element for individual lookups.
/// - Restart restore: list_assigned_devices is a full table scan, each device
///   re-adds a gateway IP + verdict map element + counter set element.
/// - ARP table: thousands of /30 gateway IPs on one interface.
const MAX_DEVICES: i64 = 4_194_240;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
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
"#;

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub device_group: String,
    pub subnet_id: Option<i64>,
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

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap())?;
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn update_counters(&self, ip: &str, rx_bytes: i64, tx_bytes: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET rx_bytes = ?1, tx_bytes = ?2 WHERE ip = ?3",
            (rx_bytes, tx_bytes, ip),
        )?;
        Ok(())
    }

    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ip, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id FROM devices"
        )?;
        let devices = stmt.query_map([], |row| {
            Ok(Device {
                mac: row.get(0)?,
                ip: row.get(1)?,
                hostname: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                rx_bytes: row.get(5)?,
                tx_bytes: row.get(6)?,
                device_group: row.get(7)?,
                subnet_id: row.get(8)?,
            })
        })?;
        Ok(devices.filter_map(|d| d.ok()).collect())
    }

    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ip, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id FROM devices WHERE mac = ?1"
        )?;
        let mut rows = stmt.query([mac])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Device {
                mac: row.get(0)?,
                ip: row.get(1)?,
                hostname: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                rx_bytes: row.get(5)?,
                tx_bytes: row.get(6)?,
                device_group: row.get(7)?,
                subnet_id: row.get(8)?,
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
    pub fn insert_new_device(&self, mac: &str, subnet_id: i64, ip: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT OR IGNORE INTO devices (mac, ip, first_seen, last_seen, device_group, subnet_id)
             VALUES (?1, ?2, ?3, ?3, 'quarantine', ?4)",
            (mac, ip, now, subnet_id),
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
            "SELECT mac, ip, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id FROM devices WHERE subnet_id IS NOT NULL"
        )?;
        let devices = stmt.query_map([], |row| {
            Ok(Device {
                mac: row.get(0)?,
                ip: row.get(1)?,
                hostname: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                rx_bytes: row.get(5)?,
                tx_bytes: row.get(6)?,
                device_group: row.get(7)?,
                subnet_id: row.get(8)?,
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
}

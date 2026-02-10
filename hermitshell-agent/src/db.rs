use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0
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

    pub fn upsert_device(&self, mac: &str, ip: Option<&str>, hostname: Option<&str>) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO devices (mac, ip, hostname, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(mac) DO UPDATE SET
                ip = ?2,
                hostname = ?3,
                last_seen = ?4",
            (mac, ip, hostname, now),
        )?;
        Ok(())
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
            "SELECT mac, ip, hostname, first_seen, last_seen, rx_bytes, tx_bytes FROM devices"
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
            })
        })?;
        Ok(devices.filter_map(|d| d.ok()).collect())
    }

    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ip, hostname, first_seen, last_seen, rx_bytes, tx_bytes FROM devices WHERE mac = ?1"
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
            }))
        } else {
            Ok(None)
        }
    }
}

use anyhow::Result;
use rusqlite::Connection;

pub use hermitshell_common::{
    Alert, AuditEntry, BandwidthPoint, BandwidthRealtime, ConnectionLog, Device,
    DhcpReservation, DnsBlocklist, DnsCustomRule, DnsForwardZone, DnsLogEntry,
    PortForward, TopDestination, WgPeer, WifiAp, WifiClient,
};

/// Practical bottlenecks before hitting address space limits:
/// - Counter polling: main loop dumps full nft sets per device every 10s.
///   Fix: single dump parsed once, or nft get element for individual lookups.
/// - Restart restore: list_assigned_devices is a full table scan, each device
///   re-adds a /32 route + verdict map element + counter set element.
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
INSERT OR IGNORE INTO config (key, value) VALUES ('lan_ip', '10.0.0.1');
INSERT OR IGNORE INTO config (key, value) VALUES ('lan_ip_v6', 'fd00::1');
INSERT OR IGNORE INTO config (key, value) VALUES ('device_ipv4_base', '10.0.0.0/8');

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

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS dns_forward_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    forward_addr TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dns_custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL DEFAULT 'A',
    value TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dns_blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    tag TEXT NOT NULL DEFAULT 'ads',
    enabled INTEGER NOT NULL DEFAULT 1
);

INSERT OR IGNORE INTO dns_blocklists (name, url, tag) VALUES ('StevenBlack Hosts', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'ads');
"#;

fn device_from_row(row: &rusqlite::Row) -> rusqlite::Result<Device> {
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
        nickname: row.get(16)?,
        wifi_ssid: row.get(17)?,
        wifi_band: row.get(18)?,
        wifi_rssi: row.get(19)?,
        wifi_ap_mac: row.get(20)?,
        wifi_last_seen: row.get(21)?,
        dhcp_fingerprint: row.get(22)?,
    })
}

/// SQLite database holding device state, config, WireGuard peers, and logs.
pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Self::run_migrations(&conn)?;
        Ok(Self { conn })
    }

    fn run_migrations(conn: &Connection) -> Result<()> {
        // Get current schema version (0 if never set)
        let version: i64 = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'schema_version'",
                [],
                |row| {
                    let v: String = row.get(0)?;
                    Ok(v.parse::<i64>().unwrap_or(0))
                },
            )
            .unwrap_or(0);

        if version < 1 {
            // Baseline: absorb all existing ad-hoc migrations
            // These are idempotent so safe to re-run on existing DBs
            for col in &[
                "runzero_os TEXT",
                "runzero_hw TEXT",
                "runzero_device_type TEXT",
                "runzero_manufacturer TEXT",
                "runzero_last_sync INTEGER",
                "nickname TEXT",
            ] {
                let _ = conn.execute_batch(&format!("ALTER TABLE devices ADD COLUMN {col}"));
            }
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
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '1')
                 ON CONFLICT(key) DO UPDATE SET value = '1'",
                [],
            )?;
        }

        if version < 2 {
            for col in &[
                "wifi_ssid TEXT",
                "wifi_band TEXT",
                "wifi_rssi INTEGER",
                "wifi_ap_mac TEXT",
                "wifi_last_seen INTEGER",
            ] {
                let _ = conn.execute_batch(&format!("ALTER TABLE devices ADD COLUMN {col}"));
            }
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS wifi_aps (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'eap_standalone',
                    model TEXT,
                    firmware TEXT,
                    username TEXT NOT NULL,
                    password_enc TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_seen INTEGER,
                    status TEXT NOT NULL DEFAULT 'unknown'
                );
                CREATE TABLE IF NOT EXISTS wifi_ssid_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ap_mac TEXT NOT NULL,
                    ssid_name TEXT NOT NULL,
                    band TEXT NOT NULL,
                    password_enc TEXT,
                    vlan_id INTEGER,
                    hidden INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    security TEXT NOT NULL DEFAULT 'wpa2_wpa3'
                );"
            )?;
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '2')
                 ON CONFLICT(key) DO UPDATE SET value = '2'",
                [],
            )?;
        }

        if version < 3 {
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '3')
                 ON CONFLICT(key) DO UPDATE SET value = '3'",
                [],
            )?;
        }

        if version < 4 {
            let _ = conn.execute_batch("ALTER TABLE wifi_aps ADD COLUMN ca_cert_pem TEXT");
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '4')
                 ON CONFLICT(key) DO UPDATE SET value = '4'",
                [],
            )?;
        }

        if version < 5 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS bandwidth_hourly (
                    device_mac TEXT NOT NULL,
                    hour_bucket INTEGER NOT NULL,
                    rx_bytes INTEGER NOT NULL DEFAULT 0,
                    tx_bytes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (device_mac, hour_bucket)
                );
                CREATE TABLE IF NOT EXISTS bandwidth_daily (
                    device_mac TEXT NOT NULL,
                    day_bucket INTEGER NOT NULL,
                    rx_bytes INTEGER NOT NULL DEFAULT 0,
                    tx_bytes INTEGER NOT NULL DEFAULT 0,
                    top_destinations TEXT,
                    PRIMARY KEY (device_mac, day_bucket)
                );
                CREATE INDEX IF NOT EXISTS idx_bw_hourly_bucket ON bandwidth_hourly(hour_bucket);
                CREATE INDEX IF NOT EXISTS idx_bw_daily_bucket ON bandwidth_daily(day_bucket);"
            )?;
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '5')
                 ON CONFLICT(key) DO UPDATE SET value = '5'",
                [],
            )?;
        }

        if version < 6 {
            let _ = conn.execute_batch(
                "ALTER TABLE port_forwards ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
                 ALTER TABLE port_forwards ADD COLUMN expires_at INTEGER;
                 ALTER TABLE port_forwards ADD COLUMN requesting_ip TEXT;"
            );
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '6')
                 ON CONFLICT(key) DO UPDATE SET value = '6'",
                [],
            )?;
        }

        if version < 7 {
            let _ = conn.execute_batch("ALTER TABLE devices ADD COLUMN dhcp_fingerprint TEXT");
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '7')
                 ON CONFLICT(key) DO UPDATE SET value = '7'",
                [],
            )?;
        }

        if version < 8 {
            // Create wifi_providers table
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS wifi_providers (
                    id TEXT PRIMARY KEY,
                    provider_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_enc TEXT NOT NULL,
                    site TEXT,
                    api_key_enc TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'unknown',
                    last_seen INTEGER,
                    ca_cert_pem TEXT
                );"
            )?;

            // Migrate existing wifi_aps to new schema:
            // 1. Create a provider for each existing AP
            // 2. Rebuild wifi_aps with provider_id FK
            let has_old_table: bool = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='wifi_aps'",
                [], |row| row.get::<_, i64>(0),
            ).unwrap_or(0) > 0;

            if has_old_table {
                // Check if old schema has username column (old schema)
                let has_username: bool = conn.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('wifi_aps') WHERE name='username'",
                    [], |row| row.get::<_, i64>(0),
                ).unwrap_or(0) > 0;

                if has_username {
                    let mut stmt = conn.prepare(
                        "SELECT mac, ip, name, provider, username, password_enc, model, firmware, enabled, last_seen, status, ca_cert_pem FROM wifi_aps"
                    )?;
                    #[allow(clippy::type_complexity)]
                    let old_aps: Vec<(String, String, String, String, String, String, Option<String>, Option<String>, i64, Option<i64>, String, Option<String>)> = stmt.query_map([], |row| {
                        Ok((
                            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                            row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                            row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?,
                        ))
                    })?.filter_map(|r| r.ok()).collect();

                    conn.execute_batch("DROP TABLE IF EXISTS wifi_aps")?;
                    conn.execute_batch(
                        "CREATE TABLE wifi_aps (
                            mac TEXT PRIMARY KEY,
                            provider_id TEXT NOT NULL REFERENCES wifi_providers(id),
                            ip TEXT,
                            name TEXT,
                            model TEXT,
                            firmware TEXT,
                            status TEXT NOT NULL DEFAULT 'unknown',
                            last_seen INTEGER
                        );"
                    )?;

                    for (mac, ip, name, provider_type, username, password_enc, model, firmware, enabled, last_seen, status, ca_cert_pem) in &old_aps {
                        let provider_id = uuid::Uuid::new_v4().to_string();
                        conn.execute(
                            "INSERT INTO wifi_providers (id, provider_type, name, url, username, password_enc, enabled, last_seen, status, ca_cert_pem) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                            rusqlite::params![provider_id, provider_type, name, ip, username, password_enc, enabled, last_seen, status, ca_cert_pem],
                        )?;
                        conn.execute(
                            "INSERT INTO wifi_aps (mac, provider_id, ip, name, model, firmware, status, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            rusqlite::params![mac, provider_id, ip, name, model, firmware, status, last_seen],
                        )?;
                    }
                } else {
                    // Already new schema — just ensure table exists
                    conn.execute_batch("DROP TABLE IF EXISTS wifi_aps")?;
                    conn.execute_batch(
                        "CREATE TABLE wifi_aps (
                            mac TEXT PRIMARY KEY,
                            provider_id TEXT NOT NULL REFERENCES wifi_providers(id),
                            ip TEXT,
                            name TEXT,
                            model TEXT,
                            firmware TEXT,
                            status TEXT NOT NULL DEFAULT 'unknown',
                            last_seen INTEGER
                        );"
                    )?;
                }
            } else {
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS wifi_aps (
                        mac TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL REFERENCES wifi_providers(id),
                        ip TEXT,
                        name TEXT,
                        model TEXT,
                        firmware TEXT,
                        status TEXT NOT NULL DEFAULT 'unknown',
                        last_seen INTEGER
                    );"
                )?;
            }

            conn.execute_batch("DROP TABLE IF EXISTS wifi_ssid_configs")?;

            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '8')
                 ON CONFLICT(key) DO UPDATE SET value = '8'",
                [],
            )?;
        }

        if version < 9 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dns_forward_zones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    forward_addr TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS dns_custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL DEFAULT 'A',
                    value TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS dns_blocklists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    tag TEXT NOT NULL DEFAULT 'ads',
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                INSERT OR IGNORE INTO dns_blocklists (name, url, tag) VALUES ('StevenBlack Hosts', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'ads');"
            )?;
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('schema_version', '9')
                 ON CONFLICT(key) DO UPDATE SET value = '9'",
                [],
            )?;
        }

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
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync, nickname, wifi_ssid, wifi_band, wifi_rssi, wifi_ap_mac, wifi_last_seen, dhcp_fingerprint FROM devices"
        )?;
        let devices = stmt.query_map([], device_from_row)?;
        Ok(devices.filter_map(|d| d.ok()).collect())
    }

    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync, nickname, wifi_ssid, wifi_band, wifi_rssi, wifi_ap_mac, wifi_last_seen, dhcp_fingerprint FROM devices WHERE mac = ?1"
        )?;
        let mut rows = stmt.query([mac])?;
        if let Some(row) = rows.next()? {
            Ok(Some(device_from_row(row)?))
        } else {
            Ok(None)
        }
    }

    /// Allocate next subnet_id atomically: read current value, increment, return old value.
    /// `max_devices` is derived from the configured device IP range capacity.
    pub fn allocate_subnet_id(&self, max_devices: i64) -> Result<i64> {
        let id: i64 = self.conn.query_row(
            "SELECT value FROM config WHERE key = 'next_subnet_id'",
            [],
            |row| row.get::<_, String>(0),
        )?.parse()?;
        if id >= max_devices {
            anyhow::bail!("device limit reached ({} max)", max_devices);
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

    pub fn get_config_bool(&self, key: &str, default: bool) -> bool {
        self.get_config(key)
            .ok()
            .flatten()
            .map(|v| v == "true")
            .unwrap_or(default)
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
            "SELECT mac, ipv4, ipv6_ula, ipv6_global, hostname, first_seen, last_seen, rx_bytes, tx_bytes, device_group, subnet_id, runzero_os, runzero_hw, runzero_device_type, runzero_manufacturer, runzero_last_sync, nickname, wifi_ssid, wifi_band, wifi_rssi, wifi_ap_mac, wifi_last_seen, dhcp_fingerprint FROM devices WHERE subnet_id IS NOT NULL"
        )?;
        let devices = stmt.query_map([], device_from_row)?;
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

    pub fn set_wg_peer_enabled(&self, public_key: &str, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE wg_peers SET enabled = ?1 WHERE public_key = ?2",
            (if enabled { 1i64 } else { 0i64 }, public_key),
        )?;
        Ok(())
    }

    // Port forwarding methods

    pub fn list_port_forwards(&self) -> Result<Vec<PortForward>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, protocol, external_port_start, external_port_end, internal_ip, internal_port, enabled, description, source, expires_at, requesting_ip FROM port_forwards"
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
                source: row.get::<_, String>(8).unwrap_or_else(|_| "manual".into()),
                expires_at: row.get(9)?,
                requesting_ip: row.get(10)?,
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
            "SELECT id, protocol, external_port_start, external_port_end, internal_ip, internal_port, enabled, description, source, expires_at, requesting_ip FROM port_forwards WHERE enabled = 1"
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
                source: row.get::<_, String>(8).unwrap_or_else(|_| "manual".into()),
                expires_at: row.get(9)?,
                requesting_ip: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Insert a port forward with source, expires_at, and requesting_ip fields.
    #[allow(clippy::too_many_arguments)]
    pub fn add_port_forward_ext(
        &self, protocol: &str, ext_start: u16, ext_end: u16,
        internal_ip: &str, internal_port: u16, description: &str,
        source: &str, expires_at: Option<i64>, requesting_ip: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO port_forwards (protocol, external_port_start, external_port_end, internal_ip, internal_port, description, source, expires_at, requesting_ip) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![protocol, ext_start, ext_end, internal_ip, internal_port, description, source, expires_at, requesting_ip],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Delete all automatic (non-manual) port forwards, returning the count deleted.
    pub fn delete_automatic_port_forwards(&self) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM port_forwards WHERE source != 'manual'",
            [],
        )?;
        Ok(deleted)
    }

    /// Delete all automatic port forwards for a specific protocol and requesting IP.
    pub fn remove_auto_port_forwards_by_source(&self, protocol: &str, requesting_ip: &str) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM port_forwards WHERE source != 'manual' AND protocol = ?1 AND requesting_ip = ?2",
            rusqlite::params![protocol, requesting_ip],
        )?;
        Ok(deleted)
    }

    /// Delete expired port forwards (where expires_at <= now_unix), returning the count deleted.
    pub fn delete_expired_port_forwards(&self, now_unix: i64) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM port_forwards WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now_unix],
        )?;
        Ok(deleted)
    }

    /// Count automatic (non-manual) port forwards for a specific requesting IP.
    pub fn count_port_forwards_by_ip(&self, ip: &str) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM port_forwards WHERE requesting_ip = ?1 AND source != 'manual'",
            [ip],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Count all automatic (non-manual) port forwards.
    pub fn count_automatic_port_forwards(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM port_forwards WHERE source != 'manual'",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Find a port forward matching the given protocol and external port.
    /// Handles "both" protocol overlap: a "both" forward matches tcp/udp queries and vice versa.
    pub fn find_port_forward(&self, protocol: &str, ext_port: u16) -> Result<Option<PortForward>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, protocol, external_port_start, external_port_end, internal_ip, internal_port, enabled, description, source, expires_at, requesting_ip
             FROM port_forwards
             WHERE (protocol = ?1 OR protocol = 'both' OR ?1 = 'both')
               AND external_port_start <= ?2
               AND external_port_end >= ?2"
        )?;
        let mut rows = stmt.query(rusqlite::params![protocol, ext_port])?;
        if let Some(row) = rows.next()? {
            Ok(Some(PortForward {
                id: row.get(0)?,
                protocol: row.get(1)?,
                external_port_start: row.get(2)?,
                external_port_end: row.get(3)?,
                internal_ip: row.get(4)?,
                internal_port: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                description: row.get(7)?,
                source: row.get::<_, String>(8).unwrap_or_else(|_| "manual".into()),
                expires_at: row.get(9)?,
                requesting_ip: row.get(10)?,
            }))
        } else {
            Ok(None)
        }
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

    pub fn set_device_dhcp_fingerprint(&self, mac: &str, fingerprint: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET dhcp_fingerprint = ?1 WHERE mac = ?2",
            (fingerprint, mac),
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

    pub fn backup_path() -> String {
        crate::paths::backup_path()
    }

    pub fn vacuum_into_backup(&self) -> Result<()> {
        let path = Self::backup_path();
        self.conn.execute(&format!("VACUUM INTO '{}'", path), [])?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
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

    #[allow(clippy::too_many_arguments)]
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

    // Alert methods

    pub fn insert_alert(&self, device_mac: &str, rule: &str, severity: &str, message: &str, details: Option<&str>) -> Result<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO alerts (device_mac, rule, severity, message, details, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (device_mac, rule, severity, message, details, now),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn has_recent_alert(&self, device_mac: &str, rule: &str, cooldown_secs: i64) -> Result<bool> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - cooldown_secs;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE device_mac = ?1 AND rule = ?2 AND created_at > ?3",
            (device_mac, rule, cutoff),
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_alerts(&self, device_mac: Option<&str>, rule: Option<&str>, severity: Option<&str>, acknowledged: Option<bool>, limit: i64, offset: i64) -> Result<Vec<Alert>> {
        let mut sql = String::from("SELECT id, device_mac, rule, severity, message, details, created_at, acknowledged FROM alerts WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(mac) = device_mac {
            sql.push_str(&format!(" AND device_mac = ?{idx}"));
            params.push(Box::new(mac.to_string()));
            idx += 1;
        }
        if let Some(r) = rule {
            sql.push_str(&format!(" AND rule = ?{idx}"));
            params.push(Box::new(r.to_string()));
            idx += 1;
        }
        if let Some(s) = severity {
            sql.push_str(&format!(" AND severity = ?{idx}"));
            params.push(Box::new(s.to_string()));
            idx += 1;
        }
        if let Some(ack) = acknowledged {
            sql.push_str(&format!(" AND acknowledged = ?{idx}"));
            params.push(Box::new(ack as i32));
            idx += 1;
        }

        sql.push_str(&format!(" ORDER BY created_at DESC LIMIT ?{idx} OFFSET ?{}", idx + 1));
        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let alerts = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(Alert {
                id: row.get(0)?,
                device_mac: row.get(1)?,
                rule: row.get(2)?,
                severity: row.get(3)?,
                message: row.get(4)?,
                details: row.get(5)?,
                created_at: row.get(6)?,
                acknowledged: row.get::<_, i32>(7)? != 0,
            })
        })?;
        Ok(alerts.filter_map(|a| a.ok()).collect())
    }

    pub fn get_alert(&self, id: i64) -> Result<Option<Alert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_mac, rule, severity, message, details, created_at, acknowledged FROM alerts WHERE id = ?1"
        )?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Alert {
                id: row.get(0)?,
                device_mac: row.get(1)?,
                rule: row.get(2)?,
                severity: row.get(3)?,
                message: row.get(4)?,
                details: row.get(5)?,
                created_at: row.get(6)?,
                acknowledged: row.get::<_, i32>(7)? != 0,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn acknowledge_alert(&self, id: i64) -> Result<bool> {
        let updated = self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?1",
            [id],
        )?;
        Ok(updated > 0)
    }

    pub fn acknowledge_all_alerts(&self, device_mac: Option<&str>) -> Result<usize> {
        if let Some(mac) = device_mac {
            Ok(self.conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE device_mac = ?1 AND acknowledged = 0",
                [mac],
            )?)
        } else {
            Ok(self.conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0",
                [],
            )?)
        }
    }

    pub fn alert_counts_by_severity(&self) -> Result<(i64, i64, i64)> {
        let high: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'high' AND acknowledged = 0", [], |r| r.get(0)
        )?;
        let medium: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'medium' AND acknowledged = 0", [], |r| r.get(0)
        )?;
        let low: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'low' AND acknowledged = 0", [], |r| r.get(0)
        )?;
        Ok((high, medium, low))
    }

    // Baseline methods

    pub fn upsert_baseline(&self, mac: &str, metric: &str, avg: f64, stddev: f64) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO device_baselines (mac, metric, window_avg, window_stddev, last_computed)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(mac, metric) DO UPDATE SET window_avg = ?3, window_stddev = ?4, last_computed = ?5",
            rusqlite::params![mac, metric, avg, stddev, now],
        )?;
        Ok(())
    }

    pub fn get_baseline(&self, mac: &str, metric: &str) -> Result<Option<(f64, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT window_avg, window_stddev FROM device_baselines WHERE mac = ?1 AND metric = ?2"
        )?;
        let mut rows = stmt.query(rusqlite::params![mac, metric])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    // Aggregate queries for analysis

    pub fn count_unique_dns_domains_hourly(&self, device_ip: &str, hours_back: i64) -> Result<Vec<(i64, i64)>> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - (hours_back * 3600);
        let mut stmt = self.conn.prepare(
            "SELECT (ts / 3600) AS hour_bucket, COUNT(DISTINCT domain)
             FROM dns_logs WHERE device_ip = ?1 AND ts >= ?2
             GROUP BY hour_bucket ORDER BY hour_bucket"
        )?;
        let rows = stmt.query_map(rusqlite::params![device_ip, cutoff], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn count_unique_dest_ips_hourly(&self, device_ip: &str, hours_back: i64) -> Result<Vec<(i64, i64)>> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - (hours_back * 3600);
        let mut stmt = self.conn.prepare(
            "SELECT (started_at / 3600) AS hour_bucket, COUNT(DISTINCT dest_ip)
             FROM connection_logs WHERE device_ip = ?1 AND started_at >= ?2
             GROUP BY hour_bucket ORDER BY hour_bucket"
        )?;
        let rows = stmt.query_map(rusqlite::params![device_ip, cutoff], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_dns_beaconing_candidates(&self, device_ip: &str, min_queries: i64) -> Result<Vec<(String, Vec<i64>)>> {
        let one_hour_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - 3600;
        let mut stmt = self.conn.prepare(
            "SELECT domain FROM dns_logs
             WHERE device_ip = ?1 AND ts >= ?2
             GROUP BY domain HAVING COUNT(*) >= ?3"
        )?;
        let domains: Vec<String> = stmt.query_map(rusqlite::params![device_ip, one_hour_ago, min_queries], |row| {
            row.get(0)
        })?.filter_map(|r| r.ok()).collect();

        let mut results = Vec::new();
        for domain in domains {
            let mut ts_stmt = self.conn.prepare(
                "SELECT ts FROM dns_logs WHERE device_ip = ?1 AND domain = ?2 AND ts >= ?3 ORDER BY ts"
            )?;
            let timestamps: Vec<i64> = ts_stmt.query_map(rusqlite::params![device_ip, &domain, one_hour_ago], |row| {
                row.get(0)
            })?.filter_map(|r| r.ok()).collect();
            results.push((domain, timestamps));
        }
        Ok(results)
    }

    pub fn get_suspicious_port_connections(&self, device_ip: &str) -> Result<Vec<(String, i64, String)>> {
        let one_hour_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - 3600;
        let mut stmt = self.conn.prepare(
            "SELECT dest_ip, dest_port, protocol FROM connection_logs
             WHERE device_ip = ?1 AND started_at >= ?2
             AND (dest_port IN (23, 445, 3389, 5900) OR (dest_port > 49152 AND dest_ip LIKE '10.%'))"
        )?;
        let rows = stmt.query_map(rusqlite::params![device_ip, one_hour_ago], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_device_tx_bytes_hourly(&self, device_ip: &str, hours_back: i64) -> Result<Vec<(i64, i64)>> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - (hours_back * 3600);
        let mut stmt = self.conn.prepare(
            "SELECT (started_at / 3600) AS hour_bucket, SUM(bytes_sent)
             FROM connection_logs WHERE device_ip = ?1 AND started_at >= ?2
             GROUP BY hour_bucket ORDER BY hour_bucket"
        )?;
        let rows = stmt.query_map(rusqlite::params![device_ip, cutoff], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Roll up connection_logs into bandwidth_hourly for a specific hour bucket.
    /// hour_bucket is a Unix epoch truncated to hour (epoch / 3600 * 3600).
    pub fn rollup_bandwidth_hourly(&self, hour_bucket: i64) -> Result<usize> {
        let hour_end = hour_bucket + 3600;
        let inserted = self.conn.execute(
            "INSERT OR REPLACE INTO bandwidth_hourly (device_mac, hour_bucket, rx_bytes, tx_bytes)
             SELECT d.mac, ?1,
                    COALESCE(SUM(c.bytes_recv), 0),
                    COALESCE(SUM(c.bytes_sent), 0)
             FROM connection_logs c
             JOIN devices d ON d.ipv4 = c.device_ip
             WHERE c.started_at >= ?1 AND c.started_at < ?2
             GROUP BY d.mac",
            rusqlite::params![hour_bucket, hour_end],
        )?;
        Ok(inserted)
    }

    /// Roll up bandwidth_hourly into bandwidth_daily for a specific day bucket.
    /// day_bucket is a Unix epoch truncated to day (epoch / 86400 * 86400).
    pub fn rollup_bandwidth_daily(&self, day_bucket: i64) -> Result<usize> {
        let day_end = day_bucket + 86400;
        // First, aggregate hourly data into daily
        let inserted = self.conn.execute(
            "INSERT OR REPLACE INTO bandwidth_daily (device_mac, day_bucket, rx_bytes, tx_bytes)
             SELECT device_mac, ?1,
                    COALESCE(SUM(rx_bytes), 0),
                    COALESCE(SUM(tx_bytes), 0)
             FROM bandwidth_hourly
             WHERE hour_bucket >= ?1 AND hour_bucket < ?2
             GROUP BY device_mac",
            rusqlite::params![day_bucket, day_end],
        )?;
        // Then, compute top destinations per device from connection_logs
        let mut stmt = self.conn.prepare(
            "SELECT device_mac FROM bandwidth_daily WHERE day_bucket = ?1"
        )?;
        let macs: Vec<String> = stmt.query_map([day_bucket], |row| row.get(0))?
            .filter_map(|r| r.ok()).collect();
        for mac in &macs {
            let ip: Option<String> = self.conn.query_row(
                "SELECT ipv4 FROM devices WHERE mac = ?1", [mac], |row| row.get(0)
            ).ok();
            if let Some(ip) = ip {
                let mut dest_stmt = self.conn.prepare(
                    "SELECT dest_ip, dest_port, SUM(bytes_sent + bytes_recv) as total
                     FROM connection_logs
                     WHERE device_ip = ?1 AND started_at >= ?2 AND started_at < ?3
                     GROUP BY dest_ip, dest_port
                     ORDER BY total DESC LIMIT 5"
                )?;
                let tops: Vec<serde_json::Value> = dest_stmt.query_map(
                    rusqlite::params![ip, day_bucket, day_end], |row| {
                        Ok(serde_json::json!({
                            "dest_ip": row.get::<_, String>(0)?,
                            "dest_port": row.get::<_, u16>(1)?,
                            "total_bytes": row.get::<_, i64>(2)?,
                        }))
                    }
                )?.filter_map(|r| r.ok()).collect();
                let json = serde_json::to_string(&tops).unwrap_or_default();
                self.conn.execute(
                    "UPDATE bandwidth_daily SET top_destinations = ?1 WHERE device_mac = ?2 AND day_bucket = ?3",
                    rusqlite::params![json, mac, day_bucket],
                )?;
            }
        }
        Ok(inserted)
    }

    const MAX_ROLLUP_HOURS: usize = 168; // Process at most 1 week of hours per call
    const MAX_ROLLUP_DAYS: usize = 7; // Process at most 7 days per call

    /// Run rollup for all un-rolled hours up to the previous completed hour.
    pub fn rollup_all_pending(&self) -> Result<(usize, usize)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let current_hour = now / 3600 * 3600;
        // Find the earliest un-rolled hour (from connection_logs)
        let earliest: Option<i64> = self.conn.query_row(
            "SELECT MIN(started_at) FROM connection_logs WHERE started_at > 0",
            [], |row| row.get(0),
        ).ok();
        let Some(earliest) = earliest else { return Ok((0, 0)); };
        let start_hour = earliest / 3600 * 3600;
        let mut hourly_count = 0;
        let mut daily_count = 0;
        let mut hour = start_hour;
        let mut hours_processed = 0;
        while hour < current_hour && hours_processed < Self::MAX_ROLLUP_HOURS {
            // Check if this hour already rolled up
            let exists: bool = self.conn.query_row(
                "SELECT COUNT(*) > 0 FROM bandwidth_hourly WHERE hour_bucket = ?1",
                [hour], |row| row.get(0),
            ).unwrap_or(false);
            if !exists {
                hourly_count += self.rollup_bandwidth_hourly(hour)?;
            }
            hour += 3600;
            hours_processed += 1;
        }
        // Roll up daily for any completed days
        let current_day = now / 86400 * 86400;
        let start_day = start_hour / 86400 * 86400;
        let mut day = start_day;
        let mut days_processed = 0;
        while day < current_day && days_processed < Self::MAX_ROLLUP_DAYS {
            let exists: bool = self.conn.query_row(
                "SELECT COUNT(*) > 0 FROM bandwidth_daily WHERE day_bucket = ?1",
                [day], |row| row.get(0),
            ).unwrap_or(false);
            if !exists {
                daily_count += self.rollup_bandwidth_daily(day)?;
            }
            day += 86400;
            days_processed += 1;
        }
        Ok((hourly_count, daily_count))
    }

    /// Clean up old rollup data: hourly > 30 days, daily > 1 year.
    pub fn rotate_bandwidth_rollups(&self) -> Result<(usize, usize)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let hourly_cutoff = now - 30 * 86400;
        let daily_cutoff = now - 365 * 86400;
        let hourly_deleted = self.conn.execute(
            "DELETE FROM bandwidth_hourly WHERE hour_bucket < ?1", [hourly_cutoff]
        )?;
        let daily_deleted = self.conn.execute(
            "DELETE FROM bandwidth_daily WHERE day_bucket < ?1", [daily_cutoff]
        )?;
        Ok((hourly_deleted, daily_deleted))
    }

    /// Get bandwidth history for a device (or all devices if mac is None).
    /// period: "24h", "7d" → hourly buckets; "30d", "1y" → daily buckets.
    pub fn get_bandwidth_history(&self, device_mac: Option<&str>, period: &str) -> Result<Vec<BandwidthPoint>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        match period {
            "24h" | "7d" => {
                let hours_back = if period == "24h" { 24 } else { 168 };
                let cutoff = now - hours_back * 3600;
                let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = if let Some(mac) = device_mac {
                    (
                        "SELECT hour_bucket, SUM(rx_bytes), SUM(tx_bytes) FROM bandwidth_hourly WHERE device_mac = ?1 AND hour_bucket >= ?2 GROUP BY hour_bucket ORDER BY hour_bucket".to_string(),
                        vec![Box::new(mac.to_string()), Box::new(cutoff)],
                    )
                } else {
                    (
                        "SELECT hour_bucket, SUM(rx_bytes), SUM(tx_bytes) FROM bandwidth_hourly WHERE hour_bucket >= ?1 GROUP BY hour_bucket ORDER BY hour_bucket".to_string(),
                        vec![Box::new(cutoff)],
                    )
                };
                let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = self.conn.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(BandwidthPoint {
                        bucket: row.get(0)?,
                        rx_bytes: row.get(1)?,
                        tx_bytes: row.get(2)?,
                    })
                })?;
                Ok(rows.filter_map(|r| r.ok()).collect())
            }
            "30d" | "1y" => {
                let days_back = if period == "30d" { 30 } else { 365 };
                let cutoff = now - days_back * 86400;
                let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = if let Some(mac) = device_mac {
                    (
                        "SELECT day_bucket, SUM(rx_bytes), SUM(tx_bytes) FROM bandwidth_daily WHERE device_mac = ?1 AND day_bucket >= ?2 GROUP BY day_bucket ORDER BY day_bucket".to_string(),
                        vec![Box::new(mac.to_string()), Box::new(cutoff)],
                    )
                } else {
                    (
                        "SELECT day_bucket, SUM(rx_bytes), SUM(tx_bytes) FROM bandwidth_daily WHERE day_bucket >= ?1 GROUP BY day_bucket ORDER BY day_bucket".to_string(),
                        vec![Box::new(cutoff)],
                    )
                };
                let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
                let mut stmt = self.conn.prepare(&sql)?;
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    Ok(BandwidthPoint {
                        bucket: row.get(0)?,
                        rx_bytes: row.get(1)?,
                        tx_bytes: row.get(2)?,
                    })
                })?;
                Ok(rows.filter_map(|r| r.ok()).collect())
            }
            _ => anyhow::bail!("invalid period: {}", period),
        }
    }

    /// Get top destinations for a device in a time period.
    pub fn get_top_destinations(&self, device_mac: &str, period: &str, limit: i64) -> Result<Vec<TopDestination>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let ip: Option<String> = self.conn.query_row(
            "SELECT ipv4 FROM devices WHERE mac = ?1", [device_mac], |row| row.get(0)
        ).ok();
        let Some(ip) = ip else { return Ok(vec![]); };
        let hours_back = match period {
            "24h" => 24,
            "7d" => 168,
            "30d" => 720,
            "1y" => 8760,
            _ => 24,
        };
        let cutoff = now - hours_back * 3600;
        let mut stmt = self.conn.prepare(
            "SELECT dest_ip, dest_port, SUM(bytes_sent + bytes_recv) as total
             FROM connection_logs
             WHERE device_ip = ?1 AND started_at >= ?2
             GROUP BY dest_ip, dest_port
             ORDER BY total DESC LIMIT ?3"
        )?;
        let rows = stmt.query_map(rusqlite::params![ip, cutoff, limit], |row| {
            Ok(TopDestination {
                dest_ip: row.get(0)?,
                dest_port: row.get(1)?,
                total_bytes: row.get(2)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn rotate_alerts(&self, retention_secs: i64) -> Result<usize> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - retention_secs;
        Ok(self.conn.execute("DELETE FROM alerts WHERE created_at < ?1", [cutoff])?)
    }

    pub fn log_audit(&self, action: &str, detail: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        self.conn.execute(
            "INSERT INTO audit_log (action, detail, created_at) VALUES (?1, ?2, ?3)",
            (action, detail, now),
        )?;
        Ok(())
    }

    pub fn list_audit_logs(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, action, detail, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?1"
        )?;
        let entries = stmt.query_map([limit], |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                action: row.get(1)?,
                detail: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        Ok(entries)
    }

    pub fn set_device_nickname(&self, mac: &str, nickname: &str) -> Result<()> {
        if nickname.len() > 64 {
            anyhow::bail!("nickname too long (max 64 characters)");
        }
        let val = if nickname.is_empty() { None } else { Some(nickname) };
        self.conn.execute(
            "UPDATE devices SET nickname = ?1 WHERE mac = ?2",
            (val, mac),
        )?;
        Ok(())
    }

    // WiFi AP methods (new provider-based schema)

    pub fn list_wifi_aps(&self) -> Result<Vec<hermitshell_common::WifiAp>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.mac, COALESCE(a.ip, ''), COALESCE(a.name, ''), p.provider_type,
                    a.model, a.firmware, p.enabled, a.last_seen, a.status,
                    p.ca_cert_pem IS NOT NULL, a.provider_id
             FROM wifi_aps a JOIN wifi_providers p ON a.provider_id = p.id"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(hermitshell_common::WifiAp {
                mac: row.get(0)?,
                ip: row.get(1)?,
                name: row.get(2)?,
                provider: row.get(3)?,
                model: row.get(4)?,
                firmware: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
                last_seen: row.get(7)?,
                status: row.get(8)?,
                has_ca_cert: row.get::<_, bool>(9).unwrap_or(false),
                provider_id: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn update_device_wifi(&self, mac: &str, ssid: Option<&str>, band: Option<&str>, rssi: Option<i32>, ap_mac: Option<&str>) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "UPDATE devices SET wifi_ssid = ?1, wifi_band = ?2, wifi_rssi = ?3, wifi_ap_mac = ?4, wifi_last_seen = ?5 WHERE mac = ?6",
            rusqlite::params![ssid, band, rssi, ap_mac, now, mac],
        )?;
        Ok(())
    }

    // WiFi Provider methods

    pub fn list_wifi_providers(&self) -> Result<Vec<hermitshell_common::WifiProviderInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.provider_type, p.name, p.url, p.enabled, p.status, p.last_seen, p.ca_cert_pem,
                    (SELECT COUNT(*) FROM wifi_aps WHERE provider_id = p.id) as ap_count
             FROM wifi_providers p"
        )?;
        let rows = stmt.query_map([], |row| {
            let ca_cert: Option<String> = row.get(7)?;
            Ok(hermitshell_common::WifiProviderInfo {
                id: row.get(0)?,
                provider_type: row.get(1)?,
                name: row.get(2)?,
                url: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                status: row.get(5)?,
                last_seen: row.get(6)?,
                ap_count: row.get::<_, u32>(8).unwrap_or(0),
                has_ca_cert: ca_cert.is_some(),
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_wifi_provider(&self, id: &str) -> Result<Option<hermitshell_common::WifiProviderInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.provider_type, p.name, p.url, p.enabled, p.status, p.last_seen, p.ca_cert_pem,
                    (SELECT COUNT(*) FROM wifi_aps WHERE provider_id = p.id) as ap_count
             FROM wifi_providers p WHERE p.id = ?1"
        )?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            let ca_cert: Option<String> = row.get(7)?;
            Ok(Some(hermitshell_common::WifiProviderInfo {
                id: row.get(0)?,
                provider_type: row.get(1)?,
                name: row.get(2)?,
                url: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                status: row.get(5)?,
                last_seen: row.get(6)?,
                ap_count: row.get::<_, u32>(8).unwrap_or(0),
                has_ca_cert: ca_cert.is_some(),
            }))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_wifi_provider(&self, id: &str, provider_type: &str, name: &str, url: &str, username: &str, password_enc: &str, site: Option<&str>, api_key_enc: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO wifi_providers (id, provider_type, name, url, username, password_enc, site, api_key_enc) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![id, provider_type, name, url, username, password_enc, site, api_key_enc],
        )?;
        Ok(())
    }

    pub fn remove_wifi_provider(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM wifi_aps WHERE provider_id = ?1", [id])?;
        self.conn.execute("DELETE FROM wifi_providers WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Returns (provider_type, url, username, password_enc, site, api_key_enc)
    #[allow(clippy::type_complexity)]
    pub fn get_wifi_provider_credentials(&self, id: &str) -> Result<Option<(String, String, String, String, Option<String>, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider_type, url, username, password_enc, site, api_key_enc FROM wifi_providers WHERE id = ?1"
        )?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)))
        } else {
            Ok(None)
        }
    }

    pub fn get_wifi_provider_ca_cert(&self, id: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT ca_cert_pem FROM wifi_providers WHERE id = ?1")?;
        let mut rows = stmt.query([id])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(None)
        }
    }

    pub fn set_wifi_provider_ca_cert(&self, id: &str, ca_cert_pem: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE wifi_providers SET ca_cert_pem = ?1 WHERE id = ?2",
            rusqlite::params![ca_cert_pem, id],
        )?;
        Ok(())
    }

    pub fn update_wifi_provider_status(&self, id: &str, status: &str, last_seen: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE wifi_providers SET status = ?1, last_seen = ?2 WHERE id = ?3",
            (status, last_seen, id),
        )?;
        Ok(())
    }

    pub fn sync_wifi_aps(&self, provider_id: &str, devices: &[hermitshell_common::WifiDeviceInfo]) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        for dev in devices {
            self.conn.execute(
                "INSERT INTO wifi_aps (mac, provider_id, ip, name, model, firmware, status, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(mac) DO UPDATE SET
                    ip = ?3, name = ?4, model = ?5, firmware = ?6, status = ?7, last_seen = ?8",
                rusqlite::params![
                    dev.mac, provider_id, dev.ip, dev.name,
                    dev.model, dev.firmware, dev.status, now
                ],
            )?;
        }

        // Mark APs not in the device list as offline
        let macs: Vec<&str> = devices.iter().map(|d| d.mac.as_str()).collect();
        if macs.is_empty() {
            self.conn.execute(
                "UPDATE wifi_aps SET status = 'offline' WHERE provider_id = ?1",
                [provider_id],
            )?;
        } else {
            let placeholders: String = macs.iter().enumerate()
                .map(|(i, _)| format!("?{}", i + 2))
                .collect::<Vec<_>>().join(",");
            let sql = format!(
                "UPDATE wifi_aps SET status = 'offline' WHERE provider_id = ?1 AND mac NOT IN ({})",
                placeholders
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(provider_id.to_string())];
            for mac in &macs {
                params.push(Box::new(mac.to_string()));
            }
            stmt.execute(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())))?;
        }

        Ok(())
    }

    pub fn get_wifi_ap_provider_id(&self, mac: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT provider_id FROM wifi_aps WHERE mac = ?1")?;
        let mut rows = stmt.query([mac])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// For eap_standalone providers, insert the initial AP record when adding the provider.
    pub fn insert_wifi_ap_for_provider(&self, mac: &str, provider_id: &str, ip: &str, name: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wifi_aps (mac, provider_id, ip, name, status) VALUES (?1, ?2, ?3, ?4, 'unknown')",
            rusqlite::params![mac, provider_id, ip, name],
        )?;
        Ok(())
    }

    pub fn encrypt_wifi_provider_passwords(&self, session_secret: &str) -> Result<()> {
        let mut stmt = self.conn.prepare("SELECT id, password_enc, api_key_enc FROM wifi_providers")?;
        let rows: Vec<(String, String, Option<String>)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.filter_map(|r| r.ok()).collect();

        for (id, password_enc, api_key_enc) in rows {
            if !crate::crypto::is_encrypted(&password_enc) {
                let encrypted = crate::crypto::encrypt_password(&password_enc, session_secret)?;
                self.conn.execute(
                    "UPDATE wifi_providers SET password_enc = ?1 WHERE id = ?2",
                    (&encrypted, &id),
                )?;
            }
            if let Some(ref api_key) = api_key_enc
                && !api_key.is_empty() && !crate::crypto::is_encrypted(api_key) {
                    let encrypted = crate::crypto::encrypt_password(api_key, session_secret)?;
                    self.conn.execute(
                        "UPDATE wifi_providers SET api_key_enc = ?1 WHERE id = ?2",
                        (&encrypted, &id),
                    )?;
                }
        }
        Ok(())
    }

    // DNS forward zone methods

    pub fn list_dns_forward_zones(&self) -> Result<Vec<DnsForwardZone>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, domain, forward_addr, enabled FROM dns_forward_zones"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DnsForwardZone {
                id: row.get(0)?,
                domain: row.get(1)?,
                forward_addr: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn add_dns_forward_zone(&self, domain: &str, forward_addr: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO dns_forward_zones (domain, forward_addr) VALUES (?1, ?2)",
            (domain, forward_addr),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_dns_forward_zone(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM dns_forward_zones WHERE id = ?1", [id])?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_dns_forward_zone_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE dns_forward_zones SET enabled = ?1 WHERE id = ?2",
            (if enabled { 1 } else { 0 }, id),
        )?;
        Ok(())
    }

    // DNS custom rule methods

    pub fn list_dns_custom_rules(&self) -> Result<Vec<DnsCustomRule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, domain, record_type, value, enabled FROM dns_custom_rules"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DnsCustomRule {
                id: row.get(0)?,
                domain: row.get(1)?,
                record_type: row.get(2)?,
                value: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn add_dns_custom_rule(&self, domain: &str, record_type: &str, value: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO dns_custom_rules (domain, record_type, value) VALUES (?1, ?2, ?3)",
            (domain, record_type, value),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_dns_custom_rule(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM dns_custom_rules WHERE id = ?1", [id])?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_dns_custom_rule_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE dns_custom_rules SET enabled = ?1 WHERE id = ?2",
            (if enabled { 1 } else { 0 }, id),
        )?;
        Ok(())
    }

    // DNS blocklist methods

    pub fn list_dns_blocklists(&self) -> Result<Vec<DnsBlocklist>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, url, tag, enabled FROM dns_blocklists"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DnsBlocklist {
                id: row.get(0)?,
                name: row.get(1)?,
                url: row.get(2)?,
                tag: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn add_dns_blocklist(&self, name: &str, url: &str, tag: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO dns_blocklists (name, url, tag) VALUES (?1, ?2, ?3)",
            (name, url, tag),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn remove_dns_blocklist(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM dns_blocklists WHERE id = ?1", [id])?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_dns_blocklist_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE dns_blocklists SET enabled = ?1 WHERE id = ?2",
            (if enabled { 1 } else { 0 }, id),
        )?;
        Ok(())
    }
}

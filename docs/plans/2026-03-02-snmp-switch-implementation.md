# SNMP Switch Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace SSH-based switch management with SNMP v2c read-only MAC table polling. Remove ~1,100 LOC of fragile SSH/vendor code, add ~300 LOC of standard-MIB-based SNMP polling.

**Architecture:** Delete `switch/ssh.rs`, `switch/vendor.rs`, and rewrite `switch/mod.rs` + `socket/switch.rs` to use the `snmp2` crate for async SNMPv2c walks of standard BRIDGE-MIB and IF-MIB OIDs. Simplify DB schema from `switch_providers` (12 columns) to `snmp_switches` (7 columns). Simplify UI from SSH credential form to SNMP community string form.

**Tech Stack:** Rust, `snmp2` crate (async SNMPv2c), SQLite, Leptos 0.8 SSR

**Design doc:** `docs/plans/2026-03-02-snmp-switch-redesign.md`

---

### Task 1: Add `snmp2` dependency, remove `russh`

**Files:**
- Modify: `Cargo.toml` (workspace root, line 20)
- Modify: `hermitshell-agent/Cargo.toml` (line 21)

**Step 1: Replace dependency in workspace Cargo.toml**

In `Cargo.toml` line 20, replace:
```toml
russh = "0.57"
```
with:
```toml
snmp2 = "0.5"
```

In `hermitshell-agent/Cargo.toml` line 21, replace:
```toml
russh = { workspace = true }
```
with:
```toml
snmp2 = { workspace = true }
```

**Step 2: Verify it compiles (expect errors from switch module — that's fine)**

Run: `cargo check -p hermitshell-agent 2>&1 | head -5`
Expected: Errors about `russh` imports in `switch/ssh.rs` (confirms the dep swap worked)

**Step 3: Commit**

```bash
git add Cargo.toml hermitshell-agent/Cargo.toml
git commit -m "Replace russh dep with snmp2"
```

---

### Task 2: Delete SSH and vendor profile modules

**Files:**
- Delete: `hermitshell-agent/src/switch/ssh.rs`
- Delete: `hermitshell-agent/src/switch/vendor.rs`

**Step 1: Delete the files**

```bash
rm hermitshell-agent/src/switch/ssh.rs hermitshell-agent/src/switch/vendor.rs
```

**Step 2: Commit**

```bash
git add -u hermitshell-agent/src/switch/
git commit -m "Remove SSH and vendor profile modules"
```

---

### Task 3: Rewrite `switch/mod.rs` — SNMP types and polling

This is the core replacement. The new module drops the `SwitchProvider` trait
entirely and implements SNMP polling directly.

**Files:**
- Rewrite: `hermitshell-agent/src/switch/mod.rs`

**Step 1: Write the new module**

Replace the entire contents of `hermitshell-agent/src/switch/mod.rs` with:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use snmp2::{AsyncSession, Oid, Value};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::db::Db;

/// Standard OIDs for MAC table discovery (BRIDGE-MIB + IF-MIB).
const DOT1D_TP_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
const DOT1D_BASE_PORT_IFINDEX: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const IF_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

/// A discovered MAC-to-port mapping.
#[derive(Debug)]
struct MacEntry {
    mac: String,
    port_name: String,
}

/// Test connectivity by reading sysDescr.0.
pub async fn test_connectivity(host: &str, community: &[u8]) -> Result<String> {
    let addr: SocketAddr = format!("{}:161", host)
        .parse()
        .context("invalid SNMP host address")?;
    let oid = Oid::from(SYS_DESCR).context("invalid OID")?;
    let mut sess = AsyncSession::new_v2c(addr, community, 0)
        .await
        .context("SNMP session failed")?;
    let response = sess.get(&oid).await.context("SNMP GET sysDescr failed")?;
    for (_, val) in response.varbinds {
        if let Value::OctetString(bytes) = val {
            return Ok(String::from_utf8_lossy(&bytes).to_string());
        }
    }
    Ok("(no sysDescr)".to_string())
}

/// Walk the BRIDGE-MIB forwarding table and IF-MIB to map MACs to port names.
async fn poll_mac_table(host: &str, community: &[u8]) -> Result<Vec<MacEntry>> {
    let addr: SocketAddr = format!("{}:161", host)
        .parse()
        .context("invalid SNMP host address")?;

    let mut sess = AsyncSession::new_v2c(addr, community, 0)
        .await
        .context("SNMP session failed")?;

    // Step 1: Walk dot1dTpFdbPort to get MAC → bridge port number
    let fdb_oid = Oid::from(DOT1D_TP_FDB_PORT).context("invalid OID")?;
    let mut mac_to_bridge_port: Vec<(String, u32)> = Vec::new();
    let mut walk_oid = fdb_oid.clone();

    loop {
        let response = match sess.getnext(&walk_oid).await {
            Ok(r) => r,
            Err(_) => break,
        };
        let mut advanced = false;
        for (oid, val) in response.varbinds {
            // Check we're still under the dot1dTpFdbPort subtree
            let oid_parts = oid.as_parts();
            if oid_parts.len() <= DOT1D_TP_FDB_PORT.len()
                || &oid_parts[..DOT1D_TP_FDB_PORT.len()] != DOT1D_TP_FDB_PORT
            {
                break;
            }
            // The trailing 6 components of the OID are the MAC address bytes
            if oid_parts.len() >= DOT1D_TP_FDB_PORT.len() + 6 {
                let mac_bytes = &oid_parts[DOT1D_TP_FDB_PORT.len()..];
                let mac = format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac_bytes[0], mac_bytes[1], mac_bytes[2],
                    mac_bytes[3], mac_bytes[4], mac_bytes[5]
                );
                if let Value::Integer(port_num) = val {
                    mac_to_bridge_port.push((mac, port_num as u32));
                }
            }
            walk_oid = oid;
            advanced = true;
        }
        if !advanced {
            break;
        }
    }

    if mac_to_bridge_port.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Walk dot1dBasePortIfIndex to get bridge port → ifIndex
    let bp_oid = Oid::from(DOT1D_BASE_PORT_IFINDEX).context("invalid OID")?;
    let mut bridge_port_to_ifindex: HashMap<u32, u32> = HashMap::new();
    let mut walk_oid = bp_oid.clone();

    loop {
        let response = match sess.getnext(&walk_oid).await {
            Ok(r) => r,
            Err(_) => break,
        };
        let mut advanced = false;
        for (oid, val) in response.varbinds {
            let oid_parts = oid.as_parts();
            if oid_parts.len() <= DOT1D_BASE_PORT_IFINDEX.len()
                || &oid_parts[..DOT1D_BASE_PORT_IFINDEX.len()] != DOT1D_BASE_PORT_IFINDEX
            {
                break;
            }
            let bridge_port = oid_parts[DOT1D_BASE_PORT_IFINDEX.len()];
            if let Value::Integer(ifindex) = val {
                bridge_port_to_ifindex.insert(bridge_port, ifindex as u32);
            }
            walk_oid = oid;
            advanced = true;
        }
        if !advanced {
            break;
        }
    }

    // Step 3: Walk ifName to get ifIndex → port name
    let ifname_oid = Oid::from(IF_NAME).context("invalid OID")?;
    let mut ifindex_to_name: HashMap<u32, String> = HashMap::new();
    let mut walk_oid = ifname_oid.clone();

    loop {
        let response = match sess.getnext(&walk_oid).await {
            Ok(r) => r,
            Err(_) => break,
        };
        let mut advanced = false;
        for (oid, val) in response.varbinds {
            let oid_parts = oid.as_parts();
            if oid_parts.len() <= IF_NAME.len()
                || &oid_parts[..IF_NAME.len()] != IF_NAME
            {
                break;
            }
            let ifindex = oid_parts[IF_NAME.len()];
            if let Value::OctetString(bytes) = val {
                let name = String::from_utf8_lossy(&bytes).to_string();
                ifindex_to_name.insert(ifindex, name);
            }
            walk_oid = oid;
            advanced = true;
        }
        if !advanced {
            break;
        }
    }

    // Combine: MAC → bridge port → ifIndex → port name
    let entries = mac_to_bridge_port
        .into_iter()
        .filter_map(|(mac, bp)| {
            let ifindex = bridge_port_to_ifindex.get(&bp)?;
            let port_name = ifindex_to_name.get(ifindex)?;
            Some(MacEntry {
                mac,
                port_name: port_name.clone(),
            })
        })
        .collect();

    Ok(entries)
}

/// Background polling loop — queries switches via SNMP for MAC table data
/// and correlates entries with known devices.
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));

    loop {
        poll_interval.tick().await;

        // Skip if VLAN mode is not enabled
        let vlan_enabled = {
            let db = db.lock().unwrap();
            db.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled")
        };
        if !vlan_enabled {
            continue;
        }

        let switches = {
            let db = db.lock().unwrap();
            db.list_snmp_switches().unwrap_or_default()
        };

        for sw in &switches {
            if !sw.enabled {
                continue;
            }

            // Decrypt community string
            let community = {
                let db = db.lock().unwrap();
                match db.get_snmp_switch_community(&sw.id) {
                    Ok(enc) => {
                        let secret = db
                            .get_config("session_secret")
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        if secret.is_empty() || !crate::crypto::is_encrypted(&enc) {
                            enc
                        } else {
                            match crate::crypto::decrypt_password(&enc, &secret) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!(switch = %sw.name, error = %e, "failed to decrypt community");
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(switch = %sw.name, error = %e, "failed to get community");
                        continue;
                    }
                }
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            match poll_mac_table(&sw.host, community.as_bytes()).await {
                Ok(entries) => {
                    let db = db.lock().unwrap();
                    db.update_snmp_switch_status(&sw.id, "connected", now).ok();

                    for entry in &entries {
                        if let Ok(Some(_)) = db.get_device(&entry.mac) {
                            let port_display =
                                format!("{} on {}", entry.port_name, sw.name);
                            let _ =
                                db.update_device_switch_port(&entry.mac, &port_display);
                        }
                    }

                    info!(switch = %sw.name, mac_count = entries.len(), "SNMP poll complete");
                }
                Err(e) => {
                    warn!(switch = %sw.name, error = %e, "SNMP poll failed");
                    let db = db.lock().unwrap();
                    db.update_snmp_switch_status(&sw.id, "error", now).ok();
                }
            }
        }
    }
}
```

**Step 2: Verify it compiles (expect errors from missing DB methods — that's fine)**

Run: `cargo check -p hermitshell-agent 2>&1 | head -20`
Expected: Errors about `list_snmp_switches`, `get_snmp_switch_community`, etc. not existing yet

**Step 3: Commit**

```bash
git add hermitshell-agent/src/switch/mod.rs
git commit -m "Rewrite switch module with SNMP polling"
```

---

### Task 4: Update DB schema — new `snmp_switches` table, drop old tables

**Files:**
- Modify: `hermitshell-agent/src/db.rs`

**Step 1: Add migration version 12 for SNMP schema**

Find the end of the migration block (after the `version < 11` block at line ~561).
Add a new migration block:

```rust
if version < 12 {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS snmp_switches (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            community_enc TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'unknown',
            last_seen INTEGER NOT NULL DEFAULT 0
        );
        DROP TABLE IF EXISTS switch_providers;
        DROP TABLE IF EXISTS switch_vendor_profiles;"
    )?;
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('schema_version', '12')
         ON CONFLICT(key) DO UPDATE SET value = '12'",
        [],
    )?;
}
```

**Step 2: Replace all switch_provider DB methods with SNMP equivalents**

Find the section starting at line ~2096 (`// --- Switch provider CRUD ---`) and
replace all methods from `list_switch_providers` through `set_custom_vendor_profile`
with:

```rust
// --- SNMP switch CRUD ---

pub fn list_snmp_switches(&self) -> Result<Vec<SnmpSwitchInfo>> {
    let mut stmt = self.conn.prepare(
        "SELECT id, name, host, enabled, status, last_seen FROM snmp_switches"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SnmpSwitchInfo {
            id: row.get(0)?,
            name: row.get(1)?,
            host: row.get(2)?,
            enabled: row.get::<_, i32>(3)? != 0,
            status: row.get(4)?,
            last_seen: row.get(5)?,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn insert_snmp_switch(
    &self,
    id: &str,
    name: &str,
    host: &str,
    community_enc: &str,
) -> Result<()> {
    self.conn.execute(
        "INSERT INTO snmp_switches (id, name, host, community_enc)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, name, host, community_enc],
    )?;
    Ok(())
}

pub fn remove_snmp_switch(&self, id: &str) -> Result<()> {
    self.conn.execute("DELETE FROM snmp_switches WHERE id = ?1", [id])?;
    Ok(())
}

pub fn get_snmp_switch_community(&self, id: &str) -> Result<String> {
    Ok(self.conn.query_row(
        "SELECT community_enc FROM snmp_switches WHERE id = ?1",
        [id],
        |row| row.get(0),
    )?)
}

pub fn update_snmp_switch_status(&self, id: &str, status: &str, last_seen: i64) -> Result<()> {
    self.conn.execute(
        "UPDATE snmp_switches SET status = ?1, last_seen = ?2 WHERE id = ?3",
        rusqlite::params![status, last_seen, id],
    )?;
    Ok(())
}

pub fn update_device_switch_port(&self, mac: &str, port_display: &str) -> Result<()> {
    self.conn.execute(
        "UPDATE devices SET switch_port = ?1 WHERE mac = ?2",
        rusqlite::params![port_display, mac],
    )?;
    Ok(())
}
```

**Step 3: Add `SnmpSwitchInfo` struct**

Add near the top of `db.rs` (or wherever `SwitchProviderInfo` was referenced):

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnmpSwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
}
```

**Step 4: Remove old DB methods**

Delete these methods from db.rs:
- `list_switch_providers`
- `insert_switch_provider`
- `remove_switch_provider`
- `get_switch_provider_credentials`
- `set_switch_provider_host_key`
- `update_switch_provider_status`
- `set_switch_uplink_port`
- `update_device_switch_info`
- `get_custom_vendor_profile`
- `set_custom_vendor_profile`

Also remove the `SwitchProviderInfo` import/usage if it came from `hermitshell_common`.

**Step 5: Update DB unit tests**

Replace the old switch tests (`test_switch_provider_crud`, `test_device_switch_info`,
`test_custom_vendor_profile`) with:

```rust
#[test]
fn test_snmp_switch_crud() {
    let db = test_db();
    db.insert_snmp_switch("sw1", "Main Switch", "192.168.1.100", "public").unwrap();
    let switches = db.list_snmp_switches().unwrap();
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].name, "Main Switch");
    assert_eq!(switches[0].host, "192.168.1.100");
    let community = db.get_snmp_switch_community("sw1").unwrap();
    assert_eq!(community, "public");
    db.update_snmp_switch_status("sw1", "connected", 1000).unwrap();
    let switches = db.list_snmp_switches().unwrap();
    assert_eq!(switches[0].status, "connected");
    db.remove_snmp_switch("sw1").unwrap();
    let switches = db.list_snmp_switches().unwrap();
    assert_eq!(switches.len(), 0);
}
```

**Step 6: Run DB unit tests**

Run: `cargo test -p hermitshell-agent -- db::tests`
Expected: PASS

**Step 7: Commit**

```bash
git add hermitshell-agent/src/db.rs
git commit -m "Replace switch DB schema with SNMP"
```

---

### Task 5: Rewrite socket handlers

**Files:**
- Rewrite: `hermitshell-agent/src/socket/switch.rs`
- Modify: `hermitshell-agent/src/socket/mod.rs` (lines 107-108, 429-431, 446-448, 584-587)

**Step 1: Rewrite socket/switch.rs**

Replace the entire contents with:

```rust
use std::sync::{Arc, Mutex};
use tracing::info;
use zeroize::Zeroizing;

use crate::db::Db;
use crate::switch;
use super::{Request, Response};

pub(super) fn handle_switch_add(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name) = req.name else {
        return Response::err("name required");
    };
    let Some(ref host) = req.key else {
        return Response::err("key required (host)");
    };
    let Some(ref community) = req.value else {
        return Response::err("value required (community string)");
    };

    if name.is_empty() || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Response::err("name must be 1-64 alphanumeric characters (plus - _ . space)");
    }
    if host.is_empty() {
        return Response::err("host cannot be empty");
    }
    if community.is_empty() {
        return Response::err("community string cannot be empty");
    }

    // Encrypt community string
    let session_secret = Zeroizing::new({
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    });
    let community_enc = if session_secret.is_empty() {
        community.clone()
    } else {
        match crate::crypto::encrypt_password(community, &session_secret) {
            Ok(enc) => enc,
            Err(e) => return Response::err(&format!("encryption failed: {}", e)),
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.insert_snmp_switch(&id, name, host, &community_enc) {
        return Response::err(&format!("failed to add switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_add", &format!("added SNMP switch {} ({})", name, host));

    info!(name = %name, host = %host, "SNMP switch added");
    Response::ok()
}

pub(super) fn handle_switch_remove(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required");
    };

    let db_guard = db.lock().unwrap();
    let id = match resolve_switch_id(name_or_id, &db_guard) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(e) = db_guard.remove_snmp_switch(&id) {
        return Response::err(&format!("failed to remove switch: {}", e));
    }
    let _ = db_guard.log_audit("switch_remove", &format!("removed SNMP switch {}", name_or_id));

    info!(id = %id, "SNMP switch removed");
    Response::ok()
}

pub(super) fn handle_switch_list(_req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let db_guard = db.lock().unwrap();
    match db_guard.list_snmp_switches() {
        Ok(switches) => {
            let json = match serde_json::to_string(&switches) {
                Ok(j) => j,
                Err(e) => return Response::err(&format!("serialization failed: {}", e)),
            };
            let mut resp = Response::ok();
            resp.config_value = Some(json);
            resp
        }
        Err(e) => Response::err(&format!("failed to list switches: {}", e)),
    }
}

pub(super) async fn handle_switch_test(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref name_or_id) = req.name else {
        return Response::err("name required");
    };

    let (id, host, community) = match get_switch_info(name_or_id, db) {
        Ok(info) => info,
        Err(resp) => return resp,
    };

    match switch::test_connectivity(&host, community.as_bytes()).await {
        Ok(sys_descr) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let db_guard = db.lock().unwrap();
            let _ = db_guard.update_snmp_switch_status(&id, "connected", now);

            info!(switch = %name_or_id, sys_descr = %sys_descr, "SNMP test successful");
            Response::ok()
        }
        Err(e) => Response::err(&format!("SNMP test failed: {}", e)),
    }
}

fn resolve_switch_id(name_or_id: &str, db: &Db) -> Result<String, Response> {
    let switches = db.list_snmp_switches().unwrap_or_default();
    if let Some(s) = switches.iter().find(|s| s.id == name_or_id) {
        return Ok(s.id.clone());
    }
    if let Some(s) = switches.iter().find(|s| s.name == name_or_id) {
        return Ok(s.id.clone());
    }
    Err(Response::err("switch not found"))
}

fn get_switch_info(
    name_or_id: &str,
    db: &Arc<Mutex<Db>>,
) -> Result<(String, String, String), Response> {
    let db_guard = db.lock().unwrap();
    let id = resolve_switch_id(name_or_id, &db_guard)?;

    let switches = db_guard.list_snmp_switches().unwrap_or_default();
    let sw = switches.iter().find(|s| s.id == id).unwrap();
    let host = sw.host.clone();

    let community_enc = db_guard
        .get_snmp_switch_community(&id)
        .map_err(|e| Response::err(&format!("failed to get community: {}", e)))?;

    drop(db_guard);

    let secret = {
        let db_guard = db.lock().unwrap();
        db_guard.get_config("session_secret").ok().flatten().unwrap_or_default()
    };
    let community = if secret.is_empty() || !crate::crypto::is_encrypted(&community_enc) {
        community_enc
    } else {
        crate::crypto::decrypt_password(&community_enc, &secret)
            .map_err(|e| Response::err(&format!("decrypt failed: {}", e)))?
    };

    Ok((id, host, community))
}
```

**Step 2: Update socket/mod.rs dispatcher**

In `socket/mod.rs`:

1. Line 107-108: Remove `"switch_set_uplink",` and `"switch_ports", "switch_provision_vlans",` from the PRIVILEGED_METHODS array. Keep `"switch_add", "switch_remove", "switch_list", "switch_test",`.

2. Lines 429-431: Replace the async match arm:
   ```rust
   "switch_test" | "switch_ports" | "switch_provision_vlans" => {
       switch::handle_switch_async(&req, &db).await
   }
   ```
   with:
   ```rust
   "switch_test" => {
       switch::handle_switch_test(&req, &db).await
   }
   ```

3. Lines 446-448: Same replacement as above (the other async dispatch site).

4. Lines 584-587: Replace the sync match arms:
   ```rust
   "switch_add" => switch::handle_switch_add(&req, db),
   "switch_remove" => switch::handle_switch_remove(&req, db),
   "switch_list" => switch::handle_switch_list(&req, db),
   "switch_set_uplink" => switch::handle_switch_set_uplink(&req, db),
   ```
   with:
   ```rust
   "switch_add" => switch::handle_switch_add(&req, db),
   "switch_remove" => switch::handle_switch_remove(&req, db),
   "switch_list" => switch::handle_switch_list(&req, db),
   ```

**Step 3: Verify the agent compiles**

Run: `cargo check -p hermitshell-agent`
Expected: Clean (no errors). The UI will still reference old types — that's next.

**Step 4: Commit**

```bash
git add hermitshell-agent/src/socket/switch.rs hermitshell-agent/src/socket/mod.rs
git commit -m "Rewrite switch socket handlers for SNMP"
```

---

### Task 6: Update `hermitshell-common` types

**Files:**
- Modify: `hermitshell-common/src/lib.rs`

**Step 1: Replace `SwitchProviderInfo` with `SnmpSwitchInfo`**

Find the `SwitchProviderInfo` struct (lines ~217-229) and replace with:

```rust
/// A registered SNMP switch for MAC table polling.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnmpSwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
}
```

**Step 2: Remove `switch_id` from Device struct**

Find `pub switch_id: Option<String>` (line ~62) and remove the field and its
`#[serde(default)]` annotation. Keep `switch_port`.

**Step 3: Fix any compilation errors in the agent**

The agent's `db.rs` also has a `SnmpSwitchInfo` struct from Task 4.
Decide: either use the one from `hermitshell-common` and delete the local one,
or keep the local one and don't export from common. Using common is cleaner —
replace the local struct in `db.rs` with `use hermitshell_common::SnmpSwitchInfo;`.

**Step 4: Remove `switch_id` from device query in db.rs**

Find the device row mapping (line ~181) that reads `switch_id: row.get(23)?`
and remove it. Adjust column indices if needed.

**Step 5: Compile check**

Run: `cargo check`
Expected: Agent compiles. UI may have errors — that's next.

**Step 6: Commit**

```bash
git add hermitshell-common/src/lib.rs hermitshell-agent/src/db.rs
git commit -m "Update common types for SNMP switches"
```

---

### Task 7: Update the UI

**Files:**
- Rewrite: `hermitshell-ui/src/pages/switch_settings.rs`
- Modify: `hermitshell-ui/src/client.rs` (lines 17-28, 865-892)
- Modify: `hermitshell-ui/src/server_fns.rs` (lines 866-896)
- Modify: `hermitshell-ui/src/pages/device_detail.rs` (lines 119-123)

**Step 1: Simplify `SwitchInfo` in client.rs**

Replace the struct at lines 17-28:

```rust
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct SwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
}
```

**Step 2: Simplify client functions**

Replace `add_switch` (lines 871-882) with:

```rust
pub fn add_switch(name: &str, host: &str, community: &str) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "switch_add",
        "name": name,
        "key": host,
        "value": community,
    }))?)?;
    Ok(())
}
```

Keep `remove_switch` and `test_switch` as-is (they already work with just `name`).
Keep `list_switches` as-is (it just deserializes the new struct shape).

**Step 3: Simplify server functions**

Replace `add_switch` server fn (lines 866-881):

```rust
#[server]
pub async fn add_switch(
    name: String,
    host: String,
    community: String,
) -> Result<(), ServerFnError> {
    crate::client::add_switch(&name, &host, &community)
        .map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("switch_add", &name);
    leptos_axum::redirect("/switches");
    Ok(())
}
```

Keep `remove_switch` and `test_switch` server fns as-is.

**Step 4: Rewrite switch_settings.rs**

Replace the entire file:

```rust
use leptos::prelude::*;
use crate::client;
use crate::components::layout::Layout;
use crate::components::toast::ErrorToast;
use crate::server_fns::{AddSwitch, RemoveSwitch, TestSwitch};

#[component]
pub fn SwitchSettings() -> impl IntoView {
    let switches = Resource::new(
        || (),
        |_| async { client::list_switches() },
    );

    view! {
        <Layout title="SNMP Switches" active_page="switches">
            <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                {move || switches.get().map(|result| match result {
                    Ok(list) => {
                        let add_action = ServerAction::<AddSwitch>::new();

                        view! {
                            <div class="settings-section">
                                <h3>"SNMP Switches"</h3>
                                <p class="settings-description">"Add managed switches for MAC-to-port discovery. Uses SNMP v2c read-only polling."</p>
                                {if list.is_empty() {
                                    view! { <p class="settings-empty">"No switches configured"</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Name"</th>
                                                    <th>"Host"</th>
                                                    <th>"Status"</th>
                                                    <th>"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {list.iter().map(|sw| {
                                                    let name_for_remove = sw.name.clone();
                                                    let name_for_test = sw.name.clone();
                                                    let remove_action = ServerAction::<RemoveSwitch>::new();
                                                    let test_action = ServerAction::<TestSwitch>::new();
                                                    let status_class = if sw.status == "connected" { "card-value success" } else { "card-value warning" };
                                                    view! {
                                                        <tr>
                                                            <td>{sw.name.clone()}</td>
                                                            <td>{sw.host.clone()}</td>
                                                            <td><span class={status_class}>{sw.status.clone()}</span></td>
                                                            <td>
                                                                <ActionForm action=test_action attr:style="display:inline">
                                                                    <input type="hidden" name="name" value={name_for_test} />
                                                                    <button type="submit" class="btn btn-sm">"Test"</button>
                                                                </ActionForm>
                                                                <ActionForm action=remove_action attr:style="display:inline">
                                                                    <input type="hidden" name="name" value={name_for_remove} />
                                                                    <button type="submit" class="btn btn-danger btn-sm">"Remove"</button>
                                                                </ActionForm>
                                                                <ErrorToast value=test_action.value() />
                                                                <ErrorToast value=remove_action.value() />
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_any()
                                }}

                                <h4>"Add Switch"</h4>
                                <ActionForm action=add_action attr:class="form-inline">
                                    <label>"Name"
                                        <input type="text" name="name" required />
                                    </label>
                                    <label>"Host"
                                        <input type="text" name="host" placeholder="192.168.1.100" required />
                                    </label>
                                    <label>"Community String"
                                        <input type="password" name="community" value="public" required />
                                    </label>
                                    <button type="submit" class="btn btn-primary">"Add"</button>
                                </ActionForm>
                                <ErrorToast value=add_action.value() />
                            </div>
                        }.into_any()
                    }
                    Err(e) => view! { <p class="error">{format!("Error: {}", e)}</p> }.into_any(),
                })}
            </Suspense>
        </Layout>
    }
}
```

**Step 5: Update device_detail.rs**

In `device_detail.rs` lines 119-123, the `switch_name` lookup currently uses
`d.switch_id` and `client::list_switches()`. Since `switch_id` is removed,
replace lines 119-123:

```rust
                                    let switch_name = d.switch_id.as_ref().and_then(|sid| {
                                        client::list_switches().ok().and_then(|switches| {
                                            switches.into_iter().find(|s| s.id == *sid).map(|s| s.name)
                                        })
                                    });
```

with nothing — remove those lines entirely, and remove the "Switch" detail item
(lines 136-139). The `switch_port` field now contains the full display string
(e.g., "Gi0/3 on Main Switch") so the "Switch Port" detail item at lines 140-143
is sufficient on its own.

**Step 6: Full compile check**

Run: `cargo check`
Expected: Clean compile

**Step 7: Commit**

```bash
git add hermitshell-ui/src/
git commit -m "Update UI for SNMP switch management"
```

---

### Task 8: Update integration test

**Files:**
- Modify: `tests/cases/55-switch-vlan-management.sh`

**Step 1: Rewrite test for SNMP API**

Replace the entire contents of the test file:

```bash
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 55: SNMP switch management API ==="

# --- Add an SNMP switch ---
ADD_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_add\",\"name\":\"test-switch\",\"key\":\"192.168.1.100\",\"value\":\"public\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$ADD_RESULT" '"ok":true' "switch_add accepted"

# --- List switches ---
LIST_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$LIST_RESULT" '"ok":true' "switch_list succeeds"
assert_match "$LIST_RESULT" "test-switch" "switch_list shows added switch"
assert_match "$LIST_RESULT" "192\.168\.1\.100" "switch_list shows host"

# --- Remove switch ---
REMOVE_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_remove\",\"name\":\"test-switch\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$REMOVE_RESULT" '"ok":true' "switch_remove succeeds"

# --- Verify removal ---
LIST_EMPTY=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$LIST_EMPTY" '"ok":true' "switch_list after remove succeeds"
if echo "$LIST_EMPTY" | grep -q "test-switch"; then
    echo -e "${RED}FAIL${NC}: switch still in list after remove"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: switch removed from list"
fi

echo "=== Test 55 complete ==="
```

**Step 2: Commit**

```bash
git add tests/cases/55-switch-vlan-management.sh
git commit -m "Update test 55 for SNMP switch API"
```

---

### Task 9: Clean up dead references and run full build

**Files:**
- Possibly: `hermitshell-agent/src/main.rs` (line 17, lines 837-841)
- Any remaining references to old types

**Step 1: Verify main.rs switch spawn still works**

The `switch::run(db_switch).await` call at line 840 should still compile because
`switch::run` has the same signature. Verify `mod switch;` at line 17 still works
(the module now only has `mod.rs`, no submodules).

**Step 2: Run cargo clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: Clean (or only pre-existing warnings unrelated to switch code)

**Step 3: Run all unit tests**

Run: `cargo test --workspace`
Expected: All pass

**Step 4: Run cargo build (release profile) to verify full build**

Run: `cargo build --release -p hermitshell-agent -p hermitshell-ui`
Expected: Clean build

**Step 5: Commit any remaining fixups**

```bash
git add -A && git commit -m "Clean up dead switch references"
```

---

### Task 10: Run integration tests

**Step 1: Run the full test suite**

Run: `bash tests/run.sh`
Expected: All tests pass including updated test 55

**Step 2: If tests fail, debug and fix**

Common issues:
- Schema migration: old `switch_providers` table may still exist in VM's SQLite DB.
  The `DROP TABLE IF EXISTS` in migration 12 handles this.
- Socket method names: if test 55 still references `switch_set_uplink`, it will fail.
  Verify the test was updated correctly.

**Step 3: Final commit if any fixes needed**

```bash
git add -A && git commit -m "Fix integration test issues"
```

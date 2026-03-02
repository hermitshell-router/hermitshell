# SNMPv3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add SNMPv3 authPriv support alongside existing v2c for switch MAC table polling.

**Architecture:** Extend `snmp_switches` table with v3 columns, branch on `version` field to create v2c or v3 SNMP sessions. UI gains version dropdown that shows/hides relevant credential fields.

**Tech Stack:** snmp2 (v3 already enabled via default `crypto-rust` feature), SQLite, Leptos 0.8 SSR

---

### Task 1: DB schema migration v13

**Files:**
- Modify: `hermitshell-agent/src/db.rs` (migration block ~line 562)

**Step 1: Write the failing test**

Add to `db.rs` tests:

```rust
#[test]
fn test_snmp_switch_v3_crud() {
    let db = test_db();
    db.insert_snmp_switch_v3(
        "sw1", "Main Switch", "192.168.1.100",
        "snmpuser", "sha256", "aes128",
        "authpass_enc", "privpass_enc",
    ).unwrap();
    let switches = db.list_snmp_switches().unwrap();
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].version, "3");
    assert_eq!(switches[0].v3_username.as_deref(), Some("snmpuser"));
    assert_eq!(switches[0].v3_auth_protocol.as_deref(), Some("sha256"));
    assert_eq!(switches[0].v3_cipher.as_deref(), Some("aes128"));
    let creds = db.get_snmp_switch_v3_credentials("sw1").unwrap();
    assert_eq!(creds.0, "authpass_enc");
    assert_eq!(creds.1, "privpass_enc");
    db.remove_snmp_switch("sw1").unwrap();
    assert!(db.list_snmp_switches().unwrap().is_empty());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent test_snmp_switch_v3_crud`
Expected: FAIL — `insert_snmp_switch_v3` method doesn't exist

**Step 3: Write the migration and DB methods**

In `db.rs` migration block, after `version < 12`:

```rust
if version < 13 {
    // ALTER TABLE can't add NOT NULL without default, so use DEFAULT
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN version TEXT NOT NULL DEFAULT '2c'", []);
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN v3_username TEXT", []);
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN v3_auth_protocol TEXT", []);
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN v3_cipher TEXT", []);
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN v3_auth_pass_enc TEXT", []);
    let _ = conn.execute("ALTER TABLE snmp_switches ADD COLUMN v3_priv_pass_enc TEXT", []);
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('schema_version', '13')
         ON CONFLICT(key) DO UPDATE SET value = '13'",
        [],
    )?;
}
```

Update `list_snmp_switches()` SELECT to include new columns, update `SnmpSwitchInfo` mapping.

Add `insert_snmp_switch_v3()` method:

```rust
pub fn insert_snmp_switch_v3(
    &self, id: &str, name: &str, host: &str,
    username: &str, auth_protocol: &str, cipher: &str,
    auth_pass_enc: &str, priv_pass_enc: &str,
) -> Result<()> {
    self.conn.execute(
        "INSERT INTO snmp_switches (id, name, host, community_enc, version,
         v3_username, v3_auth_protocol, v3_cipher, v3_auth_pass_enc, v3_priv_pass_enc)
         VALUES (?1, ?2, ?3, '', '3', ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![id, name, host, username, auth_protocol, cipher,
                          auth_pass_enc, priv_pass_enc],
    )?;
    Ok(())
}
```

Add `get_snmp_switch_v3_credentials()`:

```rust
pub fn get_snmp_switch_v3_credentials(&self, id: &str) -> Result<(String, String)> {
    Ok(self.conn.query_row(
        "SELECT v3_auth_pass_enc, v3_priv_pass_enc FROM snmp_switches WHERE id = ?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p hermitshell-agent test_snmp_switch_v3`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/db.rs
git commit -m "Add v13 schema migration for SNMPv3"
```

---

### Task 2: Update SnmpSwitchInfo common type

**Files:**
- Modify: `hermitshell-common/src/lib.rs` (`SnmpSwitchInfo` struct)

**Step 1: Add v3 fields to SnmpSwitchInfo**

```rust
pub struct SnmpSwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
    #[serde(default = "default_v2c")]
    pub version: String,
    pub v3_username: Option<String>,
    pub v3_auth_protocol: Option<String>,
    pub v3_cipher: Option<String>,
}

fn default_v2c() -> String { "2c".to_string() }
```

**Step 2: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS (may need to fix `list_snmp_switches` SELECT in db.rs)

**Step 3: Commit**

```bash
git add hermitshell-common/src/lib.rs
git commit -m "Add v3 fields to SnmpSwitchInfo"
```

---

### Task 3: Update switch/mod.rs for v3 sessions

**Files:**
- Modify: `hermitshell-agent/src/switch/mod.rs`

**Step 1: Add SnmpCredentials enum and session creation**

At top of file, add:

```rust
use snmp2::v3::{Auth, AuthProtocol, Cipher, Security};

pub enum SnmpCredentials {
    V2c { community: String },
    V3 {
        username: String,
        auth_protocol: String,
        cipher: String,
        auth_pass: String,
        priv_pass: String,
    },
}
```

Add helper functions:

```rust
fn parse_auth_protocol(s: &str) -> AuthProtocol {
    match s {
        "md5" => AuthProtocol::Md5,
        "sha1" => AuthProtocol::Sha1,
        "sha224" => AuthProtocol::Sha224,
        "sha384" => AuthProtocol::Sha384,
        "sha512" => AuthProtocol::Sha512,
        _ => AuthProtocol::Sha256, // default
    }
}

fn parse_cipher(s: &str) -> Cipher {
    match s {
        "des" => Cipher::Des,
        "aes192" => Cipher::Aes192,
        "aes256" => Cipher::Aes256,
        _ => Cipher::Aes128, // default
    }
}

async fn create_session(addr: &str, creds: &SnmpCredentials) -> Result<AsyncSession> {
    match creds {
        SnmpCredentials::V2c { community } => {
            AsyncSession::new_v2c(addr, community.as_bytes(), 0)
                .await.context("SNMP v2c session failed")
        }
        SnmpCredentials::V3 { username, auth_protocol, cipher, auth_pass, priv_pass } => {
            let security = Security::new(username.as_bytes(), auth_pass.as_bytes())
                .with_auth(Auth::AuthPriv {
                    cipher: parse_cipher(cipher),
                    privacy_password: priv_pass.as_bytes().to_vec(),
                })
                .with_auth_protocol(parse_auth_protocol(auth_protocol));
            AsyncSession::new_v3(addr, 0, security)
                .await.context("SNMP v3 session failed")
        }
    }
}
```

**Step 2: Update test_connectivity and poll_mac_table**

Change signatures from `(host, community)` to `(host, creds)`:

```rust
pub async fn test_connectivity(host: &str, creds: &SnmpCredentials) -> Result<String> {
    let addr = format!("{}:161", host);
    let oid = Oid::from(SYS_DESCR).map_err(|e| anyhow::anyhow!("invalid OID: {:?}", e))?;
    let mut sess = create_session(&addr, creds).await?;
    // ... rest unchanged
}

async fn poll_mac_table(host: &str, creds: &SnmpCredentials) -> Result<Vec<MacEntry>> {
    let addr = format!("{}:161", host);
    let mut sess = create_session(&addr, creds).await?;
    // ... rest unchanged (replace the old new_v2c call)
}
```

**Step 3: Update run() to build credentials from DB**

In `run()`, after reading switch info and decrypting, build `SnmpCredentials`:

```rust
let creds = if sw_version == "3" {
    // read v3 credentials from DB, decrypt auth_pass and priv_pass
    SnmpCredentials::V3 { username, auth_protocol, cipher, auth_pass, priv_pass }
} else {
    SnmpCredentials::V2c { community }
};
match poll_mac_table(&sw.host, &creds).await { ... }
```

The `run()` loop needs to read `version` from the switch info (already in `SnmpSwitchInfo` after Task 2) and fetch v3 credentials from DB when needed.

**Step 4: Verify compilation**

Run: `cargo check -p hermitshell-agent`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/switch/mod.rs
git commit -m "Support v3 sessions in switch poller"
```

---

### Task 4: Update socket handlers for v3

**Files:**
- Modify: `hermitshell-agent/src/socket/switch.rs`
- Modify: `hermitshell-agent/src/socket/mod.rs` (Request struct)

**Step 1: Add v3 fields to Request struct**

In `socket/mod.rs`, add to `Request`:

```rust
snmp_version: Option<String>,
v3_username: Option<String>,
v3_auth_protocol: Option<String>,
v3_cipher: Option<String>,
v3_auth_pass: Option<String>,
v3_priv_pass: Option<String>,
```

**Step 2: Update handle_switch_add for v3**

In `socket/switch.rs`, update `handle_switch_add()`:
- Check `req.snmp_version`. If `"3"`, require `v3_username`, `v3_auth_pass`, `v3_priv_pass`
- Default `v3_auth_protocol` to `"sha256"`, `v3_cipher` to `"aes128"`
- Encrypt auth_pass and priv_pass with session_secret
- Call `db.insert_snmp_switch_v3()`
- If version is `"2c"` (or absent), keep existing v2c path

**Step 3: Update handle_switch_test for v3**

Update `get_switch_info()` to return `SnmpCredentials` enum instead of plain community string. Update `handle_switch_test()` to pass creds to `switch::test_connectivity()`.

**Step 4: Verify compilation**

Run: `cargo check -p hermitshell-agent`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/socket/switch.rs hermitshell-agent/src/socket/mod.rs
git commit -m "Handle v3 credentials in switch socket API"
```

---

### Task 5: Update UI — client.rs and server_fns.rs

**Files:**
- Modify: `hermitshell-ui/src/client.rs` (`SwitchInfo`, `add_switch()`)
- Modify: `hermitshell-ui/src/server_fns.rs` (`add_switch`)

**Step 1: Update SwitchInfo struct**

```rust
pub struct SwitchInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
    #[serde(default)]
    pub version: String,
    pub v3_username: Option<String>,
    pub v3_auth_protocol: Option<String>,
    pub v3_cipher: Option<String>,
}
```

**Step 2: Update add_switch client function**

Add `add_switch_v3()`:

```rust
pub fn add_switch_v3(
    name: &str, host: &str,
    username: &str, auth_protocol: &str, cipher: &str,
    auth_pass: &str, priv_pass: &str,
) -> Result<(), String> {
    ok_or_err(send(json!({
        "method": "switch_add",
        "name": name,
        "key": host,
        "snmp_version": "3",
        "v3_username": username,
        "v3_auth_protocol": auth_protocol,
        "v3_cipher": cipher,
        "v3_auth_pass": auth_pass,
        "v3_priv_pass": priv_pass,
    }))?)?;
    Ok(())
}
```

**Step 3: Update add_switch server function**

Add v3 optional params to `add_switch`:

```rust
#[server]
pub async fn add_switch(
    name: String, host: String,
    community: Option<String>,
    snmp_version: Option<String>,
    v3_username: Option<String>,
    v3_auth_protocol: Option<String>,
    v3_cipher: Option<String>,
    v3_auth_pass: Option<String>,
    v3_priv_pass: Option<String>,
) -> Result<(), ServerFnError> {
    if snmp_version.as_deref() == Some("3") {
        let username = v3_username.ok_or(ServerFnError::new("username required"))?;
        let auth_pass = v3_auth_pass.ok_or(ServerFnError::new("auth password required"))?;
        let priv_pass = v3_priv_pass.ok_or(ServerFnError::new("privacy password required"))?;
        let auth_proto = v3_auth_protocol.unwrap_or_else(|| "sha256".to_string());
        let cipher = v3_cipher.unwrap_or_else(|| "aes128".to_string());
        crate::client::add_switch_v3(&name, &host, &username, &auth_proto, &cipher, &auth_pass, &priv_pass)
            .map_err(ServerFnError::new)?;
    } else {
        let community = community.ok_or(ServerFnError::new("community required"))?;
        crate::client::add_switch(&name, &host, &community)
            .map_err(ServerFnError::new)?;
    }
    let _ = crate::client::log_audit("switch_add", &name);
    leptos_axum::redirect("/switches");
    Ok(())
}
```

**Step 4: Verify compilation**

Run: `cargo check --workspace`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-ui/src/client.rs hermitshell-ui/src/server_fns.rs
git commit -m "Add v3 params to switch client and server fns"
```

---

### Task 6: Update UI — switch_settings.rs

**Files:**
- Modify: `hermitshell-ui/src/pages/switch_settings.rs`

**Step 1: Add version dropdown and conditional v3 fields**

The form needs:
1. SNMP Version `<select>` (v2c / v3)
2. When v2c: Community String field (existing)
3. When v3: Username, Auth Password, Privacy Password, Auth Protocol dropdown, Cipher dropdown
4. Switch table gains "Version" column

Since this is SSR-only (no WASM), use a `<select name="snmp_version">` and server-side validation handles which fields are required. Both sets of fields are always rendered in HTML but with `style="display:none"` toggled by a tiny inline `<script>` or just let the server ignore empty v3 fields for v2c and vice versa.

Better approach for SSR-only: render all fields, mark none as `required`, let the server fn validate based on version. This avoids needing JS.

Table: add `<th>"Version"</th>` and `<td>{sw.version.clone()}</td>`.

Update description text to mention "SNMP v2c/v3".

**Step 2: Verify compilation**

Run: `cargo check -p hermitshell-ui`
Expected: PASS

**Step 3: Commit**

```bash
git add hermitshell-ui/src/pages/switch_settings.rs
git commit -m "Add v3 fields to switch settings UI"
```

---

### Task 7: Update integration test

**Files:**
- Modify: `tests/cases/55-switch-vlan-management.sh`

**Step 1: Add v3 switch test**

After existing v2c tests, add:

```bash
# --- Add a v3 switch ---
V3_ADD=$(vm_sudo router "echo '{\"method\":\"switch_add\",\"name\":\"v3-switch\",\"key\":\"192.168.1.200\",\"snmp_version\":\"3\",\"v3_username\":\"snmpuser\",\"v3_auth_pass\":\"authpass123\",\"v3_priv_pass\":\"privpass123\",\"v3_auth_protocol\":\"sha256\",\"v3_cipher\":\"aes128\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$V3_ADD" '"ok":true' "v3 switch_add accepted"

# --- List shows v3 switch ---
V3_LIST=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$V3_LIST" "v3-switch" "switch_list shows v3 switch"
assert_match "$V3_LIST" '"version":"3"' "switch shows version 3"

# --- Remove v3 switch ---
V3_REMOVE=$(vm_sudo router 'echo "{\"method\":\"switch_remove\",\"name\":\"v3-switch\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$V3_REMOVE" '"ok":true' "v3 switch_remove succeeds"
```

**Step 2: Commit**

```bash
git add tests/cases/55-switch-vlan-management.sh
git commit -m "Add v3 assertions to switch integration test"
```

---

### Task 8: Verify everything compiles and unit tests pass

**Step 1: Run full check**

```bash
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Fix any issues.

**Step 2: Commit fixes if needed**

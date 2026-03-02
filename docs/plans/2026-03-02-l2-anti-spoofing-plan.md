# L2 Anti-Spoofing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add rogue DHCP blocking, per-trust-group VLAN segmentation, and managed switch integration via SSH to close L2 spoofing gaps.

**Architecture:** Three components shipped incrementally. Component 1 (nftables rules) is standalone and can ship immediately. Components 2 (VLAN subinterfaces + DHCP changes) and 3 (SSH switch management) are opt-in behind a `vlan_mode` config flag. The existing flat L2 + L3 isolation remains the default.

**Tech Stack:** Rust (async with tokio), nftables, `russh` crate for SSH, existing SQLite DB, Leptos 0.8 SSR web UI.

**Design doc:** `docs/plans/2026-03-02-l2-anti-spoofing-design.md`

---

## Component 1: Rogue DHCP Server Blocking

### Task 1: Add rogue DHCP blocking to nftables base ruleset

**Files:**
- Modify: `hermitshell-agent/src/nftables.rs:113-205` (forward chain in `build_base_ruleset`)

**Step 1: Write the failing test**

Add to the existing test module in `nftables.rs`:

```rust
#[test]
fn test_base_ruleset_blocks_rogue_dhcp() {
    let rules = build_base_ruleset("eth1", "eth2", "10.0.0.1");
    assert!(rules.contains("iifname \"eth2\" udp sport 67"), "missing rogue DHCP block rule");
    assert!(rules.contains("ROGUE_DHCP"), "missing rogue DHCP log prefix");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent test_base_ruleset_blocks_rogue_dhcp`
Expected: FAIL — the string isn't in the ruleset yet.

**Step 3: Add the rogue DHCP rules to `build_base_ruleset`**

In the `forward` chain block (after `ct state established,related accept`, before `ip saddr vmap`), add two lines:

```
        iifname "{lan_iface}" udp sport 67 log prefix "ROGUE_DHCP " limit rate 1/second
        iifname "{lan_iface}" udp sport 67 counter drop comment "block rogue DHCP server"
```

These must go in the **forward** chain (blocks rogue DHCP between LAN devices through the router) AND the **input** chain (blocks rogue DHCP targeting the router itself). In the input chain, add before the `iifname "{lan_iface}" udp dport 67 accept` line:

```
        iifname "{lan_iface}" udp sport 67 counter drop comment "block rogue DHCP server"
```

Note: we don't need the log line in input — the forward chain log covers cross-device spoofing which is the main threat.

**Step 4: Run test to verify it passes**

Run: `cargo test -p hermitshell-agent test_base_ruleset_blocks_rogue_dhcp`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/nftables.rs
git commit -m "Block rogue DHCP server traffic in nftables"
```

### Task 2: Integration test for rogue DHCP blocking

**Files:**
- Create: `tests/cases/53-rogue-dhcp-block.sh`

**Step 1: Write the integration test**

```bash
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 53: Rogue DHCP server blocking ==="

# Verify nftables forward chain contains the rogue DHCP drop rule
RULES=$(vm_sudo router 'nft list chain inet filter forward')
assert_match "$RULES" "udp sport 67.*drop" "forward chain blocks rogue DHCP (sport 67)"

# Verify nftables input chain also blocks rogue DHCP
RULES_INPUT=$(vm_sudo router 'nft list chain inet filter input')
assert_match "$RULES_INPUT" "udp sport 67.*drop" "input chain blocks rogue DHCP (sport 67)"

echo "=== Test 53 complete ==="
```

**Step 2: Run test to verify it passes**

Run: `bash tests/cases/53-rogue-dhcp-block.sh`
Expected: PASS (rules were added in Task 1 and applied on agent restart via `run.sh`)

**Step 3: Commit**

```bash
git add tests/cases/53-rogue-dhcp-block.sh
git commit -m "Add rogue DHCP blocking integration test"
```

---

## Component 2: VLAN Subinterface Management

### Task 3: Add VLAN configuration to the database schema

**Files:**
- Modify: `hermitshell-agent/src/db.rs` (schema migration + CRUD methods)

**Step 1: Design the schema migration**

Add a new migration version that creates the `vlan_config` table and adds a `vlan_id` column to the devices table:

```sql
CREATE TABLE IF NOT EXISTS vlan_config (
    group_name TEXT PRIMARY KEY,
    vlan_id INTEGER NOT NULL,
    subnet TEXT NOT NULL,
    gateway TEXT NOT NULL
);

-- Default VLAN mappings
INSERT OR IGNORE INTO vlan_config VALUES ('trusted', 10, '10.0.10.0/24', '10.0.10.1');
INSERT OR IGNORE INTO vlan_config VALUES ('iot', 20, '10.0.20.0/24', '10.0.20.1');
INSERT OR IGNORE INTO vlan_config VALUES ('guest', 30, '10.0.30.0/24', '10.0.30.1');
INSERT OR IGNORE INTO vlan_config VALUES ('servers', 40, '10.0.40.0/24', '10.0.40.1');
INSERT OR IGNORE INTO vlan_config VALUES ('quarantine', 50, '10.0.50.0/24', '10.0.50.1');
```

Add `vlan_mode` config key (default "disabled") to the config table.

**Step 2: Implement DB methods**

Add to `db.rs`:
- `get_vlan_config() -> Result<Vec<VlanGroupConfig>>` — returns all group-to-VLAN mappings
- `get_vlan_for_group(group: &str) -> Result<Option<VlanGroupConfig>>` — single group lookup
- `set_vlan_config(group: &str, vlan_id: u16, subnet: &str, gateway: &str) -> Result<()>` — upsert
- `is_vlan_mode_enabled() -> bool` — reads `vlan_mode` config key

Add struct to `hermitshell-common/src/lib.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanGroupConfig {
    pub group_name: String,
    pub vlan_id: u16,
    pub subnet: String,
    pub gateway: String,
}
```

**Step 3: Write unit tests for the DB methods**

Test in `db.rs` test module: create in-memory DB, run migration, verify defaults inserted, test CRUD.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent -- db::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/db.rs hermitshell-common/src/lib.rs
git commit -m "Add VLAN config schema and DB methods"
```

### Task 4: VLAN subinterface creation/teardown

**Files:**
- Create: `hermitshell-agent/src/vlan.rs`
- Modify: `hermitshell-agent/src/main.rs` (add `mod vlan` and call at startup)

**Step 1: Write the failing test**

In `vlan.rs`, test that `build_vlan_commands()` generates the right `ip link` commands:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_create_commands() {
        let configs = vec![
            VlanGroupConfig {
                group_name: "trusted".into(),
                vlan_id: 10,
                subnet: "10.0.10.0/24".into(),
                gateway: "10.0.10.1".into(),
            },
        ];
        let cmds = build_vlan_create_commands("eth2", &configs);
        assert_eq!(cmds.len(), 3); // link add, addr add, link set up
        assert!(cmds[0].contains("type vlan id 10"));
        assert!(cmds[1].contains("10.0.10.1/24"));
        assert!(cmds[2].contains("eth2.10 up"));
    }

    #[test]
    fn test_build_teardown_commands() {
        let cmds = build_vlan_teardown_commands("eth2", &[10, 20, 50]);
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains("del eth2.10"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent vlan::tests`
Expected: FAIL — module doesn't exist yet.

**Step 3: Implement `vlan.rs`**

```rust
use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

use crate::paths;
use hermitshell_common::VlanGroupConfig;

/// Build the `ip` commands needed to create VLAN subinterfaces.
pub fn build_vlan_create_commands(lan_iface: &str, configs: &[VlanGroupConfig]) -> Vec<String> {
    let mut cmds = Vec::new();
    for cfg in configs {
        let sub = format!("{}.{}", lan_iface, cfg.vlan_id);
        cmds.push(format!("link add link {} name {} type vlan id {}", lan_iface, sub, cfg.vlan_id));
        cmds.push(format!("addr add {}/24 dev {}", cfg.gateway, sub));
        cmds.push(format!("link set {} up", sub));
    }
    cmds
}

/// Build the `ip` commands needed to remove VLAN subinterfaces.
pub fn build_vlan_teardown_commands(lan_iface: &str, vlan_ids: &[u16]) -> Vec<String> {
    vlan_ids.iter()
        .map(|id| format!("link del {}.{}", lan_iface, id))
        .collect()
}

/// Create all VLAN subinterfaces on the LAN interface.
pub fn create_vlan_interfaces(lan_iface: &str, configs: &[VlanGroupConfig]) -> Result<()> {
    for cmd_args in build_vlan_create_commands(lan_iface, configs) {
        let args: Vec<&str> = cmd_args.split_whitespace().collect();
        let status = Command::new(paths::ip()).args(&args).status()?;
        if !status.success() {
            warn!(cmd = %cmd_args, "ip command failed (may already exist)");
        }
    }
    info!(count = configs.len(), "created VLAN subinterfaces");
    Ok(())
}

/// Remove all VLAN subinterfaces.
pub fn teardown_vlan_interfaces(lan_iface: &str, vlan_ids: &[u16]) -> Result<()> {
    for cmd_args in build_vlan_teardown_commands(lan_iface, vlan_ids) {
        let args: Vec<&str> = cmd_args.split_whitespace().collect();
        let _ = Command::new(paths::ip()).args(&args).status();
    }
    info!(count = vlan_ids.len(), "removed VLAN subinterfaces");
    Ok(())
}
```

Add `mod vlan;` to `main.rs`.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent vlan::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/vlan.rs hermitshell-agent/src/main.rs
git commit -m "Add VLAN subinterface create/teardown module"
```

### Task 5: Update nftables for VLAN mode

**Files:**
- Modify: `hermitshell-agent/src/nftables.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_base_ruleset_vlan_mode() {
    let vlan_ifaces = vec!["eth2.10", "eth2.20", "eth2.30", "eth2.40", "eth2.50"];
    let rules = build_base_ruleset_vlan("eth1", "eth2", "10.0.0.1", &vlan_ifaces);
    // DHCP input accepted on each VLAN subinterface
    assert!(rules.contains("eth2.10"));
    assert!(rules.contains("udp dport 67 accept"));
    // Rogue DHCP blocked on each VLAN subinterface
    for iface in &vlan_ifaces {
        assert!(rules.contains(&format!("iifname \"{}\" udp sport 67", iface)),
            "missing rogue DHCP block for {}", iface);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent test_base_ruleset_vlan_mode`
Expected: FAIL

**Step 3: Implement `build_base_ruleset_vlan`**

Add a new function that generates the base ruleset with VLAN subinterface awareness:
- Input chain: accept DHCP (port 67) on each VLAN subinterface
- Forward chain: block rogue DHCP (sport 67) on each VLAN subinterface
- DNS redirect: apply to each VLAN subinterface
- The `apply_base_rules` function should accept an optional `&[String]` of VLAN interface names. When `Some`, use the VLAN variant; when `None`, use the existing flat ruleset.

Keep the existing `build_base_ruleset` unchanged for backward compatibility. The VLAN variant wraps `lan_iface` references with the VLAN subinterface list where appropriate.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent -- nftables::tests`
Expected: All PASS (old and new tests)

**Step 5: Commit**

```bash
git add hermitshell-agent/src/nftables.rs
git commit -m "Add VLAN-aware nftables ruleset generation"
```

### Task 6: Update DHCP to support VLAN subinterfaces

**Files:**
- Modify: `hermitshell-dhcp/src/main.rs`

**Step 1: Understand current DHCP binding**

Current: DHCP binds to `0.0.0.0:67` with `SO_BINDTODEVICE` on `lan_iface` (e.g., `eth2`). In VLAN mode, it needs to bind to each VLAN subinterface separately, or bind to the parent and let the kernel deliver based on VLAN tagging.

**Step 2: Implement VLAN-aware DHCP binding**

The simplest approach: when VLAN mode is enabled, spawn one UDP socket per VLAN subinterface using `SO_BINDTODEVICE`. Each socket serves its VLAN's subnet range.

Add to the DHCP server:
- A `VlanMode` config struct passed at startup (read from agent socket or env)
- When VLAN mode is enabled, create one socket per VLAN subinterface
- Each socket's DHCP handler uses the VLAN's subnet range for IP allocation
- The MAC-to-IP binding still comes from the agent (via IPC)
- Gateway address per VLAN comes from the config

**Step 3: Test**

Unit test: verify that the DHCP response for a device on VLAN 20 uses the `10.0.20.0/24` range with gateway `10.0.20.1`.

Integration test: covered later in Task 8.

**Step 4: Commit**

```bash
git add hermitshell-dhcp/src/main.rs
git commit -m "Support per-VLAN DHCP binding and subnets"
```

### Task 7: VLAN mode startup integration

**Files:**
- Modify: `hermitshell-agent/src/main.rs` (startup sequence)
- Modify: `hermitshell-agent/src/socket/setup.rs` (API to enable/disable VLAN mode)

**Step 1: Add VLAN startup logic to main.rs**

After `apply_base_rules()` in main startup, check if VLAN mode is enabled:

```rust
let vlan_enabled = db.get_config("vlan_mode").ok().flatten().as_deref() == Some("enabled");
if vlan_enabled {
    let vlan_configs = db.get_vlan_config()?;
    vlan::create_vlan_interfaces(&lan_iface, &vlan_configs)?;
    let vlan_ifaces: Vec<String> = vlan_configs.iter()
        .map(|c| format!("{}.{}", lan_iface, c.vlan_id))
        .collect();
    nftables::apply_base_rules_vlan(&wan_iface, &lan_iface, &lan_ip, &vlan_ifaces)?;
} else {
    nftables::apply_base_rules(&wan_iface, &lan_iface, &lan_ip)?;
}
```

**Step 2: Add socket API for enable/disable**

In `socket/setup.rs`, add handlers:
- `vlan_enable` — creates subinterfaces, reapplies nftables, restarts DHCP
- `vlan_disable` — tears down subinterfaces, reapplies flat nftables, restarts DHCP
- `vlan_status` — returns current VLAN config and state

**Step 3: Test**

Build and verify: `cargo build -p hermitshell-agent`

**Step 4: Commit**

```bash
git add hermitshell-agent/src/main.rs hermitshell-agent/src/socket/setup.rs
git commit -m "Integrate VLAN mode into agent startup and API"
```

### Task 8: Integration test for VLAN subinterfaces

**Files:**
- Create: `tests/cases/54-vlan-subinterfaces.sh`

**Step 1: Write the integration test**

```bash
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 54: VLAN subinterface management ==="

# Enable VLAN mode via agent socket
RESULT=$(vm_sudo router 'echo "{\"command\":\"vlan_enable\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$RESULT" '"ok"' "vlan_enable command succeeds"

# Verify subinterfaces exist
for VLAN in 10 20 30 40 50; do
    IF_EXISTS=$(vm_sudo router "ip link show eth2.${VLAN} 2>&1 || true")
    assert_match "$IF_EXISTS" "eth2\.${VLAN}" "eth2.${VLAN} subinterface exists"
done

# Verify gateway IPs are assigned
IP_ADDR=$(vm_sudo router 'ip addr show eth2.10')
assert_match "$IP_ADDR" "10\.0\.10\.1/24" "eth2.10 has gateway 10.0.10.1/24"

# Verify nftables rules reference VLAN interfaces
RULES=$(vm_sudo router 'nft list chain inet filter input')
assert_match "$RULES" "eth2\.10" "nftables input chain references VLAN subinterface"

# Disable VLAN mode
RESULT=$(vm_sudo router 'echo "{\"command\":\"vlan_disable\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$RESULT" '"ok"' "vlan_disable command succeeds"

# Verify subinterfaces removed
IF_GONE=$(vm_sudo router "ip link show eth2.10 2>&1 || true")
assert_match "$IF_GONE" "does not exist" "eth2.10 removed after disable"

echo "=== Test 54 complete ==="
```

**Step 2: Run test**

Run: `bash tests/cases/54-vlan-subinterfaces.sh`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/cases/54-vlan-subinterfaces.sh
git commit -m "Add VLAN subinterface integration test"
```

---

## Component 3: Managed Switch Integration

### Task 9: Add `russh` dependency and create switch module skeleton

**Files:**
- Modify: `Cargo.toml` (workspace deps)
- Modify: `hermitshell-agent/Cargo.toml` (add russh)
- Create: `hermitshell-agent/src/switch/mod.rs`
- Create: `hermitshell-agent/src/switch/ssh.rs`
- Create: `hermitshell-agent/src/switch/vendor.rs`
- Modify: `hermitshell-agent/src/main.rs` (add `mod switch`)

**Step 1: Add russh dependency**

In workspace `Cargo.toml`:
```toml
russh = "0.49"
```

In `hermitshell-agent/Cargo.toml`:
```toml
russh = { workspace = true }
```

Check current version: `cargo search russh` to verify latest.

**Step 2: Create the trait definitions in `switch/mod.rs`**

```rust
pub mod ssh;
pub mod vendor;

use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct SwitchPort {
    pub name: String,
    pub status: PortStatus,
    pub vlan_id: Option<u16>,
    pub is_trunk: bool,
    pub macs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortStatus {
    Up,
    Down,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct MacTableEntry {
    pub mac: String,
    pub vlan_id: u16,
    pub port: String,
}

#[async_trait]
pub trait SwitchProvider: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn list_ports(&self) -> Result<Vec<SwitchPort>>;
    async fn set_port_vlan(&self, port: &str, vlan_id: u16) -> Result<()>;
    async fn get_mac_table(&self) -> Result<Vec<MacTableEntry>>;
    async fn set_trunk_port(&self, port: &str, allowed_vlans: &[u16]) -> Result<()>;
    async fn create_vlan(&self, vlan_id: u16, name: &str) -> Result<()>;
    async fn save_config(&self) -> Result<()>;
}
```

**Step 3: Verify it compiles**

Run: `cargo check -p hermitshell-agent`
Expected: No errors.

**Step 4: Commit**

```bash
git add Cargo.toml hermitshell-agent/Cargo.toml hermitshell-agent/src/switch/ hermitshell-agent/src/main.rs
git commit -m "Add switch module skeleton and SwitchProvider trait"
```

### Task 10: Implement vendor profile system

**Files:**
- Modify: `hermitshell-agent/src/switch/vendor.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisco_ios_profile_exists() {
        let profile = built_in_profile("cisco_ios").unwrap();
        assert!(profile.commands.create_vlan.contains("{vlan_id}"));
        assert!(profile.commands.set_access_port.contains("{port}"));
    }

    #[test]
    fn test_render_command() {
        let profile = built_in_profile("cisco_ios").unwrap();
        let rendered = profile.render_create_vlan(10, "trusted");
        assert!(rendered.contains("vlan 10"));
        assert!(rendered.contains("name trusted"));
    }

    #[test]
    fn test_parse_cisco_mac_table() {
        let output = "  10    001a.2b3c.4d5e    DYNAMIC     Gi0/1\n  20    aabb.ccdd.eeff    DYNAMIC     Gi0/2\n";
        let profile = built_in_profile("cisco_ios").unwrap();
        let entries = profile.parse_mac_table(output);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].vlan_id, 10);
        assert_eq!(entries[0].port, "Gi0/1");
    }

    #[test]
    fn test_unknown_profile() {
        assert!(built_in_profile("nonexistent").is_none());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent vendor::tests`
Expected: FAIL

**Step 3: Implement vendor profiles**

Define `VendorProfile` struct with command templates and regex patterns. Include built-in profiles for Cisco IOS, TP-Link T-series, and Netgear ProSafe. Each profile has:
- Command templates with `{vlan_id}`, `{name}`, `{port}`, `{vlans}` placeholders
- `prompt_pattern` regex for detecting command completion
- `mac_table_regex` for parsing MAC address table output
- `render_*()` methods that substitute placeholders
- `parse_mac_table()` method that extracts `MacTableEntry` from output

Store custom profiles as JSON in the DB `switch_vendor_profiles` table.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent vendor::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/switch/vendor.rs
git commit -m "Add vendor profile system with Cisco/TP-Link/Netgear"
```

### Task 11: Implement SSH switch provider

**Files:**
- Modify: `hermitshell-agent/src/switch/ssh.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssh_command_builder() {
        let profile = vendor::built_in_profile("cisco_ios").unwrap();
        let cmds = build_config_session(&profile, &[
            profile.render_create_vlan(10, "trusted"),
            profile.render_set_access_port("Gi0/1", 10),
        ]);
        assert!(cmds.contains("configure terminal"));
        assert!(cmds.contains("vlan 10"));
        assert!(cmds.contains("interface Gi0/1"));
        assert!(cmds.contains("end"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p hermitshell-agent ssh::tests`
Expected: FAIL

**Step 3: Implement SshSwitchProvider**

```rust
pub struct SshSwitchProvider {
    host: String,
    port: u16,
    username: String,
    password: String,   // or key-based auth
    profile: VendorProfile,
    host_key: Option<String>,  // TOFU pinned key
}
```

Implement `SwitchProvider` trait methods:
- `ping()`: open SSH connection, send a no-op command, verify prompt
- `list_ports()`: run `profile.commands.get_ports`, parse output
- `set_port_vlan()`: enter config mode, run `set_access_port` template, exit, save
- `get_mac_table()`: run `profile.commands.get_mac_table`, parse with regex
- `set_trunk_port()`: enter config mode, run `set_trunk_port` template, exit, save
- `create_vlan()`: enter config mode, run `create_vlan` template, exit, save
- `save_config()`: run `profile.commands.save_config`

Helper: `build_config_session()` wraps commands in enter_config/exit_config.

SSH session handling: use `russh::client` to create a session, open a channel, send commands line by line, read output until prompt pattern matches.

TOFU host key: implement `russh::client::Handler` trait with a custom `check_server_key()` that pins on first connect and verifies on subsequent connections.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent ssh::tests`
Expected: PASS (the test only validates command building, not actual SSH)

**Step 5: Commit**

```bash
git add hermitshell-agent/src/switch/ssh.rs
git commit -m "Implement SSH switch provider with russh"
```

### Task 12: Add switch provider DB schema and CRUD

**Files:**
- Modify: `hermitshell-agent/src/db.rs`

**Step 1: Add schema migration**

```sql
CREATE TABLE IF NOT EXISTS switch_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    vendor_profile TEXT NOT NULL DEFAULT 'cisco_ios',
    uplink_port TEXT,
    host_key TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT DEFAULT 'unknown',
    last_seen INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS switch_vendor_profiles (
    name TEXT PRIMARY KEY,
    profile_json TEXT NOT NULL
);
```

Add `switch_port` and `switch_id` columns to devices table:
```sql
ALTER TABLE devices ADD COLUMN switch_id TEXT;
ALTER TABLE devices ADD COLUMN switch_port TEXT;
```

**Step 2: Implement CRUD methods**

- `list_switch_providers() -> Result<Vec<SwitchProviderInfo>>`
- `insert_switch_provider(...)` / `remove_switch_provider(id)`
- `get_switch_provider_credentials(id) -> Result<(host, port, user, pass_enc, profile, host_key)>`
- `set_switch_provider_host_key(id, key)`
- `update_switch_provider_status(id, status, last_seen)`
- `update_device_switch_info(mac, switch_id, switch_port)`
- `get_custom_vendor_profile(name) -> Result<Option<String>>`
- `set_custom_vendor_profile(name, json)`

Add structs to `hermitshell-common/src/lib.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchProviderInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub vendor_profile: String,
    pub uplink_port: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub last_seen: i64,
}
```

**Step 3: Write unit tests**

Test CRUD operations with in-memory DB.

**Step 4: Run tests**

Run: `cargo test -p hermitshell-agent -- db::tests`
Expected: PASS

**Step 5: Commit**

```bash
git add hermitshell-agent/src/db.rs hermitshell-common/src/lib.rs
git commit -m "Add switch provider DB schema and CRUD"
```

### Task 13: Switch background polling loop

**Files:**
- Modify: `hermitshell-agent/src/switch/mod.rs` (add `run()` function)
- Modify: `hermitshell-agent/src/main.rs` (spawn switch polling task)

**Step 1: Implement polling loop**

Follow the same pattern as `wifi/mod.rs::run()`:

```rust
pub async fn run(db: Arc<Mutex<Db>>) {
    let mut poll_interval = interval(Duration::from_secs(60));
    loop {
        poll_interval.tick().await;
        // For each enabled switch provider:
        //   1. Connect via SSH
        //   2. Query MAC table
        //   3. Correlate MACs with device DB
        //   4. Update device switch_port assignments
        //   5. Update provider status
    }
}
```

**Step 2: Spawn in main.rs**

Add alongside the WiFi polling task:
```rust
let switch_db = db.clone();
tokio::spawn(async move { switch::run(switch_db).await; });
```

**Step 3: Verify it compiles and doesn't break anything**

Run: `cargo build -p hermitshell-agent`
Expected: Success

**Step 4: Commit**

```bash
git add hermitshell-agent/src/switch/mod.rs hermitshell-agent/src/main.rs
git commit -m "Add switch provider background polling loop"
```

### Task 14: Socket API for switch management

**Files:**
- Create: `hermitshell-agent/src/socket/switch.rs`
- Modify: `hermitshell-agent/src/socket/mod.rs` (add switch command dispatch)

**Step 1: Implement socket handlers**

Add commands:
- `switch_add` — add a new switch provider (host, port, credentials, vendor profile)
- `switch_remove` — remove a switch provider
- `switch_list` — list all switch providers with status
- `switch_test` — test SSH connectivity to a switch
- `switch_ports` — list ports on a switch with VLAN assignments and MAC correlations
- `switch_set_uplink` — designate a port as trunk uplink
- `switch_provision_vlans` — create VLANs and configure trunk on a switch

Follow the existing pattern in `socket/setup.rs` for command handling.

**Step 2: Wire into socket dispatch**

In `socket/mod.rs`, add the switch commands to the match block that dispatches incoming commands.

**Step 3: Verify it compiles**

Run: `cargo check -p hermitshell-agent`

**Step 4: Commit**

```bash
git add hermitshell-agent/src/socket/switch.rs hermitshell-agent/src/socket/mod.rs
git commit -m "Add switch management socket API"
```

### Task 15: Automatic VLAN assignment on device group change

**Files:**
- Modify: `hermitshell-agent/src/socket/devices.rs` (group change handler)

**Step 1: Understand current group change flow**

Read `socket/devices.rs` to find where `device_set_group` is handled. Currently it:
1. Updates group in DB
2. Removes old forward rule
3. Adds new forward rule
4. Flushes conntrack

**Step 2: Add VLAN reassignment**

When VLAN mode is enabled and a device changes group:
1. Look up new group's VLAN ID from `vlan_config` table
2. If device has a known `switch_id` and `switch_port`:
   a. SSH to switch, change port VLAN to new VLAN ID
   b. Save switch config
3. The device will lose connectivity briefly as its VLAN changes
4. DHCP: the old IP is in the wrong VLAN range now. On next DHCP renewal, the device gets a NAK (wrong subnet), re-discovers, and gets a new IP in the correct VLAN range.

**Step 3: Test**

This is best tested as an integration test (Task 16).

**Step 4: Commit**

```bash
git add hermitshell-agent/src/socket/devices.rs
git commit -m "Auto-reassign VLAN on device group change"
```

### Task 16: Integration test for switch VLAN management

**Files:**
- Create: `tests/cases/55-switch-vlan-management.sh`

**Step 1: Write the test**

Note: This test cannot fully test SSH to a real switch in the VM environment. It tests the socket API responses and verifies the agent handles switch commands correctly (even if the SSH connection itself fails in test).

```bash
#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 55: Switch VLAN management API ==="

# Add a switch provider (will fail SSH in test env, but API should accept it)
ADD_RESULT=$(vm_sudo router "echo '{\"command\":\"switch_add\",\"name\":\"test-switch\",\"host\":\"192.168.1.100\",\"port\":22,\"username\":\"admin\",\"password\":\"admin\",\"vendor_profile\":\"cisco_ios\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$ADD_RESULT" '"ok"' "switch_add command accepted"

# List switches
LIST_RESULT=$(vm_sudo router "echo '{\"command\":\"switch_list\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$LIST_RESULT" 'test-switch' "switch_list shows added switch"

# Remove switch
REMOVE_RESULT=$(vm_sudo router "echo '{\"command\":\"switch_remove\",\"name\":\"test-switch\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$REMOVE_RESULT" '"ok"' "switch_remove succeeds"

echo "=== Test 55 complete ==="
```

**Step 2: Run test**

Run: `bash tests/cases/55-switch-vlan-management.sh`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/cases/55-switch-vlan-management.sh
git commit -m "Add switch VLAN management integration test"
```

---

## Component 2b: WiFi SSID-to-VLAN Mapping

### Task 17: Add `set_ssid_vlan` to WifiProvider trait

**Files:**
- Modify: `hermitshell-agent/src/wifi/mod.rs`
- Modify: `hermitshell-agent/src/wifi/eap_standalone.rs`
- Modify: `hermitshell-agent/src/wifi/unifi.rs`

**Step 1: Add trait method**

In `wifi/mod.rs`, add to `WifiProvider` trait:
```rust
async fn set_ssid_vlan(&self, ssid_name: &str, vlan_id: u16) -> Result<()>;
async fn get_ssid_vlan(&self, ssid_name: &str) -> Result<Option<u16>>;
```

**Step 2: Implement for EAP720**

In `eap_standalone.rs`, POST to wireless SSID config with `vlanId` field.

**Step 3: Implement for UniFi**

In `unifi.rs`, PUT to WLAN config with `vlan` or `vlan_enabled` + `vlan` fields.

**Step 4: Verify it compiles**

Run: `cargo check -p hermitshell-agent`

**Step 5: Commit**

```bash
git add hermitshell-agent/src/wifi/mod.rs hermitshell-agent/src/wifi/eap_standalone.rs hermitshell-agent/src/wifi/unifi.rs
git commit -m "Add SSID-to-VLAN mapping to WiFi providers"
```

### Task 18: Socket API for WiFi VLAN configuration

**Files:**
- Modify: `hermitshell-agent/src/socket/setup.rs` or new `socket/wifi.rs`

**Step 1: Add socket commands**

- `wifi_set_ssid_vlan` — set VLAN tag for an SSID on a provider
- `wifi_get_ssid_vlans` — list current SSID-to-VLAN mappings

**Step 2: Commit**

```bash
git add hermitshell-agent/src/socket/
git commit -m "Add WiFi SSID VLAN configuration API"
```

---

## Web UI

### Task 19: VLAN settings page

**Files:**
- Create: `hermitshell-ui/src/pages/vlan_settings.rs`
- Modify: `hermitshell-ui/src/pages/mod.rs` (add route)
- Modify: `hermitshell-ui/src/pages/settings.rs` (add nav link)

**Step 1: Create the VLAN settings page**

Settings > Network > VLANs page with:
- Enable/disable VLAN mode toggle
- VLAN ID and subnet mapping table (editable)
- Status indicators per VLAN

Follow existing settings page patterns (e.g., WiFi settings page).

**Step 2: Commit**

```bash
git add hermitshell-ui/src/pages/
git commit -m "Add VLAN settings page to web UI"
```

### Task 20: Switch management page

**Files:**
- Create: `hermitshell-ui/src/pages/switch_settings.rs`
- Modify: `hermitshell-ui/src/pages/mod.rs`

**Step 1: Create the switch management page**

Settings > Network > Switches page with:
- Add/remove switches form
- Test connection button
- Per-switch port view with VLAN assignments
- Designate uplink port dropdown

**Step 2: Commit**

```bash
git add hermitshell-ui/src/pages/
git commit -m "Add switch management page to web UI"
```

### Task 21: Update device detail page

**Files:**
- Modify: `hermitshell-ui/src/pages/device_detail.rs`

**Step 1: Add VLAN info to device detail**

Show current VLAN, switch port, and switch name when VLAN mode is enabled.

**Step 2: Commit**

```bash
git add hermitshell-ui/src/pages/device_detail.rs
git commit -m "Show VLAN and switch info on device detail page"
```

---

## Documentation

### Task 22: Update SECURITY.md

**Files:**
- Modify: `docs/SECURITY.md`

**Step 1: Update threat entries**

- Mark rogue DHCP server threat as mitigated (with caveats for same-segment)
- Add new entry for VLAN mode mitigations
- Update ARP spoofing entries to reference VLAN isolation
- Note that managed switch integration provides full L2 isolation

**Step 2: Commit**

```bash
git add docs/SECURITY.md
git commit -m "Update SECURITY.md for L2 anti-spoofing"
```

### Task 23: Update NixOS provisioning for testing

**Files:**
- Modify: `tests/provision/router-nixos.sh`

**Step 1: Ensure 8021q kernel module is available**

Add to NixOS config if needed:
```nix
boot.kernelModules = [ "8021q" ];
```

Verify `ip link add type vlan` works in the test VM.

**Step 2: Commit**

```bash
git add tests/provision/router-nixos.sh
git commit -m "Ensure 8021q VLAN module available in test VM"
```

---

## Final Verification

### Task 24: Run full test suite

**Step 1: Run all tests**

Run: `bash run.sh` (builds, deploys, runs full test suite)

Expected: All tests pass, including new tests 53, 54, 55.

**Step 2: Verify no regressions**

Check that all existing 37 tests still pass. The key risk areas:
- Test 02 (LAN DHCP) — DHCP still works in non-VLAN mode
- Test 03 (LAN internet) — forwarding rules unchanged
- Test 14 (agent restart) — agent starts correctly with default (non-VLAN) config
- Test 15 (device groups) — group changes work without VLAN mode

**Step 3: Commit any fixes needed**

If tests fail, fix and commit with descriptive messages.

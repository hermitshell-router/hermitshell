# Wire Dead Code Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire all dead code into active code paths, removing every `#[allow(dead_code)]` annotation from the codebase (except Group A L2 anti-spoofing scaffolding).

**Architecture:** Add socket API endpoints + UI integration for WiFi client management and DNS toggles. Remove duplicate code (DoH constants, mDNS query). Wire `remove_upnp_input_rules` into UPnP disable flow. Add WAN lease info to status. Prefix truly unused struct fields with `_`.

**Tech Stack:** Rust (async Tokio), Leptos 0.8 SSR, Unix socket JSON API, nftables

---

### Task 1: WiFi Client Management — Socket Handlers

**Files:**
- Modify: `hermitshell-agent/src/socket/wifi.rs:228-240` (handle_wifi_async)
- Modify: `hermitshell-agent/src/socket/mod.rs:61-108` (WEB_ALLOWED_METHODS)
- Modify: `hermitshell-agent/src/socket/mod.rs:421-424,437-440` (async dispatch)

**Step 1: Add 3 new methods to handle_wifi_async in socket/wifi.rs**

In `handle_wifi_async` (line 228), add three new match arms before the `_ =>` fallback:

```rust
"wifi_kick_client" => handle_wifi_kick_client(req, db).await,
"wifi_block_client" => handle_wifi_block_client(req, db).await,
"wifi_unblock_client" => handle_wifi_unblock_client(req, db).await,
```

**Step 2: Implement the three handler functions in socket/wifi.rs**

Add after handle_wifi_async (around line 240):

```rust
async fn handle_wifi_kick_client(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref mac) = req.mac else {
        return Response::err("mac required (client MAC)");
    };
    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.kick_client(mac).await {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&format!("kick_client failed: {}", e)),
    }
}

async fn handle_wifi_block_client(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref mac) = req.mac else {
        return Response::err("mac required (client MAC)");
    };
    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.block_client(mac).await {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&format!("block_client failed: {}", e)),
    }
}

async fn handle_wifi_unblock_client(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref mac) = req.mac else {
        return Response::err("mac required (client MAC)");
    };
    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match provider.unblock_client(mac).await {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(&format!("unblock_client failed: {}", e)),
    }
}
```

**Step 3: Add to WEB_ALLOWED_METHODS in socket/mod.rs**

Add after `"wifi_get_clients"` (around line 88):
```rust
"wifi_kick_client",
"wifi_block_client",
"wifi_unblock_client",
```

**Step 4: Add to async dispatch in socket/mod.rs**

In both async dispatch blocks (lines 421-424 and 437-440), add the new methods to the match pattern:

Change:
```rust
"wifi_get_ssids" | "wifi_set_ssid" | "wifi_delete_ssid"
| "wifi_get_radios" | "wifi_set_radio"
| "wifi_set_ssid_vlan" | "wifi_get_ssid_vlans" => {
```
To:
```rust
"wifi_get_ssids" | "wifi_set_ssid" | "wifi_delete_ssid"
| "wifi_get_radios" | "wifi_set_radio"
| "wifi_set_ssid_vlan" | "wifi_get_ssid_vlans"
| "wifi_kick_client" | "wifi_block_client" | "wifi_unblock_client" => {
```

Both blocks (with-mac at ~421 and without-mac at ~437).

**Step 5: Remove `#[allow(dead_code)]` from trait definitions in wifi/mod.rs**

Remove the 3 annotations at lines 39, 41, 43 for `kick_client`, `block_client`, `unblock_client`.

**Step 6: Remove `#[allow(dead_code)]` from EAP impl in wifi/eap_standalone.rs**

Remove annotations at lines 619, 632, 659 for `kick_client_impl`, `block_client_impl`, `unblock_client_impl`.

**Step 7: Remove `#[allow(dead_code)]` from UniFi impl in wifi/unifi.rs**

Remove annotation at line 423 for `stamgr_cmd`.

**Step 8: Build and verify no warnings**

Run: `cargo build 2>&1 | grep "dead_code\|unused"`
Expected: No warnings for WiFi client management methods.

**Step 9: Commit**

```
git add hermitshell-agent/src/socket/wifi.rs hermitshell-agent/src/socket/mod.rs hermitshell-agent/src/wifi/mod.rs hermitshell-agent/src/wifi/eap_standalone.rs hermitshell-agent/src/wifi/unifi.rs
git commit -m "Wire wifi client kick/block/unblock endpoints"
```

---

### Task 2: WiFi AP Status — Socket Handler

**Files:**
- Modify: `hermitshell-agent/src/socket/wifi.rs:228-240` (handle_wifi_async)
- Modify: `hermitshell-agent/src/socket/mod.rs:61-108` (WEB_ALLOWED_METHODS)
- Modify: `hermitshell-agent/src/socket/mod.rs:421-424,437-440` (async dispatch)
- Modify: `hermitshell-agent/src/wifi/mod.rs:50-52` (WifiDevice trait)

**Step 1: Add wifi_get_ap_status to handle_wifi_async**

Add match arm:
```rust
"wifi_get_ap_status" => handle_wifi_get_ap_status(req, db).await,
```

**Step 2: Implement handler**

Add after existing handlers in socket/wifi.rs:

```rust
async fn handle_wifi_get_ap_status(req: &Request, db: &Arc<Mutex<Db>>) -> Response {
    let Some(ref provider_id) = req.provider_id else {
        return Response::err("provider_id required");
    };
    let Some(ref ap_mac) = req.mac else {
        return Response::err("mac required (AP MAC)");
    };
    let provider = match connect_to_provider(provider_id, db).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let device = match provider.device(ap_mac).await {
        Ok(d) => d,
        Err(e) => return Response::err(&format!("device connect failed: {}", e)),
    };
    match device.get_status().await {
        Ok(status) => {
            let mut resp = Response::ok();
            resp.config_value = Some(serde_json::json!({
                "model": status.model,
                "firmware": status.firmware,
                "uptime": status.uptime,
            }).to_string());
            resp
        }
        Err(e) => Response::err(&format!("get_status failed: {}", e)),
    }
}
```

**Step 3: Add to WEB_ALLOWED_METHODS**

Add `"wifi_get_ap_status"` after the other wifi methods.

**Step 4: Add to async dispatch**

Add `| "wifi_get_ap_status"` to both async dispatch match patterns (same places as Task 1).

**Step 5: Remove `#[allow(dead_code)]` from WifiDevice::get_status in wifi/mod.rs:50-51**

**Step 6: Build and verify**

Run: `cargo build 2>&1 | grep "dead_code\|unused"`

**Step 7: Commit**

```
git add hermitshell-agent/src/socket/wifi.rs hermitshell-agent/src/socket/mod.rs hermitshell-agent/src/wifi/mod.rs
git commit -m "Wire wifi AP status endpoint"
```

---

### Task 3: WiFi Client Management — UI Client + Server Functions + Page

**Files:**
- Modify: `hermitshell-ui/src/client.rs` (add 3 methods)
- Modify: `hermitshell-ui/src/server_fns.rs` (add 3 server fns)
- Modify: `hermitshell-ui/src/pages/wifi.rs` (add action buttons to clients table)

**Step 1: Add client methods in client.rs**

Add after `wifi_get_clients` (around line 519):

```rust
pub fn wifi_kick_client(provider_id: &str, mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "wifi_kick_client", "provider_id": provider_id, "mac": mac}))?)?;
    Ok(())
}

pub fn wifi_block_client(provider_id: &str, mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "wifi_block_client", "provider_id": provider_id, "mac": mac}))?)?;
    Ok(())
}

pub fn wifi_unblock_client(provider_id: &str, mac: &str) -> Result<(), String> {
    ok_or_err(send(json!({"method": "wifi_unblock_client", "provider_id": provider_id, "mac": mac}))?)?;
    Ok(())
}
```

**Step 2: Add server functions in server_fns.rs**

Add after existing WiFi server functions:

```rust
#[server]
pub async fn wifi_kick_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_kick_client(&provider_id, &mac).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("wifi_kick_client", &mac);
    leptos_axum::redirect("/wifi");
    Ok(())
}

#[server]
pub async fn wifi_block_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_block_client(&provider_id, &mac).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("wifi_block_client", &mac);
    leptos_axum::redirect("/wifi");
    Ok(())
}

#[server]
pub async fn wifi_unblock_client(provider_id: String, mac: String) -> Result<(), ServerFnError> {
    crate::client::wifi_unblock_client(&provider_id, &mac).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("wifi_unblock_client", &mac);
    leptos_axum::redirect("/wifi");
    Ok(())
}
```

**Step 3: Add action buttons to WiFi clients table in pages/wifi.rs**

In the clients table (around line 236-276), add an "Actions" column header and action forms to each row. The clients table currently has columns: MAC, AP, SSID, Band, RSSI.

Add `<th>"Actions"</th>` to the thead row.

For each client row, add a td with kick and block buttons. The clients are loaded from the DB (which doesn't store provider_id per client), so we need a default provider. Since the WiFi page already has providers loaded, pick the first provider with a matching AP MAC if possible. For simplicity, pass provider_id as a hidden field. Look at how the page currently gets the provider list — it should have a `providers` resource. If there's only one provider, use that. Add the action forms:

```rust
<td>
    <ActionForm action=kick_action attr:style="display:inline">
        <input type="hidden" name="provider_id" value={/* provider_id for this AP */} />
        <input type="hidden" name="mac" value={c.mac.clone()} />
        <button type="submit" class="btn btn-warning btn-sm">"Kick"</button>
    </ActionForm>
</td>
```

Since each row needs its own `ServerAction` and `provider_id`, and the providers resource may contain multiple providers, map the `ap_mac` from the client to the provider. This requires reading the page more carefully. If complex, a simpler approach: add provider_id as a column in the table (hidden) and create actions per-row.

**Step 4: Build and verify**

Run: `cargo build 2>&1 | grep "error\|warning"`

**Step 5: Commit**

```
git add hermitshell-ui/src/client.rs hermitshell-ui/src/server_fns.rs hermitshell-ui/src/pages/wifi.rs
git commit -m "Add wifi client kick/block/unblock to UI"
```

---

### Task 4: WiFi AP Status — UI Integration

**Files:**
- Modify: `hermitshell-ui/src/client.rs` (add method)
- Modify: `hermitshell-ui/src/pages/wifi.rs` (show AP status info)

**Step 1: Add client method**

```rust
pub fn wifi_get_ap_status(provider_id: &str, mac: &str) -> Result<String, String> {
    let resp = ok_or_err(send(json!({"method": "wifi_get_ap_status", "provider_id": provider_id, "mac": mac}))?)?;
    Ok(resp.config_value.unwrap_or_default())
}
```

**Step 2: Show AP status in the WiFi APs table**

The WiFi page already shows APs in a table. For now, add status info as extra columns or a detail row. This requires an async call per AP, which is complex in SSR mode. A simpler approach: add a "Check Status" button per AP that navigates to a status display, or show it inline if feasible.

Given SSR complexity, the simplest approach is to add the client method (making it callable) and note the UI integration as a future enhancement. The dead code is wired in at the socket/API level.

**Step 3: Build and verify**

**Step 4: Commit**

```
git add hermitshell-ui/src/client.rs
git commit -m "Add wifi AP status client method"
```

---

### Task 5: DNS Toggle Endpoints — Socket Handlers

**Files:**
- Modify: `hermitshell-agent/src/socket/dns.rs` (add 3 handlers)
- Modify: `hermitshell-agent/src/socket/mod.rs:563-573` (dispatch table)
- Modify: `hermitshell-agent/src/socket/mod.rs:61-108` (WEB_ALLOWED_METHODS)
- Modify: `hermitshell-agent/src/db.rs:1960-2047` (remove #[allow(dead_code)])

**Step 1: Add 3 handlers to socket/dns.rs**

Add after `handle_remove_dns_blocklist` (line 298):

```rust
pub(super) fn handle_set_dns_forward_enabled(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required (true or false)");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_dns_forward_zone_enabled(id, enabled) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);
    let mut mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}

pub(super) fn handle_set_dns_rule_enabled(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required (true or false)");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_dns_custom_rule_enabled(id, enabled) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);
    let mut mgr = unbound.lock().unwrap();
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}

pub(super) fn handle_set_dns_blocklist_enabled(
    req: &Request,
    db: &Arc<Mutex<Db>>,
    unbound: &Arc<Mutex<UnboundManager>>,
) -> Response {
    let Some(id) = req.id else {
        return Response::err("id required");
    };
    let Some(enabled) = req.enabled else {
        return Response::err("enabled required (true or false)");
    };
    let db_guard = db.lock().unwrap();
    if let Err(e) = db_guard.set_dns_blocklist_enabled(id, enabled) {
        return Response::err(&e.to_string());
    }
    drop(db_guard);
    let mut mgr = unbound.lock().unwrap();
    let _ = mgr.download_blocklists(db);
    let _ = mgr.write_config(db);
    let _ = mgr.reload();
    Response::ok()
}
```

**Step 2: Add to dispatch table in socket/mod.rs**

After `"remove_dns_blocklist"` (line 573), add:
```rust
"set_dns_forward_enabled" => dns::handle_set_dns_forward_enabled(&req, db, unbound),
"set_dns_rule_enabled" => dns::handle_set_dns_rule_enabled(&req, db, unbound),
"set_dns_blocklist_enabled" => dns::handle_set_dns_blocklist_enabled(&req, db, unbound),
```

**Step 3: Add to WEB_ALLOWED_METHODS**

Add the 3 method names after existing DNS methods.

**Step 4: Remove `#[allow(dead_code)]` from db.rs**

Remove annotations at lines 1960, 2000, 2040 for the three DB methods.

**Step 5: Build and verify**

Run: `cargo build 2>&1 | grep "dead_code\|unused"`

**Step 6: Commit**

```
git add hermitshell-agent/src/socket/dns.rs hermitshell-agent/src/socket/mod.rs hermitshell-agent/src/db.rs
git commit -m "Wire DNS forward/rule/blocklist toggle endpoints"
```

---

### Task 6: DNS Toggle — UI Client + Server Functions + Page

**Files:**
- Modify: `hermitshell-ui/src/client.rs`
- Modify: `hermitshell-ui/src/server_fns.rs`
- Modify: `hermitshell-ui/src/pages/dns.rs`

**Step 1: Add client methods**

```rust
pub fn set_dns_forward_enabled(id: i64, enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_dns_forward_enabled", "id": id, "enabled": enabled}))?)?;
    Ok(())
}

pub fn set_dns_rule_enabled(id: i64, enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_dns_rule_enabled", "id": id, "enabled": enabled}))?)?;
    Ok(())
}

pub fn set_dns_blocklist_enabled(id: i64, enabled: bool) -> Result<(), String> {
    ok_or_err(send(json!({"method": "set_dns_blocklist_enabled", "id": id, "enabled": enabled}))?)?;
    Ok(())
}
```

**Step 2: Add server functions**

```rust
#[server]
pub async fn set_dns_forward_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_forward_enabled(id, enabled).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("set_dns_forward_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns");
    Ok(())
}

#[server]
pub async fn set_dns_rule_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_rule_enabled(id, enabled).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("set_dns_rule_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns");
    Ok(())
}

#[server]
pub async fn set_dns_blocklist_enabled(id: i64, enabled: String) -> Result<(), ServerFnError> {
    let enabled = enabled == "true";
    crate::client::set_dns_blocklist_enabled(id, enabled).map_err(ServerFnError::new)?;
    let _ = crate::client::log_audit("set_dns_blocklist_enabled", &format!("id={} enabled={}", id, enabled));
    leptos_axum::redirect("/dns");
    Ok(())
}
```

**Step 3: Add toggle buttons to DNS page tables**

For each table (forward zones, custom rules, blocklists), add an "Enabled" column with a toggle form. Check if `DnsForwardZone`, `DnsCustomRule`, `DnsBlocklist` structs have an `enabled` field. If they do, show current state and toggle button. If not, add the field to the common structs.

In each table row, add:
```rust
<td>
    <ActionForm action=toggle_action attr:style="display:inline">
        <input type="hidden" name="id" value={id.to_string()} />
        <input type="hidden" name="enabled" value={if currently_enabled { "false" } else { "true" }} />
        <button type="submit" class={if currently_enabled { "btn btn-sm btn-success" } else { "btn btn-sm btn-secondary" }}>
            {if currently_enabled { "Enabled" } else { "Disabled" }}
        </button>
    </ActionForm>
</td>
```

**Step 4: Build and verify**

**Step 5: Commit**

```
git add hermitshell-ui/src/client.rs hermitshell-ui/src/server_fns.rs hermitshell-ui/src/pages/dns.rs
git commit -m "Add DNS toggle switches to UI"
```

---

### Task 7: UPnP Input Rule Cleanup

**Files:**
- Modify: `hermitshell-agent/src/socket/network.rs:210-232` (handle_set_upnp_config)
- Modify: `hermitshell-agent/src/nftables.rs:869-887` (remove #[allow(dead_code)])

**Step 1: Wire remove_upnp_input_rules into disable flow**

In `handle_set_upnp_config` (network.rs:226-231), change:

```rust
    if value == "false" {
        portmap.clear_automatic();
    }
    let mut resp = Response::ok();
    resp.config_value = Some("restart_required".to_string());
    resp
```

To:

```rust
    if value == "false" {
        portmap.clear_automatic();
        if let Err(e) = crate::nftables::remove_upnp_input_rules() {
            tracing::warn!(error = %e, "failed to remove UPnP input rules");
        }
    }
    Response::ok()
```

When disabling, we clean up input rules immediately (no restart required). When enabling, still return `restart_required` since we need the daemon task started.

Actually, re-read the handler — it doesn't distinguish enable vs disable for the response. Let's only return `restart_required` for enable:

```rust
    if value == "false" {
        portmap.clear_automatic();
        if let Err(e) = crate::nftables::remove_upnp_input_rules() {
            tracing::warn!(error = %e, "failed to remove UPnP input rules");
        }
        Response::ok()
    } else {
        let mut resp = Response::ok();
        resp.config_value = Some("restart_required".to_string());
        resp
    }
```

**Step 2: Remove `#[allow(dead_code)]` from nftables.rs:869**

**Step 3: Build and verify**

**Step 4: Commit**

```
git add hermitshell-agent/src/socket/network.rs hermitshell-agent/src/nftables.rs
git commit -m "Wire remove_upnp_input_rules on UPnP disable"
```

---

### Task 8: Remove Duplicate DoH Constants

**Files:**
- Modify: `hermitshell-agent/src/unbound.rs:12-46` (remove constants)

**Step 1: Delete the constants**

Remove lines 12-46 (`DOH_RESOLVER_IPS_V4` and `DOH_RESOLVER_IPS_V6`). These exact IPs are already hardcoded in the nftables ruleset at `nftables.rs:126-134` as nftables sets `doh_block_v4` and `doh_block_v6`. Keeping them in two places risks them going out of sync.

**Step 2: Build and verify no compilation errors**

Run: `cargo build 2>&1 | grep error`

**Step 3: Commit**

```
git add hermitshell-agent/src/unbound.rs
git commit -m "Remove duplicate DoH IP constants"
```

---

### Task 9: Remove Duplicate mDNS query() Method

**Files:**
- Modify: `hermitshell-agent/src/mdns.rs:152-189` (remove query())

**Step 1: Delete the `query()` method**

Remove lines 152-189. The `query_full()` method (lines 191-228) already does the same group-based filtering and is actively used by the mDNS proxy at line 549. The `query()` method is a duplicate that returns cloned `MdnsService` values instead of references.

**Step 2: Build and verify**

**Step 3: Commit**

```
git add hermitshell-agent/src/mdns.rs
git commit -m "Remove duplicate mDNS query method"
```

---

### Task 10: Remove PCP_UNSUPP_OPTION Constant

**Files:**
- Modify: `hermitshell-agent/src/natpmp.rs:25-26`

**Step 1: Delete lines 25-26**

Remove:
```rust
#[allow(dead_code)]
const PCP_UNSUPP_OPTION: u8 = 5;
```

This PCP error code is unused and other error codes are defined inline where needed.

**Step 2: Build and verify**

**Step 3: Commit**

```
git add hermitshell-agent/src/natpmp.rs
git commit -m "Remove unused PCP_UNSUPP_OPTION constant"
```

---

### Task 11: Prefix Unused Struct Fields

**Files:**
- Modify: `hermitshell-agent/src/conntrack.rs:22-23`
- Modify: `hermitshell-agent/src/unbound.rs` (struct fields, after Task 8 line shift)
- Modify: `hermitshell-agent/src/mdns.rs` (ServiceRecord fields)

**Step 1: ConntrackEvent.src_port → _src_port**

In conntrack.rs, change:
```rust
    #[allow(dead_code)]
    pub src_port: u16,
```
To:
```rust
    pub _src_port: u16,
```

Also update the parsing code that writes to this field (search for `src_port:` in the parser).

**Step 2: UnboundManager fields**

In unbound.rs (after line shift from Task 8), change:
```rust
    #[allow(dead_code)]
    listen_addr: String,
    #[allow(dead_code)]
    listen_addr_v6: Option<String>,
```
To:
```rust
    _listen_addr: String,
    _listen_addr_v6: Option<String>,
```

Also update the constructor that sets these fields.

**Step 3: ServiceRecord fields in mdns.rs**

Change:
```rust
    #[allow(dead_code)]
    device_mac: String,
    ...
    #[allow(dead_code)]
    ttl_secs: u32,
```
To:
```rust
    _device_mac: String,
    ...
    _ttl_secs: u32,
```

Update the constructor(s) that write to these fields.

**Step 4: Build and verify all 3 changes compile**

**Step 5: Commit**

```
git add hermitshell-agent/src/conntrack.rs hermitshell-agent/src/unbound.rs hermitshell-agent/src/mdns.rs
git commit -m "Prefix unused struct fields with underscore"
```

---

### Task 12: Wire WanLease into Status

**Files:**
- Modify: `hermitshell-agent/src/wan.rs:20-23` (remove #[allow(dead_code)])
- Modify: `hermitshell-agent/src/socket/mod.rs` (pass SharedWanLease to handler)
- Modify: `hermitshell-agent/src/socket/devices.rs:41-52` (add WAN info to status)
- Modify: `hermitshell-agent/src/socket/mod.rs:306-310` (add WAN fields to Status struct)
- Modify: `hermitshell-agent/src/main.rs` (pass wan_lease to socket listener)

**Step 1: Add WAN fields to Status struct in socket/mod.rs:306-310**

Change:
```rust
struct Status {
    uptime_secs: u64,
    device_count: usize,
    ad_blocking_enabled: bool,
}
```
To:
```rust
struct Status {
    uptime_secs: u64,
    device_count: usize,
    ad_blocking_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    wan_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wan_gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wan_dns: Option<Vec<String>>,
}
```

**Step 2: Thread SharedWanLease through socket dispatch**

This requires:
1. Adding `wan_lease: crate::wan::SharedWanLease` parameter to `handle_client`
2. Passing it through to `handle_request`
3. Passing it to `devices::handle_get_status`

In `main.rs`, find where `socket::listen` is called and pass `wan_lease`.
In `socket/mod.rs`, add the parameter through the chain:
- `listen()` signature
- `handle_client()` signature (line 401)
- `handle_request()` signature (line 463)
- The `get_status` dispatch at line 471

**Step 3: Update handle_get_status in socket/devices.rs**

```rust
pub(super) fn handle_get_status(
    _req: &Request,
    db: &Arc<Mutex<Db>>,
    start_time: std::time::Instant,
    wan_lease: &crate::wan::SharedWanLease,
) -> Response {
    let db = db.lock().unwrap();
    let device_count = db.list_devices().map(|d| d.len()).unwrap_or(0);
    let ad_blocking = db.get_config_bool("ad_blocking_enabled", true);
    let lease_guard = wan_lease.lock().unwrap();
    let (wan_ip, wan_gateway, wan_dns) = match lease_guard.as_ref() {
        Some(l) => (
            Some(l.ip.to_string()),
            Some(l.gateway.to_string()),
            Some(l.dns_servers.iter().map(|d| d.to_string()).collect()),
        ),
        None => (None, None, None),
    };
    drop(lease_guard);
    let mut resp = Response::ok();
    resp.status = Some(Status {
        uptime_secs: start_time.elapsed().as_secs(),
        device_count,
        ad_blocking_enabled: ad_blocking,
        wan_ip,
        wan_gateway,
        wan_dns,
    });
    resp
}
```

**Step 4: Remove `#[allow(dead_code)]` from WanLease struct in wan.rs:22**

**Step 5: Build and verify**

**Step 6: Commit**

```
git add hermitshell-agent/src/wan.rs hermitshell-agent/src/socket/mod.rs hermitshell-agent/src/socket/devices.rs hermitshell-agent/src/main.rs
git commit -m "Wire WAN lease info into status endpoint"
```

---

### Task 13: Full Build + Test

**Step 1: Full cargo build with no warnings**

Run: `cargo build 2>&1 | grep -E "warning|error"`
Expected: Only Group A warnings (switch/vlan scaffolding).

**Step 2: Run unit tests**

Run: `cargo test`
Expected: All pass.

**Step 3: Run integration tests (if VMs available)**

Run: `bash run.sh`
Expected: All 37 tests pass.

**Step 4: Final commit if any fixups needed**

---

### Task 14: Update Design Doc

**Files:**
- Modify: `docs/plans/2026-03-02-wire-dead-code-design.md`

**Step 1: Update the design doc**

Note what was actually done vs planned. Specifically document:
- DoH constants: removed as duplicates (not wired in)
- mDNS query(): removed as duplicate (not wired in)
- WanLease: wired into status endpoint
- PCP_UNSUPP_OPTION: removed

**Step 2: Commit**

```
git add docs/plans/2026-03-02-wire-dead-code-design.md
git commit -m "Update design doc with final decisions"
```

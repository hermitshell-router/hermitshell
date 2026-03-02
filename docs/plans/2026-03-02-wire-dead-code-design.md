# Wire In Dead Code — Design

All dead code in the repo falls into two groups: Group A (L2 anti-spoofing
scaffolding, kept as-is for Phase 20) and Group B (implemented but uncalled
features). This design covers wiring Group B into the active code paths and
removing all `#[allow(dead_code)]` annotations.

## 1. WiFi Client Management

**Dead code:** `WifiProvider::kick_client/block_client/unblock_client`,
`EapSession::kick_client_impl/block_client_impl/unblock_client_impl`,
`UnifiController::stamgr_cmd`

**Wire-in:**
- Add async socket commands `wifi_kick_client`, `wifi_block_client`,
  `wifi_unblock_client` to `socket/wifi.rs` async dispatcher
- Each takes `provider_id` + `mac` from request
- Add to `WEB_ALLOWED_METHODS`
- Add `client.rs` methods: `wifi_kick_client`, `wifi_block_client`,
  `wifi_unblock_client`
- Add server functions and action buttons to the WiFi clients table
- Remove `#[allow(dead_code)]` from trait + impls

## 2. WiFi AP Status

**Dead code:** `WifiDevice::get_status()`

**Wire-in:**
- Add async socket command `wifi_get_ap_status` (takes `provider_id` + `mac`)
- Returns `ApStatus` as JSON in `config_value`
- Add to `WEB_ALLOWED_METHODS`, client, and WiFi page (show model/firmware/uptime)
- Remove `#[allow(dead_code)]`

## 3. DNS Toggle Endpoints

**Dead code:** `Db::set_dns_forward_zone_enabled`,
`Db::set_dns_custom_rule_enabled`, `Db::set_dns_blocklist_enabled`

**Wire-in:**
- Add socket commands `set_dns_forward_enabled`, `set_dns_rule_enabled`,
  `set_dns_blocklist_item_enabled` (each takes `id` + `enabled`)
- After DB toggle, rebuild unbound config and reload
- Add to `WEB_ALLOWED_METHODS`
- Add client methods and toggle switches to DNS page
- Remove `#[allow(dead_code)]`

## 4. mDNS Group-Aware Query

**Dead code:** `ServiceRegistry::query()`, `ServiceRecord.device_mac`,
`ServiceRecord.ttl_secs`

**Wire-in:**
- Use `query()` in the mDNS proxy response path so proxied mDNS responses
  respect trust-group isolation (trusted sees iot+servers, iot sees trusted only)
- Fields `device_mac` and `ttl_secs` are used by the record lifecycle; remove
  `#[allow(dead_code)]` annotations only
- Remove `#[allow(dead_code)]` from `query()`

## 5. DoH Bypass Prevention

**Dead code:** `DOH_RESOLVER_IPS_V4`, `DOH_RESOLVER_IPS_V6`

**Wire-in:**
- In `nftables.rs`, when ad-blocking is enabled, generate rules blocking
  outbound TCP 443 + TCP 853 to these IPs
- Prevents DNS bypass via DoH/DoT to known public resolvers
- Remove `#[allow(dead_code)]`

## 6. UPnP Input Rule Cleanup

**Dead code:** `nftables::remove_upnp_input_rules()`

**Wire-in:**
- Call from `handle_set_upnp_config` when disabling UPnP (`value == "false"`)
- Eliminates the restart requirement for disabling UPnP
- Remove `#[allow(dead_code)]`

## 7. Simple Fixes

| Item | Action |
|------|--------|
| `ConntrackEvent.src_port` | Rename to `_src_port` (parsed but unused pending per-port analysis) |
| `WanLease` struct | Wire into `get_status` so WAN lease info is visible |
| `UnboundManager.listen_addr/listen_addr_v6` | Rename to `_listen_addr`/`_listen_addr_v6` |
| `PCP_UNSUPP_OPTION` | Delete (unused constant, other PCP codes defined inline) |

## Group A — Kept As-Is

The following dead code is L2 anti-spoofing scaffolding for Phase 20 and is
intentionally kept:

- `SwitchProvider::set_port_vlan`, `set_trunk_port`
- `MacTableEntry.vlan_id`
- `VendorProfile::render_set_access_port`, `render_set_trunk_port`
- `list_built_in_profiles()`
- `Db::set_vlan_config`, `is_vlan_mode_enabled`, `set_custom_vendor_profile`

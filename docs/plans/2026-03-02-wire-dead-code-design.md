# Wire In Dead Code — Design

All dead code in the repo falls into two groups: Group A (L2 anti-spoofing
scaffolding, kept as-is for Phase 20) and Group B (implemented but uncalled
features). This design covers wiring Group B into the active code paths and
removing all `#[allow(dead_code)]` annotations.

## 1. WiFi Client Management — Done

**Dead code:** `WifiProvider::kick_client/block_client/unblock_client`,
`EapSession::kick_client_impl/block_client_impl/unblock_client_impl`,
`UnifiController::stamgr_cmd`

**Result:** Added async socket commands `wifi_kick_client`, `wifi_block_client`,
`wifi_unblock_client`. Wired through async dispatcher, WEB_ALLOWED_METHODS,
client.rs, server functions, and WiFi page (Kick button per client row).
Removed all `#[allow(dead_code)]` from trait + impls.

## 2. WiFi AP Status — Done

**Dead code:** `WifiDevice::get_status()`

**Result:** Added async socket command `wifi_get_ap_status`. Returns
`ApStatus` JSON in `config_value`. Client method added. UI page integration
deferred (SSR complexity for per-AP async calls).

## 3. DNS Toggle Endpoints — Done

**Dead code:** `Db::set_dns_forward_zone_enabled`,
`Db::set_dns_custom_rule_enabled`, `Db::set_dns_blocklist_enabled`

**Result:** Added socket commands `set_dns_forward_enabled`,
`set_dns_rule_enabled`, `set_dns_blocklist_enabled`. Each toggles the DB
field, rebuilds unbound config, and reloads. Added client methods, server
functions, and toggle buttons (Enabled/Disabled) to all 3 DNS page tables.

## 4. mDNS Group-Aware Query — Removed as Duplicate

**Original plan:** Wire `ServiceRegistry::query()` into mDNS proxy path.

**Actual result:** Discovered `query()` is a duplicate of `query_full()` which
is already actively used by the mDNS proxy. The `query()` method returned
cloned `MdnsService` values while `query_full()` returns `&ServiceRecord`
references. Removed `query()` entirely. Prefixed `device_mac` and `ttl_secs`
fields with `_` (set during construction but not read after).

## 5. DoH Bypass Prevention — Removed as Duplicate

**Original plan:** Wire `DOH_RESOLVER_IPS_V4/V6` into nftables rules.

**Actual result:** Discovered these exact IPs are already hardcoded in the
nftables ruleset as `doh_block_v4` and `doh_block_v6` sets (nftables.rs
lines 126-134). The constants in unbound.rs were duplicates. Removed them to
avoid the lists going out of sync.

## 6. UPnP Input Rule Cleanup — Done

**Dead code:** `nftables::remove_upnp_input_rules()`

**Result:** Called from `handle_set_upnp_config` when disabling UPnP. Now
cleans up nftables rules immediately without requiring a restart. Enabling
still requires restart (daemon tasks need to start).

## 7. Simple Fixes — Done

| Item | Result |
|------|--------|
| `ConntrackEvent.src_port` | Renamed to `_src_port` |
| `WanLease` struct | Wired `ip`, `gateway`, `dns_servers` into `get_status` endpoint; prefixed remaining unused fields with `_` |
| `UnboundManager.listen_addr/listen_addr_v6` | Renamed to `_listen_addr`/`_listen_addr_v6` |
| `PCP_UNSUPP_OPTION` | Deleted |

## Group A — Kept As-Is

The following dead code is L2 anti-spoofing scaffolding for Phase 20 and is
intentionally kept (5 compiler warnings):

- `SwitchProvider::set_port_vlan`, `set_trunk_port`
- `MacTableEntry.vlan_id`
- `VendorProfile::render_set_access_port`, `render_set_trunk_port`
- `list_built_in_profiles()`
- `Db::set_vlan_config`, `is_vlan_mode_enabled`, `set_custom_vendor_profile`

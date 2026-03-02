# Replace SSH switch automation with SNMP read-only polling

## Problem

The current switch management code (~1,100 LOC) uses interactive SSH sessions
with regex-based CLI scraping to poll MAC tables from managed switches. This is
fragile: firmware updates change CLI output formats, prompt detection varies by
vendor/locale, and three separate vendor profiles (Cisco IOS, TP-Link T-series,
Netgear ProSafe) must be maintained. Write operations (set_port_vlan,
set_trunk_port, create_vlan) exist as dead code — scaffolding for automatic VLAN
provisioning that was never wired up.

## Decision

Replace SSH CLI scraping with SNMP v2c read-only polling using standard MIBs.
Drop all write operations. Manual switch VLAN configuration is the user's
responsibility.

Keep the router-side VLAN subsystem (vlan.rs, socket/vlan.rs, nftables VLAN
rules) unchanged.

## What gets removed

- `switch/ssh.rs` — SSH client, TOFU handler, CLI scraping (~476 LOC)
- `switch/vendor.rs` — vendor profiles, CLI templates, regex MAC parsing (~249 LOC)
- `socket/switch.rs` — all switch socket handlers (~393 LOC)
- `SwitchProvider` trait and `SshSwitchProvider` implementation
- `russh` workspace dependency
- DB tables: `switch_providers`, `switch_vendor_profiles`
- DB column: `devices.switch_id`
- Switch settings UI page (current form with SSH credentials)
- Switch-specific parts of integration test 55

## What gets kept

- `vlan.rs` — router-side VLAN subinterface creation/teardown (79 LOC)
- `socket/vlan.rs` — VLAN enable/disable/status handlers (106 LOC)
- `vlan_config` DB table with default group-to-VLAN mappings
- VLAN settings UI page
- `nftables::apply_base_rules_vlan()`
- `devices.switch_port` column (populated by SNMP instead of SSH)

## What gets added

### SNMP polling module (`switch/snmp.rs`, ~150-200 LOC)

SNMP v2c client using standard MIBs that every managed switch implements:

- `dot1dTpFdbTable` (BRIDGE-MIB) — MAC address to bridge port mapping
- `dot1dBasePortIfIndex` — bridge port to ifIndex mapping
- `ifName` / `ifDescr` (IF-MIB) — ifIndex to human-readable port name

No vendor profiles needed. The MIBs are IEEE/IETF standards.

### Simplified DB schema

Replace `switch_providers` and `switch_vendor_profiles` with:

```sql
CREATE TABLE snmp_switches (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    community_enc TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_seen INTEGER NOT NULL DEFAULT 0
);
```

Community string encrypted at rest using the existing crypto module.

Drop `devices.switch_id`. Keep `devices.switch_port`.

### Simplified socket API (~100 LOC)

- `switch_add` — store SNMP target (name, host, community string)
- `switch_remove` — delete by name or ID
- `switch_list` — list configured switches with status
- `switch_test` — SNMP GET `sysDescr.0` to verify connectivity

### Background polling loop

Same structure as current `switch::run()`:

1. Check if VLAN mode is enabled
2. For each enabled SNMP switch, walk `dot1dTpFdbTable`
3. Map bridge port → ifIndex → port name
4. Correlate discovered MACs with known devices
5. Update `devices.switch_port` in DB

### Rust dependency

Replace `russh` with a lightweight SNMP crate (e.g. `snmp` or `rasn-snmp`).
SNMP is UDP-based — no connection state, no PTY, no prompt detection.

### UI changes

Switch settings page simplifies to:
- Add/remove SNMP switch targets (name, host, community string)
- Test connectivity button
- Status indicator (connected/error/unknown)

Device detail page: "Port: Gi0/3 on Main Switch" (same display, SNMP-sourced).

## Comparison

| Aspect | SSH (current) | SNMP (proposed) |
|--------|---------------|-----------------|
| Vendor profiles | 3 regex-based, fragile | None (standard MIB) |
| Auth | SSH password + TOFU key | Community string |
| Dependencies | russh (async SSH, heavy) | snmp (UDP, lightweight) |
| Fragility | Firmware breaks CLI parsing | MIB is an IEEE standard |
| Code | ~1,100 LOC | ~300-400 LOC |
| Write support | Dead scaffolding | Intentionally omitted |
| MAC correlation | Regex per vendor | Standard OID walk |

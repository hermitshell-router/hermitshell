# L2 Anti-Spoofing: VLAN Microsegmentation + Rogue DHCP Blocking

## Problem

The current architecture isolates devices at L3 (nftables /32 rules, MAC-IP
validation, permanent ARP entries). This prevents most IP-level attacks but
leaves three L2 gaps:

1. **Rogue DHCP server** — a compromised LAN device can race the router and
   serve malicious leases to neighbors on the same switch segment.
2. **ARP spoofing between wired devices** — devices on the same switch can
   poison each other's ARP caches. The router never sees this traffic.
3. **ARP/DHCP spoofing between WiFi clients** — WiFi clients on the same AP
   can spoof at L2 unless the AP enforces client isolation.

## Solution

Three components, each closing one gap:

### Component 1: Rogue DHCP Server Blocking (nftables)

Add rules to drop DHCP server traffic (UDP source port 67) arriving from the
LAN interface. Only the router should originate DHCP offers.

Rules added to `apply_base_rules()` in the forward and input chains:

```
# Log then drop rogue DHCP server packets from LAN devices
iifname "{lan_iface}" udp sport 67 log prefix "ROGUE_DHCP " limit rate 1/second
iifname "{lan_iface}" udp sport 67 counter drop comment "block rogue DHCP server"
```

This blocks rogue DHCP traffic that passes through the router (cross-VLAN or
destined to the router). Same-segment rogue DHCP is addressed by component 3
(VLAN isolation at the switch).

### Component 2: Per-Trust-Group VLAN Segmentation

Assign each device group its own VLAN. Traffic between groups must route
through the router, where existing nftables policy applies.

#### VLAN Allocation

| Group      | VLAN ID | Subnet (default)  | Purpose                     |
|------------|---------|--------------------|-----------------------------|
| management | 1       | —                  | Switch/AP management (native) |
| trusted    | 10      | 10.0.10.0/24       | Full-access devices          |
| iot        | 20      | 10.0.20.0/24       | IoT, internet-only           |
| guest      | 30      | 10.0.30.0/24       | Guest, internet-only         |
| servers    | 40      | 10.0.40.0/24       | LAN servers                  |
| quarantine | 50      | 10.0.50.0/24       | New/untrusted (default)      |

VLAN IDs and subnets are configurable in the DB. Blocked devices get no VLAN
assignment (switch port disabled or moved to a dead VLAN).

#### Router-Side Changes

**VLAN subinterfaces on the LAN interface:**

```
ip link add link eth2 name eth2.10 type vlan id 10
ip addr add 10.0.10.1/24 dev eth2.10
ip link set eth2.10 up
# ... repeated for each VLAN
```

The base `eth2` interface remains up for untagged management traffic (VLAN 1).

**IP addressing migration:**

Current: flat 10.0.0.0/8 with /32 per device, gateway 10.0.0.1.
New: per-VLAN /24 subnets with /32 device addresses within each.

- Devices keep /32 point-to-point addressing within their VLAN subnet.
- Gateway per VLAN is x.x.x.1 (e.g., 10.0.10.1 for trusted).
- `compute_subnet()` updated to allocate from the correct VLAN range based on
  device group.
- Migration: on upgrade, existing devices are reassigned IPs within their
  group's VLAN subnet. DHCP lease renewal handles the transition.

**nftables changes:**

- `mac_ip_validate` chain: rules now also match on input interface
  (`iifname "eth2.{vlan}"`) for defense-in-depth. A device in VLAN 20 sending
  traffic on eth2.10 is dropped.
- `device_groups_v4` map: unchanged, still routes by source IP to group chain.
- Per-group forward chains: unchanged.
- New: input chain accepts DHCP (port 67) on each VLAN subinterface.

**DHCP changes:**

- DHCP server binds to each VLAN subinterface.
- Each interface serves its VLAN's subnet range.
- MAC-to-IP binding unchanged (permanent per device).
- When a device changes group, it gets a new IP in the new VLAN range. The old
  lease is NAK'd on renewal, forcing the client to re-DHCPDISCOVER on the new
  VLAN.

#### WiFi AP Changes

One SSID per trust group, each tagged with the corresponding VLAN:

| SSID          | VLAN | Group      |
|---------------|------|------------|
| HomeNet       | 10   | trusted    |
| IoT           | 20   | iot        |
| Guest         | 30   | guest      |

Configuration via existing `WifiProvider` trait:

- Add `set_ssid_vlan(ssid_name: &str, vlan_id: u16) -> Result<()>` method.
- EAP720: SSID VLAN tagging via wireless.ssids.json `vlanId` field.
- UniFi: SSID VLAN via WLAN config `networkconf_id` or `vlan` field.
- Default: when VLAN mode is enabled, auto-configure SSID-to-VLAN mapping for
  all existing SSIDs that match group names.

New devices connecting to any SSID land in the mapped VLAN and get quarantine
treatment until classified.

### Component 3: Managed Switch Integration (SSH)

SSH into managed switches to assign per-port VLANs and configure the trunk
uplink to the router.

#### SwitchProvider Trait

```rust
#[async_trait]
pub trait SwitchProvider: Send + Sync {
    /// Test connectivity and authentication.
    async fn ping(&self) -> Result<()>;

    /// List physical ports with status and current VLAN.
    async fn list_ports(&self) -> Result<Vec<SwitchPort>>;

    /// Set the access VLAN on a port.
    async fn set_port_vlan(&self, port: &str, vlan_id: u16) -> Result<()>;

    /// Get the MAC address table (port -> Vec<MAC>).
    async fn get_mac_table(&self) -> Result<Vec<MacTableEntry>>;

    /// Configure a port as a trunk (uplink to router).
    async fn set_trunk_port(&self, port: &str, allowed_vlans: &[u16]) -> Result<()>;

    /// Create a VLAN on the switch.
    async fn create_vlan(&self, vlan_id: u16, name: &str) -> Result<()>;

    /// Save running config to startup config.
    async fn save_config(&self) -> Result<()>;
}

pub struct SwitchPort {
    pub name: String,         // e.g., "GigabitEthernet0/1"
    pub status: PortStatus,   // Up, Down, Disabled
    pub vlan_id: Option<u16>, // Current access VLAN
    pub is_trunk: bool,
    pub macs: Vec<String>,    // MACs learned on this port
}

pub struct MacTableEntry {
    pub mac: String,
    pub vlan_id: u16,
    pub port: String,
}
```

#### SSH Implementation

Use the `russh` crate for async SSH connections.

**Vendor profiles** stored in DB with built-in defaults:

```json
{
  "vendor": "cisco_ios",
  "commands": {
    "create_vlan": "vlan {vlan_id}\n name {name}",
    "set_access_port": "interface {port}\n switchport mode access\n switchport access vlan {vlan_id}",
    "set_trunk_port": "interface {port}\n switchport mode trunk\n switchport trunk allowed vlan {vlans}",
    "get_mac_table": "show mac address-table",
    "get_ports": "show interfaces status",
    "save_config": "write memory",
    "enter_config": "configure terminal",
    "exit_config": "end"
  },
  "prompt_pattern": "[#>]\\s*$",
  "config_prompt_pattern": "\\(config[^)]*\\)#\\s*$",
  "mac_table_regex": "\\s+(\\d+)\\s+([0-9a-fA-F.:-]+)\\s+\\S+\\s+(\\S+)"
}
```

Built-in profiles shipped for:
- **Cisco IOS** (Catalyst, SG series)
- **TP-Link T-series** (managed switches)
- **Netgear ProSafe** (managed switches)

Users can add custom profiles for other vendors via the web UI.

**Connection management:**
- One SSH session per switch, reconnect on failure with exponential backoff.
- Credentials stored encrypted (same pattern as WiFi providers).
- TOFU host key pinning (same pattern as WiFi TLS cert pinning).

#### Device-to-Port Mapping

Correlate switch MAC table with known device MACs from DHCP:

1. Poll switch MAC table every 60 seconds (same interval as WiFi polling).
2. Match MACs against device DB.
3. Store port assignment per device in DB.
4. When a device changes group, SSH to switch and change the port's access VLAN.
5. The router's uplink port is user-designated as trunk and never modified for
   access VLAN.

#### Automatic VLAN Provisioning

When VLAN mode is first enabled:
1. SSH to switch, create VLANs 10/20/30/40/50.
2. Configure the user-designated uplink port as trunk with all VLANs allowed.
3. Query MAC table, map known devices to ports.
4. Set each port's access VLAN based on the device's current group.
5. Unrecognized ports stay on VLAN 50 (quarantine).

When a device changes group (e.g., quarantine -> iot):
1. Agent updates device group in DB.
2. Agent SSHs to switch, changes port VLAN.
3. Agent updates DHCP: device gets new IP in new VLAN range on next renewal.
4. Old IP/route/nftables rules cleaned up; new ones installed.

#### Background Polling

Same pattern as WiFi module:
- 60-second poll interval.
- Sync port state and MAC table.
- Detect manual changes (someone changed a VLAN on the switch directly) and
  log a warning.
- Update device-to-port mapping as devices move.

### Web UI

**Settings > Network > Switches:**
- Add switch: hostname/IP, SSH port, credentials, vendor profile (dropdown).
- Test connection button (calls `ping()`).
- Per-switch port view: port name, link status, assigned VLAN/group, connected
  device (from MAC table correlation).
- Designate uplink port(s).

**Settings > Network > VLANs:**
- Enable/disable VLAN mode (off by default for backward compatibility).
- VLAN ID and subnet mapping table (editable).
- Status: which VLANs are active on which switches.

**Device detail page:**
- Show current VLAN, switch port, and group.
- Group change triggers automatic VLAN reassignment.

### Security Considerations

**Switch credential storage:** Encrypted with session_secret, same as WiFi
provider credentials.

**SSH host key pinning:** TOFU model — first connection records the host key,
subsequent connections reject mismatches. Stored in DB per switch.

**Fallback:** If SSH to switch fails, device isolation still enforced at L3 by
existing nftables rules. VLAN mode is defense-in-depth, not a replacement for
L3 policy. Log warnings when switch is unreachable.

**Management VLAN:** Switch management interface stays on VLAN 1 (native).
Router can reach switch management IP for SSH. Consider restricting VLAN 1 to
router-only access.

### Migration and Backward Compatibility

VLAN mode is **opt-in** (disabled by default). The current flat L2 + L3
isolation continues to work for users without managed switches.

When enabled:
1. Create VLAN subinterfaces on router.
2. Provision VLANs on switch via SSH.
3. Reassign device IPs to per-VLAN subnets.
4. Configure AP SSID-to-VLAN mapping.
5. Existing nftables rules adapt to new subinterfaces.

Disabling VLAN mode reverses the process: remove subinterfaces, reset switch
ports to VLAN 1, reassign devices to flat 10.0.0.x range.

### Testing

- **Component 1:** Integration test — LAN device sends UDP sport 67; verify
  drop + log entry.
- **Component 2:** Unit tests for VLAN subinterface creation, IP allocation
  per VLAN, nftables rule generation with VLAN interfaces. Integration test
  with router VM (create subinterfaces, verify routing between VLANs).
- **Component 3:** Unit tests for SSH command generation per vendor profile,
  MAC table parsing. Integration testing requires a managed switch or mock SSH
  server.

### Dependencies

- `russh` crate — async SSH client for switch management.
- No new system packages required on the router (VLAN subinterfaces use
  standard `ip link` commands, already available).
- NixOS provisioning: add `8021q` kernel module load if not already present.

### Open Questions

None — all design decisions resolved during brainstorming.

# Configuration Reference

Complete TOML schema reference for `hermitshell.toml` and
`hermitshell.secrets.toml`.

The config file is the single source of truth for the router's desired state.
Apply it with [`hermitctl apply`](hermitctl.md#apply) -- the agent converges
the running system to match.

---

## File Locations

| File | Default Path |
|------|-------------|
| Main config | `/etc/hermitshell/hermitshell.toml` |
| Secrets | `/etc/hermitshell/hermitshell.secrets.toml` |

The secrets file holds passwords, private keys, and API tokens. Keep it
`chmod 600` and never commit it to version control.

---

## \[network\]

Top-level network settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `wan_interface` | string | -- | WAN interface name (1-15 chars, alphanumeric/dash/dot/underscore) |
| `lan_interface` | string | -- | LAN interface name (same rules) |
| `hostname` | string | -- | Router hostname |
| `timezone` | string | -- | IANA timezone (e.g. `America/New_York`) |
| `upstream_dns` | string[] | `[]` | Upstream DNS servers; empty = recursive mode |

### \[network.wan\]

WAN connection mode.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `"dhcp"` | `"dhcp"`, `"static"`, or `"pppoe"` |
| `address` | string | -- | Static IP with prefix (required when `mode = "static"`) |
| `gateway` | string | -- | Default gateway (required when `mode = "static"`) |

```toml
[network]
wan_interface = "eth0"
lan_interface = "eth1"
hostname = "hermit"
timezone = "America/New_York"
upstream_dns = ["1.1.1.1", "9.9.9.9"]

[network.wan]
mode = "dhcp"
```

---

## \[dns\]

DNS resolver and ad blocking settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ad_blocking` | bool | `true` | Enable DNS-based ad blocking |
| `ratelimit_per_second` | u32 | -- | Per-client DNS query rate limit (queries/sec) |

### \[\[dns.blocklists\]\]

Ad/tracker blocklist sources. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Display name (1-128 chars) |
| `url` | string | *required* | HTTPS URL to hosts/domain list |
| `tag` | string | `"ads"` | `"ads"`, `"custom"`, or `"strict"` |
| `enabled` | bool | `true` | Whether this list is active |

### \[\[dns.forward\_zones\]\]

Forward DNS queries for specific domains to a designated resolver. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `domain` | string | *required* | Domain to match (e.g. `corp.example.com`) |
| `forward_to` | string | *required* | IP address of the upstream resolver |
| `enabled` | bool | `true` | Whether this zone is active |

### \[\[dns.custom\_records\]\]

Static DNS records served by the local resolver. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `domain` | string | *required* | Fully qualified domain name |
| `type` | string | *required* | `"A"`, `"AAAA"`, `"CNAME"`, `"MX"`, or `"TXT"` |
| `value` | string | *required* | Record value |
| `enabled` | bool | `true` | Whether this record is active |

### \[dns.bypass\_allowed\]

Per-group toggles that allow devices in a group to use their own DNS servers
instead of the router's resolver. All default to `false`.

| Key | Type | Default |
|-----|------|---------|
| `trusted` | bool | `false` |
| `guest` | bool | `false` |
| `quarantine` | bool | `false` |
| `iot` | bool | `false` |
| `servers` | bool | `false` |

```toml
[dns]
ad_blocking = true
ratelimit_per_second = 100

[[dns.blocklists]]
name = "StevenBlack Unified"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
tag = "ads"

[[dns.forward_zones]]
domain = "corp.example.com"
forward_to = "10.0.0.53"

[[dns.custom_records]]
domain = "nas.home"
type = "A"
value = "10.19.0.50"

[dns.bypass_allowed]
servers = true
```

---

## \[firewall\]

Firewall, port forwarding, and IPv6 pinhole settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dmz_host` | string | -- | IPv4 address to receive all unsolicited inbound traffic |
| `upnp_enabled` | bool | -- | Enable UPnP/NAT-PMP/PCP automatic port mapping |

### \[\[firewall.port\_forwards\]\]

Static port forwarding rules. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `protocol` | string | `"both"` | `"tcp"`, `"udp"`, or `"both"` |
| `external_port` | u16 | *required* | External port (must be > 0) |
| `external_port_end` | u16 | -- | End of port range (omit for single port) |
| `internal_ip` | string | *required* | Destination IPv4 address on LAN |
| `internal_port` | u16 | *required* | Destination port |
| `enabled` | bool | `true` | Whether this rule is active |
| `description` | string | `""` | Human-readable label (max 256 chars) |

### \[\[firewall.ipv6\_pinholes\]\]

Allow inbound IPv6 traffic to specific devices. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `device` | string | *required* | MAC address of the target device |
| `protocol` | string | *required* | `"tcp"` or `"udp"` |
| `port_start` | u16 | *required* | Start of port range |
| `port_end` | u16 | -- | End of port range (omit for single port) |
| `description` | string | `""` | Human-readable label |

```toml
[firewall]
upnp_enabled = false

[[firewall.port_forwards]]
protocol = "tcp"
external_port = 443
internal_ip = "10.19.0.50"
internal_port = 443
description = "HTTPS to NAS"

[[firewall.ipv6_pinholes]]
device = "AA:BB:CC:DD:EE:FF"
protocol = "tcp"
port_start = 443
description = "HTTPS to server"
```

---

## \[wireguard\]

WireGuard VPN server settings. The agent manages the `wg0` interface directly.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable the WireGuard VPN server |
| `listen_port` | u16 | `51820` | UDP listen port (must be > 0) |

### \[\[wireguard.peers\]\]

VPN peers. Each peer gets a /30 subnet like a LAN device. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Peer display name (1-64 chars) |
| `public_key` | string | *required* | Base64-encoded WireGuard public key (44 chars with `=` padding) |
| `device_group` | string | `"trusted"` | `"trusted"`, `"iot"`, `"guest"`, `"servers"`, or `"quarantine"` |
| `enabled` | bool | `true` | Whether this peer is active |

```toml
[wireguard]
enabled = true
listen_port = 51820

[[wireguard.peers]]
name = "laptop"
public_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
device_group = "trusted"
```

---

## \[\[devices\]\]

Known network devices. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mac` | string | *required* | MAC address (`XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX`) |
| `hostname` | string | -- | DHCP or mDNS hostname |
| `nickname` | string | -- | User-assigned friendly name |
| `group` | string | `"quarantine"` | `"trusted"`, `"iot"`, `"guest"`, `"servers"`, or `"quarantine"` |

```toml
[[devices]]
mac = "AA:BB:CC:DD:EE:01"
nickname = "Living Room TV"
group = "iot"

[[devices]]
mac = "AA:BB:CC:DD:EE:02"
nickname = "NAS"
group = "servers"
```

---

## \[dhcp\]

### \[\[dhcp.reservations\]\]

DHCP address reservations. Each reservation binds a MAC address to a
specific subnet ID (and therefore a fixed IP). Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mac` | string | *required* | MAC address |
| `subnet_id` | i64 | *required* | Subnet slot ID (>= 0) |

```toml
[[dhcp.reservations]]
mac = "AA:BB:CC:DD:EE:01"
subnet_id = 50
```

---

## \[qos\]

Quality of service / traffic shaping.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable QoS traffic shaping |
| `upload_mbps` | u32 | `0` | Upload bandwidth cap in Mbps (required > 0 when enabled) |
| `download_mbps` | u32 | `0` | Download bandwidth cap in Mbps (required > 0 when enabled) |

When `enabled = true`, both `upload_mbps` and `download_mbps` must be greater
than zero.

```toml
[qos]
enabled = true
upload_mbps = 50
download_mbps = 500
```

---

## \[logging\]

Log output and retention settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"text"` | `"text"` or `"json"` |
| `retention_days` | u32 | `7` | Days to retain logs in the database |
| `syslog_target` | string | -- | Remote syslog destination (`host:port`) |
| `webhook_url` | string | -- | HTTPS URL for alert webhook delivery |

```toml
[logging]
format = "json"
retention_days = 30
syslog_target = "syslog.example.com:514"
webhook_url = "https://hooks.example.com/hermitshell"
```

---

## \[tls\]

TLS certificate mode for the web UI.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `"self_signed"` | Certificate strategy (see below) |

**Modes:**

| Mode | Description |
|------|-------------|
| `self_signed` | Auto-generated self-signed certificate (default) |
| `custom` | User-provided certificate and key (set in secrets file) |
| `tailscale` | Obtain certificate from Tailscale HTTPS integration |
| `acme_dns01` | ACME DNS-01 challenge via Cloudflare API |

```toml
[tls]
mode = "acme_dns01"
```

---

## \[analysis\]

Behavioral traffic analysis and alerting.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable the analysis engine |

### \[analysis.alert\_rules\]

Individual alert rule toggles. When omitted, the engine uses its built-in
defaults.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dns_beaconing` | bool | -- | Detect periodic DNS callbacks (C2 beaconing) |
| `dns_volume_spike` | bool | -- | Detect sudden DNS query volume increases |
| `new_dest_spike` | bool | -- | Detect bursts of connections to new destinations |
| `suspicious_ports` | bool | -- | Detect traffic on suspicious port numbers |
| `bandwidth_spike` | bool | -- | Detect abnormal bandwidth usage |

```toml
[analysis]
enabled = true

[analysis.alert_rules]
dns_beaconing = true
suspicious_ports = true
bandwidth_spike = false
```

---

## \[wifi\]

### \[\[wifi.providers\]\]

WiFi access point controllers/connections. Repeatable.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | *required* | Provider display name (1-64 chars) |
| `type` | string | *required* | `"eap_standalone"` (TP-Link EAP) or `"unifi"` (UniFi Controller) |
| `url` | string | *required* | Base URL of the controller or AP |
| `enabled` | bool | `true` | Whether this provider is active |
| `site` | string | -- | UniFi site name (default: `"default"`) |
| `username` | string | -- | Login username (default: `"admin"`) |

Credentials (passwords, API keys) are stored in the secrets file, not here.

```toml
[[wifi.providers]]
name = "Office APs"
type = "unifi"
url = "https://192.168.1.1"
site = "default"
username = "admin"

[[wifi.providers]]
name = "Garage AP"
type = "eap_standalone"
url = "http://192.168.1.85"
```

---

## Secrets File

`hermitshell.secrets.toml` holds all sensitive values. It is loaded separately
with `hermitctl apply --secrets`.

### Top-level Keys

| Key | Type | Description |
|-----|------|-------------|
| `admin_password_hash` | string | Argon2id hash of the web UI admin password |
| `session_secret` | string | HMAC key for session cookies |
| `wg_private_key` | string | WireGuard server private key (base64) |

### \[tls\]

| Key | Type | Description |
|-----|------|-------------|
| `key_pem` | string | PEM-encoded private key (for `mode = "custom"`) |
| `cert_pem` | string | PEM-encoded certificate chain (for `mode = "custom"`) |
| `acme_cf_api_token` | string | Cloudflare API token (for `mode = "acme_dns01"`) |
| `acme_account_key` | string | ACME account private key (auto-generated if absent) |

### \[integrations\]

| Key | Type | Description |
|-----|------|-------------|
| `runzero_token` | string | runZero export API token for device fingerprinting |
| `webhook_secret` | string | HMAC secret for signing webhook payloads |

### \[\[wifi.providers\]\]

Matched to main config entries by `name`. Repeatable.

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Must match a `[[wifi.providers]]` entry in the main config |
| `password` | string | Login password (for password-based auth) |
| `api_key` | string | API key (for UniFi API key auth) |

```toml
# hermitshell.secrets.toml

admin_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
session_secret = "random-256-bit-hex-string"
wg_private_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

[tls]
acme_cf_api_token = "cf-api-token-here"

[integrations]
runzero_token = "rz-token-here"
webhook_secret = "webhook-hmac-secret"

[[wifi.providers]]
name = "Office APs"
password = "unifi-password"
```

---

## Validation Rules

The agent validates the config before applying. `hermitctl validate` runs the
same checks offline.

### Format Rules

| Rule | Detail |
|------|--------|
| Interface names | 1-15 chars; alphanumeric, dash, dot, underscore only |
| MAC addresses | `XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX` (hex digits) |
| WireGuard keys | Standard base64, exactly 44 chars, must end with `=` |
| Blocklist/webhook URLs | Must be HTTPS; private/internal IPs rejected (SSRF protection) |
| Device groups | Must be one of: `trusted`, `iot`, `guest`, `servers`, `quarantine` |
| DNS record types | Must be one of: `A`, `AAAA`, `CNAME`, `MX`, `TXT` |
| Blocklist tags | Must be one of: `ads`, `custom`, `strict` |
| WAN mode | Must be one of: `dhcp`, `static`, `pppoe` |
| TLS mode | Must be one of: `self_signed`, `custom`, `tailscale`, `acme_dns01` |
| Port forward protocol | Must be one of: `tcp`, `udp`, `both` |
| IPv6 pinhole protocol | Must be one of: `tcp`, `udp` |

### Size Limits

| Resource | Maximum |
|----------|---------|
| Devices | 10,000 |
| Port forwards | 1,000 |
| IPv6 pinholes | 1,000 |
| WiFi providers | 100 |
| Blocklist name | 128 chars |
| Peer name | 64 chars |
| WiFi provider name | 64 chars |
| Port forward description | 256 chars |

### Conditional Rules

- `network.wan.address` and `network.wan.gateway` are required when
  `network.wan.mode = "static"`.
- `qos.upload_mbps` and `qos.download_mbps` must both be > 0 when
  `qos.enabled = true`.
- `wireguard.listen_port` must be > 0.
- `firewall.port_forwards[].external_port` must be > 0.

---

## Minimal Example

The smallest useful config -- just network, DNS, and TLS:

```toml
[network]
wan_interface = "eth0"
lan_interface = "eth1"
hostname = "hermit"

[network.wan]
mode = "dhcp"

[dns]
ad_blocking = true

[tls]
mode = "self_signed"
```

---

## Full Example

A config with every section populated:

```toml
[network]
wan_interface = "eth0"
lan_interface = "eth1"
hostname = "hermit"
timezone = "America/New_York"
upstream_dns = ["1.1.1.1", "9.9.9.9"]

[network.wan]
mode = "dhcp"

[dns]
ad_blocking = true
ratelimit_per_second = 100

[[dns.blocklists]]
name = "StevenBlack Unified"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
tag = "ads"

[[dns.blocklists]]
name = "Strict Privacy"
url = "https://example.com/strict-list.txt"
tag = "strict"
enabled = false

[[dns.forward_zones]]
domain = "corp.example.com"
forward_to = "10.0.0.53"

[[dns.custom_records]]
domain = "nas.home"
type = "A"
value = "10.19.0.50"

[[dns.custom_records]]
domain = "printer.home"
type = "A"
value = "10.19.0.51"

[dns.bypass_allowed]
servers = true

[firewall]
upnp_enabled = false

[[firewall.port_forwards]]
protocol = "tcp"
external_port = 443
internal_ip = "10.19.0.50"
internal_port = 443
description = "HTTPS to NAS"

[[firewall.port_forwards]]
protocol = "udp"
external_port = 51820
internal_ip = "10.19.0.1"
internal_port = 51820
description = "WireGuard"

[[firewall.ipv6_pinholes]]
device = "AA:BB:CC:DD:EE:02"
protocol = "tcp"
port_start = 443
description = "HTTPS to server"

[wireguard]
enabled = true
listen_port = 51820

[[wireguard.peers]]
name = "laptop"
public_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
device_group = "trusted"

[[wireguard.peers]]
name = "phone"
public_key = "enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmEwOTg3NjU="
device_group = "trusted"

[[devices]]
mac = "AA:BB:CC:DD:EE:01"
nickname = "Living Room TV"
group = "iot"

[[devices]]
mac = "AA:BB:CC:DD:EE:02"
nickname = "NAS"
group = "servers"

[[devices]]
mac = "AA:BB:CC:DD:EE:03"
hostname = "printer"
group = "iot"

[[dhcp.reservations]]
mac = "AA:BB:CC:DD:EE:02"
subnet_id = 50

[qos]
enabled = true
upload_mbps = 50
download_mbps = 500

[logging]
format = "json"
retention_days = 30
syslog_target = "syslog.example.com:514"
webhook_url = "https://hooks.example.com/hermitshell"

[tls]
mode = "acme_dns01"

[analysis]
enabled = true

[analysis.alert_rules]
dns_beaconing = true
dns_volume_spike = true
new_dest_spike = true
suspicious_ports = true
bandwidth_spike = false

[[wifi.providers]]
name = "Office APs"
type = "unifi"
url = "https://192.168.1.1"
site = "default"
username = "admin"

[[wifi.providers]]
name = "Garage AP"
type = "eap_standalone"
url = "http://192.168.1.85"
```

# HermitShell

**Your router, your rules. No cloud, no controller, no surprises.**

A modern, open-source router platform for people who want Ubiquiti-level features without the Ubiquiti headaches. Runs on commodity hardware, configured directly on the device—no external controller, no cloud account, no adoption ceremony.

---

## 1. Overview

### 1.1 Why HermitShell?

**The Ubiquiti problem:**

You bought a UniFi router because the hardware is good and affordable. Then you discovered:

- You need a separate controller (Cloud Key, self-hosted, or their cloud) just to configure it
- Controller updates break things on a different schedule than device updates
- The "adoption" workflow is designed for MSPs managing hundreds of sites, not your home
- Features disappear between versions without warning
- The UI keeps getting rewritten, removing functionality each time
- SSH access feels like an afterthought
- Despite "local" marketing, it's increasingly cloud-dependent

**What you actually want:**

- Configure the device directly—web UI runs on the router itself
- Device works standalone, no external dependencies
- Settings don't reset or migrate poorly between versions
- Standard Linux underneath—SSH in, `tcpdump`, debug like a normal system
- No cloud account required, no phoning home
- Backup is `cp hermitshell.db somewhere-safe/`

**HermitShell delivers this.** It runs on:

| Hardware | Cost | Notes |
|----------|------|-------|
| Mini PCs (N100 boxes) | ~$150 | Best balance of performance/cost |
| Old laptop + USB ethernet | Free | Repurpose what you have |
| Raspberry Pi 4/5 + USB ethernet | ~$80 | Lower power, sufficient for most homes |
| Thin clients (Dell Wyse, HP t620/t730) | ~$50 used | Fanless, reliable |
| Any x86 box with 2 NICs | Varies | If it runs Debian, it runs HermitShell |

Escape the proprietary software trap without buying new proprietary hardware.

### 1.2 Features

- **Device discovery and approval** - New devices quarantined until approved
- **True device isolation** - Each device gets its own /30 subnet, no special hardware needed
- **Group-based policy** - Trusted, IoT, Guest, Servers, Quarantine with configurable inter-group rules
- **Traffic visibility** - Per-device bandwidth, connection logs, DNS queries
- **Privacy-focused DNS** - DNSSEC validation, DNS-over-TLS upstream, optional ad blocking
- **Modern stack** - systemd-networkd, nftables, Unbound—no legacy iptables or dnsmasq sprawl
- **Direct configuration** - Web UI runs on the router, no external controller
- **Standard Linux** - SSH in, poke around, `tcpdump`, export to syslog, integrate with your tools
- **API-first** - Everything the UI does is available via REST API (enables Ansible, Terraform, scripts)

### 1.3 How It Compares

| | HermitShell | Ubiquiti UniFi | pfSense/OPNsense | OpenWrt | Firewalla |
|---|---|---|---|---|---|
| **Controller required** | No | Yes | No | No | No |
| **Cloud account** | No | Optional but pushed | No | No | Optional |
| **Runs on commodity HW** | Yes | No (locked to their HW) | Yes | Yes | No (their HW only) |
| **Device-centric UI** | Yes | Network-centric | Network-centric | Network-centric | Yes |
| **Per-device isolation** | Yes (default) | Requires VLANs | Requires VLANs | Requires VLANs | Partial |
| **Works with dumb switch** | Yes | Partial | Partial | Partial | Yes |
| **Learning curve** | Low | Medium | High | High | Low |
| **Open source** | Yes | No | Yes | Yes | No |
| **Price** | Free + your HW | $$ + their HW | Free + your HW | Free + your HW | $$$ (HW bundle) |

**Why not pfSense/OPNsense?**

Great software, but designed for network engineers. The UI assumes you know what a VLAN is, why you'd want one, and how to configure it. For most home users, that's complexity they don't need—HermitShell gives you isolation by default without the learning curve.

**Why not OpenWrt?**

Targets embedded devices with limited resources. The LuCI interface shows its age. Package management is fragile. Great for hacking on a cheap router; less great as a reliable home gateway on real hardware.

**Why not Firewalla?**

Solid product, but you're locked to their hardware and their update schedule. HermitShell gives you similar functionality on hardware you control.

### 1.4 Requirements

It runs on any Linux host with two NICs (WAN + LAN). The web UI and API run in Docker; the network stack (nftables, systemd-networkd) runs on the host for performance and reliability.

**What you need:**

| Requirement | Details |
|-------------|---------|
| Linux host | Debian 12+, Ubuntu 22.04+, or similar with systemd |
| Two NICs | One for WAN (ISP), one for LAN (your devices) |
| Docker | For the web UI container |
| Any switch | Dumb/unmanaged is fine—no VLAN support needed |
| Any WiFi AP | Consumer-grade is fine—no special features needed |

**What you DON'T need:**

| NOT Required | Why |
|--------------|-----|
| Managed switch | Per-device subnets work at L3, no VLAN tagging needed |
| VLAN-capable WiFi AP | Isolation happens at IP layer, not WiFi layer |
| AP client isolation | Devices are on different subnets, can't reach each other directly |
| Multiple SSIDs | All devices can be on one SSID; they're isolated by subnet |
| Enterprise hardware | Works with consumer-grade networking equipment |

**Key assumption: HermitShell is the only router on your LAN.**

All LAN devices must get their IP address from HermitShell. If you have another router/DHCP server on the LAN, devices may get addresses that bypass our per-device subnet model.

**How isolation works (and why it doesn't need special hardware):**

1. Each device gets a unique /30 subnet (e.g., Device A: 10.0.1.2/30, Device B: 10.0.2.2/30)
2. Devices see only their gateway—from their perspective, they're alone on their subnet
3. Device A wants to reach Device B → A checks "is 10.0.2.2 on my /30?" → No → sends to gateway
4. HermitShell receives traffic, applies policy (allow/deny), forwards or drops
5. Even on the same switch or WiFi AP, devices won't ARP for each other—different subnets

This works because IP routing, not L2 switching, determines reachability. No special hardware cooperation required.

**What this breaks (intentionally):**

- **mDNS/Bonjour discovery** - Devices can't auto-discover each other (can be selectively enabled)
- **LAN broadcast games** - Old games that use broadcast won't work across devices
- **Wake-on-LAN** - Requires explicit configuration to allow

These are security features. The default is isolation; connectivity is opt-in.

**Installation:**
```bash
git clone https://github.com/youruser/hermitshell
cd hermitshell
docker compose up -d
# Open http://router-ip:8080, complete setup via UI
```

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Linux Host                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Docker Network (bridge)                   │    │
│  │                                                              │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │              hermitshell (API + web UI)              │   │    │
│  │  │                       :8080                          │   │    │
│  │  └──────────────────────────┬───────────────────────────┘   │    │
│  │                             │                                │    │
│  └─────────────────────────────┼────────────────────────────────┘    │
│                                │ unix socket                         │
│  ══════════════════════════════╪════════════════════════════════    │
│                        HOST SERVICES                                 │
│  ═══════════════════════════════════════════════════════════════    │
│                                │                                     │
│  ┌─────────────────────────────┴───────────────────────────────┐    │
│  │                    hermitshell-agent                         │    │
│  │  • Applies nftables rules    • Reads traffic counters       │    │
│  │  • Streams conntrack events  • Per-device isolation rules   │    │
│  │  • Generates systemd configs • DNS query logging (nflog)    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌──────────────┐  ┌───────────────────────────┐  ┌──────────────┐  │
│  │   nftables   │  │      systemd-networkd     │  │   systemd-   │  │
│  │  (firewall)  │  │  (interfaces + DHCP srv)  │  │   resolved   │  │
│  │  + counters  │  │                           │  │  (DNS + DoT) │  │
│  │  + nflog     │  │                           │  │              │  │
│  └──────────────┘  └───────────────────────────┘  └──────────────┘  │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│  eth0 (WAN - DHCP from ISP)                    eth1 (LAN)           │
└───────┬─────────────────────────────────────────────────────────────┘
        │                                     │
        ▼                                     ▼
    Internet                            Switch / WiFi AP
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                   ▼
                              WiFi devices       Wired devices
                           (each own /30)     (each own /30)
```

**Network topology:** Each device gets its own /30 subnet. From the device's perspective, it's alone on its network with only the gateway. This forces all traffic through HermitShell, enabling policy enforcement without requiring VLANs, managed switches, or AP cooperation.

### 2.1 Components

| Component | Runs On | Purpose |
|-----------|---------|---------|
| **hermitshell** | Docker | Web UI, REST API, device management, rule generation |
| **hermitshell-agent** | Host | Applies configs, reads counters, streams events, DNS logging |
| **systemd-networkd** | Host | Interface management (addresses, routing) |
| **dnsmasq** | Host | DHCP server (per-device subnet assignment) |
| **systemd-resolved** | Host | DNS resolver with DoT upstream, DNSSEC, caching |
| **nftables** | Host (kernel) | Firewall, NAT, per-device traffic counters, routing policy |
| **conntrack** | Host (kernel) | Connection tracking for flow logs |
| **vnstat** | Host | Interface-level bandwidth statistics |

### 2.2 Per-Device Subnet Isolation

HermitShell provides true device isolation without requiring VLANs, managed switches, or AP cooperation.

**How it works:**

1. **Unique /30 subnet per device** - Each device gets its own network (e.g., 10.0.1.0/30)
2. **Device sees only the gateway** - From the device's perspective, it's alone with 10.0.1.1 (gateway)
3. **All traffic routes through HermitShell** - Devices can't ARP for each other (different subnets)
4. **Policy at routing layer** - nftables decides what forwarding is allowed

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Per-Device Subnet Model                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │    Laptop    │  │    Phone     │  │    Camera    │               │
│  │  10.0.1.2/30 │  │  10.0.2.2/30 │  │  10.0.3.2/30 │               │
│  │  gw: 10.0.1.1│  │  gw: 10.0.2.1│  │  gw: 10.0.3.1│               │
│  │   TRUSTED    │  │   TRUSTED    │  │     IOT      │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                 │                        │
│         │    Different subnets = no direct communication             │
│         │    All traffic MUST go through gateway                     │
│         ▼                 ▼                 ▼                        │
│  ═══════════════════════════════════════════════════════════════    │
│              HermitShell (all gateway addresses)                     │
│              10.0.1.1, 10.0.2.1, 10.0.3.1, ... on br0                │
│  ═══════════════════════════════════════════════════════════════    │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    nftables (routing policy)                 │    │
│  ├─────────────────────────────────────────────────────────────┤    │
│  │ Laptop (10.0.1.2) → Phone (10.0.2.2): ✓ (both TRUSTED)      │    │
│  │ Laptop (10.0.1.2) → Camera (10.0.3.2): ✓ (TRUSTED can init) │    │
│  │ Camera (10.0.3.2) → Laptop (10.0.1.2): ✗ (IOT can't init)   │    │
│  │ Camera (10.0.3.2) → Internet: ✓                              │    │
│  │ Any device → mDNS broadcast: ✗ (blocked by default)         │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Why this is better than MAC-based firewall rules:**

| Approach | Same-switch traffic | Same-AP wireless | Requires special hardware |
|----------|---------------------|------------------|---------------------------|
| MAC-based rules | Can bypass via L2 | Can bypass | No |
| VLANs | Isolated | Requires VLAN-capable AP | Yes |
| **Per-device subnet** | **Must route through us** | **Must route through us** | **No** |

**Why devices can't bypass this:**

- Device A (10.0.1.2/30) wants to reach Device B (10.0.2.2)
- Device A checks: "Is 10.0.2.2 on my subnet (10.0.1.0/30)?" → No
- Device A sends packet to its gateway (10.0.1.1) → HermitShell
- HermitShell applies policy, forwards or drops

Even if devices are on the same physical switch or WiFi AP, they won't ARP for each other because the IP math says "that's not my network." The only way to bypass this is raw Ethernet frame injection, which requires root access on an already-compromised device.

**Address allocation:**

| Range | Purpose |
|-------|---------|
| 10.0.0.0/16 | Device subnets |
| 10.0.X.0/30 | Device X's subnet (10.0.X.1 = gateway, 10.0.X.2 = device) |
| 10.255.255.0/24 | Management (router UI, SSH) |

With a /16, we can support 65,534 devices (each using a /30). More than enough for any home.

**mDNS/Bonjour:**

By default, mDNS is broken—devices can't discover each other. This is a feature:
- Prevents IoT devices from finding and attacking other devices
- Blocks tracking via mDNS fingerprinting

For devices that legitimately need discovery (e.g., AirPlay, Chromecast), users can explicitly allow mDNS relay between specific devices or groups. This is opt-in, not opt-out.

### 2.3 Why This Stack

| Choice | Rationale |
|--------|-----------|
| **Per-device /30 subnets** | True isolation without VLANs, managed switches, or AP cooperation |
| **systemd-networkd** | Modern, declarative, handles interfaces + DHCP server in one |
| **systemd-resolved** | DoT upstream, DNSSEC, caching, zero extra packages |
| **nftables routing policy** | Per-device forwarding rules based on source/dest subnet |
| **Host services** | Network services run on host for reliability; container restart doesn't kill network |

### 2.4 Why the Firewall is Not Containerized

The web UI runs in Docker, but the firewall (nftables) runs directly on the host. This is intentional:

**1. Network namespace isolation breaks visibility**

Containers have their own network namespace. A containerized firewall would only see traffic to/from that container, not traffic flowing through the host between devices. Using `--network=host` partially solves this but requires `CAP_NET_ADMIN`, which significantly weakens container isolation.

**2. Boot ordering vulnerability**

The firewall must be active *before* the network is exposed to the internet. Container runtimes start after basic networking is up. A containerized firewall creates a window during boot where the host is unprotected.

**3. Recovery scenarios**

If a containerized firewall breaks (bad config, OOM, runtime crash), you may be locked out with no way to SSH in and fix it. Host-level nftables means:
- Rules persist in kernel even if management software crashes
- You can always recover via physical console
- systemd can restore rules on boot before Docker starts

**4. Docker's own firewall manipulation**

Docker manipulates iptables/nftables for container networking (NAT, port forwarding). A containerized firewall managing the same tables creates conflicts and race conditions.

**5. Industry consensus**

No serious router project containerizes the firewall:
- OPNsense/pfSense: Base OS, not containerized
- OpenWRT: Base OS, not containerized
- VyOS: Base OS, not containerized
- router7: Appliance image, not containerized

**Our security boundary:**

```
┌─────────────────────────────────────────────────────────┐
│                 UNTRUSTED ZONE                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │  hermitshell (Docker container)                   │  │
│  │  - Web UI, API                                    │  │
│  │  - No CAP_NET_ADMIN                               │  │
│  │  - Cannot touch nftables directly                 │  │
│  │  - Can only send HTTP requests to agent           │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────┘
                          │ HTTP (validated requests)
                          ▼
┌─────────────────────────────────────────────────────────┐
│                 TRUSTED ZONE (host)                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │  hermitshell-agent                                │  │
│  │  - Validates ALL input                            │  │
│  │  - Sudoers whitelist (explicit commands only)     │  │
│  │  - Generates nftables rules from validated input  │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │  nftables (kernel)                                │  │
│  │  - Firewall rules                                 │  │
│  │  - NAT                                            │  │
│  │  - Traffic counters                               │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

The container isolates the attack surface (web UI parsing user input, handling HTTP requests). The agent is the security boundary that validates everything before touching the firewall.

### 2.4 Traffic Monitoring (No DPI)

We use kernel facilities instead of external analyzers:

| Need | Solution |
|------|----------|
| Per-device bandwidth | nftables counters keyed by device subnet |
| Interface-level bandwidth | vnstat (daily/weekly/monthly totals) |
| Connection logs | conntrack events (new/destroy with byte counts) |
| Application ID | Port → app name lookup table |
| Historical data | Agent snapshots counters to SQLite periodically |

**nftables accounting (per-device):**
```nft
table inet accounting {
    chain traffic {
        type filter hook forward priority -50; policy accept;
        
        # Count by source subnet (outbound from device)
        # Device 1 (10.0.1.0/30)
        ip saddr 10.0.1.0/30 counter name "dev:1:out"
        ip daddr 10.0.1.0/30 counter name "dev:1:in"
        
        # Device 2 (10.0.2.0/30)
        ip saddr 10.0.2.0/30 counter name "dev:2:out"
        ip daddr 10.0.2.0/30 counter name "dev:2:in"
        
        # ... generated for each device
    }
}
```

**vnstat (interface-level):**
```bash
# Installed by agent, monitors WAN and LAN interfaces
vnstat -i eth0      # WAN traffic
vnstat -i eth1      # LAN traffic

# JSON output for API consumption
vnstat -i eth0 --json d   # Daily stats
vnstat -i eth0 --json m   # Monthly stats
```

**conntrack events:**
```
[NEW] tcp src=10.0.1.2 dst=142.250.80.46 sport=54321 dport=443
[DESTROY] tcp src=10.0.1.2 dst=142.250.80.46 packets=15 bytes=1420
```

Agent streams conntrack events via WebSocket to hermitshell, which:
1. Maps src IP → device (10.0.X.2 → device ID X)
2. Maps dst port → application name (443=HTTPS, 22=SSH, etc.)
3. Stores in SQLite for historical queries

---

## 3. Technology Stack

### 3.1 Implementation

| Component | Choice | Rationale |
|-----------|--------|-----------|
| **Backend** | Rust + Axum + Tokio | Memory safety, single binary, async performance |
| **Frontend** | Leptos | Full-stack Rust, SSR + hydration, no JS toolchain |
| **Charts** | apexcharts-rs (or charming) | Interactive traffic graphs |
| **Database** | SQLite (rusqlite) | Zero config, single file, embedded |
| **Styling** | Tailwind CSS | Utility-first, no runtime |

Single binary deployment: `hermitshell` contains web UI, API, and can be run in Docker or directly on host.

### 3.2 Container Configuration

```yaml
hermitshell:
  image: ghcr.io/youruser/hermitshell:latest
  ports:
    - "8080:8080"
  volumes:
    - /data/hermitshell/db:/app/data
    - /data/hermitshell/config:/app/config:ro
    - /run/hermitshell/agent.sock:/run/hermitshell/agent.sock  # Unix socket to agent
  environment:
    - DATABASE_PATH=/app/data/hermitshell.db
    - CONFIG_PATH=/app/config/hermitshell.toml
```

### 3.3 Container ↔ Agent Communication

**Unix socket** instead of HTTP with shared secret:

```
Container                          Host
┌─────────────┐                   ┌─────────────┐
│ hermitshell │◄──────────────────│    agent    │
│             │  /run/hermitshell │             │
│             │     /agent.sock   │             │
└─────────────┘                   └─────────────┘
```

**Why unix socket over HTTP:**
- No secret to manage or rotate
- No port to bind or firewall
- Kernel enforces access control via filesystem permissions
- Cannot be accidentally exposed to network
- Same pattern Docker uses for its own API

Agent creates socket with restricted permissions:
```bash
# /run/hermitshell/agent.sock owned by hermitshell-agent:docker
# Mode 0660 - only agent and docker group can access
```

---

## 4. Host Services

Network services run directly on the host (not in containers) for reliability and performance. The hermitshell-agent manages their configuration.

### 4.1 systemd-networkd (Interface Management)

**Default mode (flat network):** Single LAN subnet, all devices share the same broadcast domain.

```ini
# /etc/systemd/network/10-wan.network
[Match]
Name=eth0

[Network]
DHCP=yes

[DHCPv4]
UseDNS=false  # We use our own DNS
```

```ini
# /etc/systemd/network/20-lan.network
[Match]
Name=eth1

[Network]
# Base address for the LAN interface (management)
Address=10.255.255.1/24
IPForward=yes
# Per-device addresses are added dynamically by the agent
```

**Per-device subnet implementation:**

The agent dynamically adds a /30 address for each device:

```bash
# When device with MAC aa:bb:cc:dd:ee:ff connects:
# 1. Agent assigns it device ID 1 → subnet 10.0.1.0/30
# 2. Agent adds gateway address to br0/eth1:
ip addr add 10.0.1.1/30 dev eth1

# 3. Agent configures DHCP to offer 10.0.1.2/30 to that MAC
# 4. Device gets: IP 10.0.1.2, netmask 255.255.255.252, gateway 10.0.1.1
```

HermitShell can have hundreds of addresses on the LAN interface—Linux handles this efficiently.

### 4.2 DHCP Server (Per-Device Subnets)

systemd-networkd's built-in DHCP server doesn't support per-client subnets. HermitShell uses **dnsmasq** for DHCP, configured by the agent.

**Why dnsmasq for DHCP:**
- Supports per-host network configuration via `dhcp-host` + `dhcp-range`
- Can assign different subnet masks per client
- Lightweight, battle-tested
- systemd-resolved still handles DNS (dnsmasq only does DHCP)

```ini
# /etc/dnsmasq.d/hermitshell.conf
# Generated by hermitshell-agent - DO NOT EDIT

# Disable DNS (systemd-resolved handles it)
port=0

# Listen on LAN interface only
interface=eth1
bind-interfaces

# Lease file location
dhcp-leasefile=/var/lib/hermitshell/dhcp.leases

# Default lease time
dhcp-lease-max=1000

# Device 1: Laptop (TRUSTED)
dhcp-host=aa:bb:cc:dd:ee:01,10.0.1.2,255.255.255.252,set:dev1
dhcp-range=tag:dev1,10.0.1.2,10.0.1.2,255.255.255.252,24h
dhcp-option=tag:dev1,option:router,10.0.1.1
dhcp-option=tag:dev1,option:dns-server,10.0.1.1

# Device 2: Phone (TRUSTED)
dhcp-host=aa:bb:cc:dd:ee:02,10.0.2.2,255.255.255.252,set:dev2
dhcp-range=tag:dev2,10.0.2.2,10.0.2.2,255.255.255.252,24h
dhcp-option=tag:dev2,option:router,10.0.2.1
dhcp-option=tag:dev2,option:dns-server,10.0.2.1

# Device 3: Camera (IOT)
dhcp-host=aa:bb:cc:dd:ee:03,10.0.3.2,255.255.255.252,set:dev3
dhcp-range=tag:dev3,10.0.3.2,10.0.3.2,255.255.255.252,24h
dhcp-option=tag:dev3,option:router,10.0.3.1
dhcp-option=tag:dev3,option:dns-server,10.0.3.1

# Unknown devices get quarantine subnet (temporary, until agent assigns permanent)
dhcp-range=10.254.0.2,10.254.255.254,255.255.255.252,5m
dhcp-option=option:router,10.254.0.1
dhcp-option=option:dns-server,10.254.0.1
```

**New device flow:**

1. Unknown MAC requests DHCP
2. dnsmasq assigns from quarantine pool (10.254.x.x/30, short lease)
3. Agent detects new lease, creates device record in DB
4. Agent assigns permanent device ID → permanent /30 subnet
5. Agent regenerates dnsmasq.conf with new `dhcp-host` entry
6. Agent adds gateway address to LAN interface: `ip addr add 10.0.X.1/30 dev eth1`
7. Agent reloads dnsmasq: `systemctl reload dnsmasq`
8. Device's next DHCP renew gets permanent subnet

**Quarantine subnet handling:**

Quarantine devices (10.254.x.x) get:
- Internet access (NAT works normally)
- DNS (for captive portal and basic function)
- Access to HermitShell UI (for self-registration if enabled)
- No access to any other device

```nft
# Quarantine policy
chain forward {
    # Quarantine can reach internet
    ip saddr 10.254.0.0/16 oifname "eth0" accept
    
    # Quarantine can reach router UI
    ip saddr 10.254.0.0/16 ip daddr 10.255.255.1 tcp dport 8080 accept
    
    # Quarantine cannot reach anything else
    ip saddr 10.254.0.0/16 drop
}
```

**Reading leases:**
```bash
# Leases in dnsmasq format
cat /var/lib/hermitshell/dhcp.leases
# Format: timestamp MAC IP hostname client-id

# Or via agent API
curl -s http://localhost:9999/api/leases
```

### 4.3 systemd-resolved (DNS with DoT)

systemd-resolved provides DNS resolution with DNS-over-TLS upstream.

```ini
# /etc/systemd/resolved.conf.d/hermitshell.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
Domains=~.

# Listen on LAN interfaces (not just localhost)
DNSStubListenerExtra=10.0.10.1
DNSStubListenerExtra=10.0.20.1
DNSStubListenerExtra=10.0.30.1
DNSStubListenerExtra=10.0.50.1
```

**Why systemd-resolved:**
- DNS-over-TLS to upstream (ISP can't see queries)
- DNSSEC validation
- Caching
- Built into systemd (no extra packages)

**Query logging limitation:**

systemd-resolved lacks structured query logging. Workarounds:

1. **Debug mode** (verbose, includes internal state):
   ```bash
   resolvectl log-level debug
   journalctl -u systemd-resolved -f | grep "Looking up RR for"
   ```

2. **nftables DNS logging** (recommended - captures source device):
   See Section 4.4

### 4.4 DNS Query Logging via nftables

Since systemd-resolved doesn't log which device made which query, we capture this at the firewall level using nflog:

```nft
table inet dns_log {
    chain prerouting {
        type filter hook prerouting priority -150; policy accept;
        
        # Log all DNS queries from LAN before forwarding to resolved
        iifname "eth1.*" udp dport 53 log prefix "DNS: " group 100
        iifname "eth1.*" tcp dport 53 log prefix "DNS: " group 100
    }
}
```

**Userspace logger** (agent component):

```bash
# Using ulogd2 or custom parser
ulogd -c /etc/ulogd.conf
```

Or the agent directly reads from nflog:
```rust
// Agent subscribes to nflog group 100
// Parses DNS query from packet payload
// Logs: timestamp, src_mac, src_ip, query_domain, query_type
```

**Log format:**
```json
{"ts": "2025-02-03T14:30:00Z", "src_mac": "aa:bb:cc:dd:ee:ff", "src_ip": "10.0.20.15", "domain": "api.Ring.com", "type": "A"}
{"ts": "2025-02-03T14:30:01Z", "src_mac": "aa:bb:cc:dd:ee:ff", "src_ip": "10.0.20.15", "domain": "firmware.Ring.com", "type": "A"}
```

This gives us per-device DNS visibility without relying on resolved's limited logging.

**Future improvement:** Contribute structured query logging to systemd-resolved upstream (issue #20264 tracks this).

### 4.5 Ad Blocking

Without dnsmasq's hosts file or Unbound's RPZ, ad blocking options with pure systemd:

1. **Response Policy Zone via nftables** - Drop packets to known ad server IPs (limited, IPs change)

2. **External blocklist DNS** - Point resolved at a filtering upstream like NextDNS or Quad9

3. **Local blocklist integration** - V2 feature: patch resolved or add a lightweight filtering proxy

For V1, recommend users who want ad blocking either:
- Use `provider = "external"` with Pi-hole/AdGuard
- Use a filtering upstream like `dns.adguard.com` or NextDNS

```ini
# /etc/systemd/resolved.conf.d/adblocking.conf
[Resolve]
DNS=94.140.14.14#dns.adguard.com
DNSOverTLS=yes
```

---

## 5. Configuration

### 5.1 Main Configuration File

`/data/hermitshell/config/hermitshell.toml`:

```toml
[general]
hostname = "hermitshell"
timezone = "America/Chicago"

[network]
wan_interface = "eth0"
lan_interface = "eth1"

[dns]
# Upstream resolvers (with DoT hostnames)
upstream = ["1.1.1.1#cloudflare-dns.com", "9.9.9.9#dns.quad9.net"]
dns_over_tls = true
dnssec = true

# "internal" = systemd-resolved managed by HermitShell
# "external" = user manages their own DNS (Pi-hole, AdGuard, etc.)
provider = "internal"

# Ad blocking (when provider = "internal")
# Options: "none", "adguard-upstream", "nextdns"
# For full local blocking, use provider = "external" with Pi-hole
[dns.adblocking]
mode = "none"

[agent]
socket = "/run/hermitshell/agent.sock"

[web]
listen = "0.0.0.0:8080"
```

### 5.2 Alternative: External DNS

If user already has Pi-hole, AdGuard Home, or another DNS solution:

```toml
[dns]
provider = "external"
external_server = "10.0.1.53"  # Their existing DNS server
```

HermitShell will configure DHCP to point clients to this server instead of managing DNS itself.

---

## 6. Agent (Host Service)

The agent runs on the host with carefully scoped privileges.

**Installation:**
```bash
# Quick install
curl -sSL https://install.hermitshell.dev/agent | sudo bash

# With options
curl -sSL https://install.hermitshell.dev/agent | sudo bash -s -- \
    --wan eth0 \
    --lan eth1 \
    --yes           # Non-interactive

# Uninstall
curl -sSL https://install.hermitshell.dev/agent | sudo bash -s -- --uninstall
```

**Config at /etc/hermitshell/agent.toml:**
```toml
socket = "/run/hermitshell/agent.sock"
wan_interface = "eth0"
lan_interface = "eth1"

[features]
vnstat = true
conntrack = true
dns_logging = true  # nflog-based DNS query capture
```

**Directory structure:**
```
/etc/hermitshell/
├── agent.toml           # Agent config
├── backups/             # Auto-backup before changes
│   └── network-2025-02-02T14:00:00/
└── sudoers.d/
    └── hermitshell      # Copied to /etc/sudoers.d/
```

**Sudoers whitelist (/etc/sudoers.d/hermitshell):**
```sudoers
# HermitShell agent - minimal privilege set
# DO NOT use ALL or wildcards

# nftables
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/nft -f /etc/hermitshell/rules.nft
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/nft list counters

# systemd-networkd (interface + DHCP management)
hermitshell-agent ALL=(ALL) NOPASSWD: /bin/systemctl reload systemd-networkd
hermitshell-agent ALL=(ALL) NOPASSWD: /bin/networkctl reload

# systemd-resolved
hermitshell-agent ALL=(ALL) NOPASSWD: /bin/systemctl reload systemd-resolved
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/bin/resolvectl flush-caches

# Monitoring
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/conntrack -E -o xml
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/bin/vnstat --json *

# System
hermitshell-agent ALL=(ALL) NOPASSWD: /sbin/sysctl -w *
```

**Systemd unit (/lib/systemd/system/hermitshell-agent.service):**
```ini
[Unit]
Description=HermitShell Network Agent
After=network-online.target nftables.service systemd-networkd.service systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
User=hermitshell-agent
Group=hermitshell-agent
ExecStart=/usr/local/bin/hermitshell-agent
Restart=always
RestartSec=5
# For nflog access
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

Note: We don't add systemd sandboxing (ProtectSystem, etc.) to the agent because it legitimately needs to run privileged commands via sudo. The sudoers whitelist is the security boundary. `CAP_NET_ADMIN` is needed to read nflog for DNS query logging.

**Agent responsibilities:**
- Generate and apply nftables rulesets (including device group MAC sets)
- Update MAC address sets when devices are approved/moved/blocked
- Generate systemd-networkd configs for LAN + DHCP (VLANs optional)
- Generate systemd-resolved config (writes to /etc/systemd/resolved.conf.d/)
- Subscribe to nflog group 100 for DNS query logging
- Parse DNS packets and log per-device queries to SQLite
- Read nftables counters (polled every 10s)
- Stream conntrack events (real-time via WebSocket)
- Report vnstat interface stats
- Configure host sysctl flags (including proxy ARP for isolation)
- Backup configs before changes

---

## 7. Data Model

### 7.1 Device

```sql
CREATE TABLE devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- Device ID, determines subnet (10.0.{id}.0/30)
    mac         TEXT NOT NULL UNIQUE,
    ip          TEXT,              -- Current IP (10.0.{id}.2)
    subnet      TEXT,              -- Assigned subnet (10.0.{id}.0/30)
    gateway     TEXT,              -- Gateway IP (10.0.{id}.1)
    hostname    TEXT,
    name        TEXT,              -- User-assigned friendly name
    vendor      TEXT,              -- OUI lookup
    group_id    INTEGER NOT NULL DEFAULT 5,  -- FK to device_groups, default=Quarantine
    status      TEXT NOT NULL DEFAULT 'online',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    approved    INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    notes       TEXT,
    icon        TEXT,
    FOREIGN KEY (group_id) REFERENCES device_groups(id)
);

-- Device states:
-- approved = 0: In quarantine (10.254.x.x temporary subnet), awaiting approval  
-- approved = 1: Approved, has permanent subnet (10.0.{id}.0/30)
-- blocked = 1:  All traffic dropped regardless of group

-- When device is approved:
-- 1. Device ID (INTEGER) determines subnet: 10.0.{id}.0/30
-- 2. Device gets IP: 10.0.{id}.2
-- 3. Gateway is: 10.0.{id}.1
-- 4. Agent adds 10.0.{id}.1/30 to LAN interface
-- 5. Agent adds dhcp-host entry to dnsmasq
```

### 4.2 Traffic Stats (per-device, hourly rollups)

```sql
CREATE TABLE traffic_stats (
    id          INTEGER PRIMARY KEY,
    device_id   TEXT NOT NULL,
    hour        TEXT NOT NULL,     -- "2025-02-02T14:00:00Z"
    bytes_in    INTEGER NOT NULL,
    bytes_out   INTEGER NOT NULL,
    UNIQUE(device_id, hour)
);
```

### 4.3 Connections (sampled, not every flow)

```sql
CREATE TABLE connections (
    id          INTEGER PRIMARY KEY,
    device_id   TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    protocol    TEXT NOT NULL,     -- tcp, udp
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    bytes       INTEGER,
    app         TEXT               -- looked up from port
);

-- Index for "top destinations" queries
CREATE INDEX idx_conn_device_time ON connections(device_id, timestamp);
```

### 4.4 Firewall Rules

```sql
CREATE TABLE firewall_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 100,
    source      TEXT NOT NULL,     -- JSON
    destination TEXT NOT NULL,     -- JSON
    protocol    TEXT,
    ports       TEXT,              -- JSON
    action      TEXT NOT NULL,     -- accept, drop, reject
    log         INTEGER NOT NULL DEFAULT 0
);
```

### 7.5 Device Groups

Device groups define isolation policies enforced via per-device subnet routing rules.

```sql
CREATE TABLE device_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    isolation   TEXT NOT NULL,      -- none, internet_only, full_isolation
    can_reach   TEXT NOT NULL,      -- JSON array of group IDs this group can initiate connections to
    description TEXT
);

-- Isolation levels (enforced via nftables routing policy):
-- none:           Can reach internet and other devices in groups listed in can_reach
-- internet_only:  Can reach internet, can be reached by devices in groups that list this group
-- full_isolation: Can reach internet only, cannot initiate to or be reached by any other device

-- Default groups
INSERT INTO device_groups VALUES 
    (1, 'Trusted',    'none',           '[1,2,4]', 'Personal devices - can reach other trusted, IoT, servers'),
    (2, 'IoT',        'internet_only',  '[]',      'IoT devices - internet + can be reached by Trusted'),
    (3, 'Guest',      'full_isolation', '[]',      'Guest devices - internet only, fully isolated'),
    (4, 'Servers',    'none',           '[1,2,4]', 'Home servers - can reach trusted, IoT, other servers'),
    (5, 'Quarantine', 'full_isolation', '[]',      'Unapproved devices - internet only, fully isolated');
```
```

**How it works:** Each device gets its own /30 subnet. The agent generates nftables rules based on each device's group membership:

```nft
table inet hermitshell {
    # Device subnets by group (populated by agent)
    # Format: 10.0.X.0/30 where X is device ID
    set trusted_subnets { type ipv4_addr; flags interval; }
    set iot_subnets { type ipv4_addr; flags interval; }
    set guest_subnets { type ipv4_addr; flags interval; }
    set server_subnets { type ipv4_addr; flags interval; }
    # Quarantine uses 10.254.0.0/16
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established/related first (fast path)
        ct state established,related accept
        
        # Quarantine (10.254.x.x): internet only
        ip saddr 10.254.0.0/16 oifname "eth0" accept
        ip saddr 10.254.0.0/16 ip daddr 10.255.255.1 tcp dport 8080 accept  # Router UI
        ip saddr 10.254.0.0/16 drop
        
        # Guest: internet only
        ip saddr @guest_subnets oifname "eth0" accept
        ip saddr @guest_subnets drop
        
        # IoT: internet + can receive from trusted/server
        ip saddr @iot_subnets oifname "eth0" accept
        ip daddr @iot_subnets ip saddr @trusted_subnets accept
        ip daddr @iot_subnets ip saddr @server_subnets accept
        ip saddr @iot_subnets drop
        
        # Trusted: can reach internet and each other
        ip saddr @trusted_subnets oifname "eth0" accept
        ip saddr @trusted_subnets ip daddr @trusted_subnets accept
        ip saddr @trusted_subnets ip daddr @server_subnets accept
        ip saddr @trusted_subnets ip daddr @iot_subnets accept
        
        # Servers: full access
        ip saddr @server_subnets accept
    }
    
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Allow DHCP from LAN
        iifname "eth1" udp dport 67 accept
        
        # Allow DNS from all device subnets
        ip saddr 10.0.0.0/8 udp dport 53 accept
        ip saddr 10.0.0.0/8 tcp dport 53 accept
        ip saddr 10.254.0.0/16 udp dport 53 accept
        ip saddr 10.254.0.0/16 tcp dport 53 accept
        
        # Allow router UI from trusted + quarantine (for approval)
        ip saddr @trusted_subnets tcp dport 8080 accept
        ip saddr 10.254.0.0/16 tcp dport 8080 accept
        
        # Allow SSH from trusted only
        ip saddr @trusted_subnets tcp dport 22 accept
    }
}
```

**Example populated sets:**

```nft
# After devices are assigned:
# Device 1 (Laptop) = trusted, subnet 10.0.1.0/30
# Device 2 (Phone) = trusted, subnet 10.0.2.0/30  
# Device 3 (Camera) = iot, subnet 10.0.3.0/30
# Device 4 (Smart TV) = guest, subnet 10.0.4.0/30

set trusted_subnets {
    type ipv4_addr
    flags interval
    elements = { 10.0.1.0/30, 10.0.2.0/30 }
}

set iot_subnets {
    type ipv4_addr
    flags interval
    elements = { 10.0.3.0/30 }
}

set guest_subnets {
    type ipv4_addr
    flags interval
    elements = { 10.0.4.0/30 }
}
```

**Per-device communication overrides:**

For cases where specific cross-group communication is needed (e.g., trusted laptop needs to reach IoT camera):

```sql
-- Allow rules override group defaults
CREATE TABLE device_allow_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    src_device  INTEGER NOT NULL REFERENCES devices(id),
    dst_device  INTEGER NOT NULL REFERENCES devices(id),
    ports       TEXT,  -- NULL = all, or "tcp/80,tcp/443"
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
```

```nft
# Generated per-device allow rules
chain device_overrides {
    # Laptop (10.0.1.2) can reach Camera (10.0.3.2) on any port
    ip saddr 10.0.1.0/30 ip daddr 10.0.3.0/30 accept
}
```

### 4.6 VLANs (Optional, for Advanced Users)

Per-device subnets provide strong isolation without VLANs. VLANs are only useful for:

1. **Multi-site or complex topologies** - Extending isolation across multiple switches/buildings
2. **Legacy devices** - Devices that need to be on a specific subnet for compatibility
3. **Defense in depth** - Additional L2 isolation on top of per-device subnets

If you need VLANs, you need VLAN-capable switches and APs. For most home users, per-device subnets are simpler and work with any hardware.

---

## 8. API

**API-first design:** The web UI consumes the same REST API available to external tools. This enables automation via scripts, Ansible modules, Terraform providers, or any HTTP client—without HermitShell needing to ship those integrations directly.

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/devices | List all |
| GET | /api/devices/:id | Get one |
| PATCH | /api/devices/:id | Update (name, notes, icon, group_id) |
| DELETE | /api/devices/:id | Forget device |
| POST | /api/devices/:id/approve | Approve, assign to group |
| POST | /api/devices/:id/block | Block all traffic |
| POST | /api/devices/:id/unblock | Unblock |
| GET | /api/devices/:id/traffic | Bandwidth history |
| GET | /api/devices/:id/connections | Recent connections |

### Device Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/groups | List with device counts |
| GET | /api/groups/:id | Get config |
| POST | /api/groups | Create custom group |
| PATCH | /api/groups/:id | Update (isolation, can_reach) |
| DELETE | /api/groups/:id | Delete (must be empty) |
| GET | /api/groups/:id/devices | Devices in group |

### VLANs (Optional)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/vlans | List configured VLANs |
| POST | /api/vlans | Create VLAN (requires VLAN mode enabled) |
| PATCH | /api/vlans/:id | Update (subnet, DHCP range) |
| DELETE | /api/vlans/:id | Delete VLAN |
| POST | /api/vlans/enable | Enable VLAN mode (advanced) |
| POST | /api/vlans/disable | Disable VLAN mode |

### Firewall

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/firewall/rules | List rules |
| POST | /api/firewall/rules | Create |
| PATCH | /api/firewall/rules/:id | Update |
| DELETE | /api/firewall/rules/:id | Delete |
| POST | /api/firewall/apply | Push to host |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/system/status | Health check |
| GET | /api/system/stats | Dashboard summary |
| WS | /api/ws | Real-time events |

---

## 9. Agent API

Internal API on localhost:9999 (authenticated with shared secret).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /rules | Apply nftables ruleset |
| GET | /counters | Read all nftables counters |
| POST | /vlan | Create/delete VLAN interface (optional) |
| POST | /device-sets | Update MAC address sets for groups |
| GET | /custom-rules | Get current custom rules file |
| PUT | /custom-rules | Replace custom rules (validates, writes file, reloads) |
| POST | /custom-rules/validate | Validate rules syntax without applying |
| GET | /status | Agent health + host info |
| GET | /vnstat/:iface | Interface bandwidth stats (daily/monthly) |
| GET | /vnstat/:iface/live | Live bandwidth (5-second updates) |
| WS | /events | Stream conntrack events |

**Custom rules validation:**
```json
// PUT /custom-rules
{
  "rules": "chain custom_forward_early {\n    ip saddr 10.0.42.2 accept\n}"
}

// Response (success)
{
  "status": "ok",
  "applied": true
}

// Response (validation error)
{
  "status": "error",
  "error": "line 2: syntax error, unexpected accept",
  "applied": false
}
```

**Example vnstat response:**
```json
{
  "interface": "eth0",
  "daily": [
    {"date": "2025-02-01", "rx_bytes": 1234567890, "tx_bytes": 987654321},
    {"date": "2025-02-02", "rx_bytes": 2345678901, "tx_bytes": 876543210}
  ],
  "monthly": [
    {"month": "2025-01", "rx_bytes": 98765432100, "tx_bytes": 87654321000}
  ]
}
```

---

## 10. Host Configuration

### 7.1 Sysctl Flags (Critical)

The agent must configure these flags on startup. Without them, ARP responses from multiple interfaces on the same subnet cause bizarre routing failures.

```bash
# /etc/sysctl.d/99-hermitshell.conf

# === PACKET FORWARDING ===
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# === ARP CONFIGURATION (CRITICAL) ===
# Without these, devices may receive ARP replies from wrong interfaces,
# causing packets to be routed to LAN instead of WAN.
# See: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
net.ipv4.conf.all.arp_filter = 1    # Only respond on correct interface
net.ipv4.conf.all.arp_announce = 1  # Use best local address for ARP
net.ipv4.conf.all.arp_ignore = 1    # Ignore ARP for addresses not on this interface

# === REVERSE PATH FILTERING ===
# Prevents IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# === ICMP HARDENING ===
# Don't accept ICMP redirects (prevent MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === ICMP RATE LIMITING (kernel-level) ===
# More efficient than firewall rate limiting
# Rate limit outgoing ICMP error messages (ms between responses)
net.ipv4.icmp_ratelimit = 1000
# Bitmask: dest-unreach, source-quench, time-exceeded, param-problem
net.ipv4.icmp_ratemask = 6168
# IPv6 ICMP rate limiting (ms)
net.ipv6.icmp.ratelimit = 1000

# === CONNTRACK ===
net.netfilter.nf_conntrack_acct = 1           # Enable byte/packet counters
net.netfilter.nf_conntrack_timestamp = 1      # Enable timestamps
net.netfilter.nf_conntrack_max = 262144       # Increase max connections
net.netfilter.nf_conntrack_tcp_timeout_established = 86400  # 24h for established TCP

# === BRIDGE (if using Linux bridge) ===
# Don't pass bridged traffic through iptables/nftables
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-arptables = 0
```

### 7.2 Quality of Service (Bufferbloat Prevention)

Bufferbloat causes latency spikes during heavy traffic (e.g., video calls stutter when someone starts a download). The solution is **CAKE** queue discipline with traffic shaping.

**Why this matters:** Test your connection at http://www.dslreports.com/speedtest — the bufferbloat grade should be A+.

#### Disable Hardware Offloads

Hardware offloading (GRO, GSO, TSO) batches packets for throughput at the cost of latency. For a router, we prefer consistent low latency:

```bash
# /etc/networkd-dispatcher/routable.d/10-disable-offloads
#!/bin/bash
for iface in eth0 eth1; do
    ethtool -K "$iface" gro off gso off tso off 2>/dev/null || true
done
```

#### CAKE Configuration

**CAKE** (Common Applications Kept Enhanced) combines queue management, flow isolation, and traffic shaping:

```bash
# Egress (upload) shaping - directly on WAN interface
# Set to 90-95% of actual upload speed
tc qdisc replace dev eth0 root cake bandwidth 19mbit besteffort wash

# Ingress (download) shaping - requires IFB device
modprobe ifb numifbs=1
ip link set ifb0 up
tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc replace dev ifb0 root cake bandwidth 95mbit besteffort wash ingress
```

**Key CAKE options:**
- `bandwidth` - Set to 90-95% of actual link speed (queuing must happen on router, not ISP)
- `besteffort` - No DiffServ priority classes (simpler, prevents gaming by apps)
- `wash` - Clear DSCP markings from ISP (prevents priority manipulation)
- `ingress` - Optimize for ingress traffic patterns on IFB device

#### Configuration

```toml
[qos]
enabled = true
# Set to 90-95% of actual speeds (run speed test with QoS disabled to determine)
wan_download_mbps = 95
wan_upload_mbps = 19

# "static" = fixed bandwidth (recommended for cable/fiber)
# "autorate" = dynamic adjustment (for LTE/Starlink/variable connections)
mode = "static"
```

#### Dynamic Bandwidth (Variable Connections)

For connections with variable bandwidth (LTE, Starlink, congested cable), static settings cause problems:
- Set too high → bufferbloat when link degrades
- Set too low → wasted bandwidth when link is good

**autorate mode** monitors RTT and adjusts CAKE bandwidth dynamically:

```toml
[qos]
enabled = true
mode = "autorate"
# Bounds for auto-adjustment
min_download_mbps = 10
max_download_mbps = 100
min_upload_mbps = 2
max_upload_mbps = 20
# Reflector hosts for latency measurement
reflectors = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
```

The agent implements a simplified version of [cake-autorate](https://github.com/lynxthecat/cake-autorate):
1. Ping reflectors every 50ms
2. If RTT increases under load → reduce bandwidth
3. If RTT stable under load → gradually increase bandwidth
4. Stay within configured min/max bounds

### 7.3 Network Interfaces (systemd-networkd)

The agent generates systemd-networkd configuration files based on the network mode.

#### 7.3.1 Flat Network Mode (Default)

Most users run a flat network—single subnet, all devices share the same L2 segment. This works with any consumer WiFi AP or unmanaged switch.

```ini
# /etc/systemd/network/10-wan.network
[Match]
Name=eth0

[Network]
DHCP=yes
DNSDefaultRoute=false

[DHCPv4]
UseDNS=false       # We use our own DNS
UseRoutes=true
```

```ini
# /etc/systemd/network/20-lan.network
[Match]
Name=eth1

[Network]
Address=192.168.1.1/24
DHCPServer=yes
IPForward=yes

[DHCPServer]
PoolOffset=100
PoolSize=150
EmitDNS=yes
DNS=192.168.1.1
EmitRouter=yes
DefaultLeaseTimeSec=86400
```

**Isolation in flat mode:** All devices get IPs from the same subnet (192.168.1.0/24). Isolation is enforced purely by nftables rules using MAC-based sets. See Section 4.5 (Device Groups) for details.

**Proxy ARP for discovery prevention:**
```bash
# Isolated devices can't ARP for each other—router answers instead
sysctl -w net.ipv4.conf.eth1.proxy_arp=1
sysctl -w net.ipv4.conf.eth1.proxy_arp_pvlan=1  # Private VLAN proxy ARP
```

#### 7.3.2 VLAN Mode (Optional - Advanced)

For users with managed switches and VLAN-capable APs, enable VLAN mode for hardware-level isolation:

```ini
# /etc/systemd/network/20-lan.network (VLAN mode)
[Match]
Name=eth1

[Network]
# Trunk interface, no IP
VLAN=eth1.10
VLAN=eth1.20
VLAN=eth1.30
VLAN=eth1.50
```

```ini
# /etc/systemd/network/30-vlan-trusted.netdev
[NetDev]
Name=eth1.10
Kind=vlan

[VLAN]
Id=10
```

```ini
# /etc/systemd/network/30-vlan-trusted.network
[Match]
Name=eth1.10

[Network]
Address=10.0.10.1/24
DHCPServer=yes

[DHCPServer]
PoolOffset=100
PoolSize=150
EmitDNS=yes
DNS=10.0.10.1
EmitRouter=yes
```

**Why enable VLAN mode:**
- True broadcast isolation (IoT can't see mDNS from trusted devices)
- Defense in depth (firewall misconfiguration doesn't expose devices)
- Required by compliance (some enterprise security policies)

**Requirements:**
- Managed switch (to tag switch ports)
- VLAN-capable WiFi AP (to tag SSIDs) or multiple SSIDs on separate ports

Agent applies changes via `networkctl reload` — no service restart required, existing connections maintained.

### 7.4 Firewall Policy

#### 7.4.1 Base Ruleset (Flat Network Mode - Default)

```nft
#!/usr/sbin/nft -f

flush ruleset

define WAN = eth0
define LAN = eth1

table inet filter {
    # ============ DEVICE GROUP SETS ============
    # Populated dynamically by hermitshell-agent
    set trusted_macs { type ether_addr; }
    set iot_macs { type ether_addr; }
    set guest_macs { type ether_addr; }
    set server_macs { type ether_addr; }
    set quarantine_macs { type ether_addr; }
    set blocked_macs { type ether_addr; }

    # ============ CUSTOM CHAINS (user-managed) ============
    # HermitShell NEVER modifies these - contents from /etc/hermitshell/custom-rules.nft
    chain custom_input {}
    chain custom_forward_early {}
    chain custom_forward_late {}
    chain custom_output {}

    # ============ INPUT CHAIN ============
    chain input {
        type filter hook input priority 0; policy drop;

        # Custom rules (early)
        jump custom_input

        # Allow established/related
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # ICMP (IPv4)
        ip protocol icmp icmp type {
            echo-request,
            echo-reply,
            destination-unreachable,
            time-exceeded,
            parameter-problem
        } accept

        # ICMPv6 (RFC 4890 compliant)
        ip6 nexthdr icmpv6 icmpv6 type {
            destination-unreachable,
            packet-too-big,
            time-exceeded,
            parameter-problem,
            echo-request,
            echo-reply,
            nd-router-solicit,
            nd-router-advert,
            nd-neighbor-solicit,
            nd-neighbor-advert,
            mld-listener-query,
            mld-listener-report,
            mld-listener-done,
            mld2-listener-report
        } accept

        # DHCP server
        udp dport { 67, 68 } accept

        # DNS (will be redirected to local resolver)
        tcp dport 53 accept
        udp dport 53 accept

        # DHCPv6 client (from ISP)
        iifname $WAN udp dport 546 accept

        # Web UI - from LAN only, trusted devices only
        iifname $LAN ether saddr @trusted_macs tcp dport 8080 accept

        # Drop everything else from WAN
        iifname $WAN log prefix "[HERMIT:INPUT:DROP] " drop

        # Accept from LAN
        iifname $LAN accept
    }

    # ============ FORWARD CHAIN ============
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Custom rules (early - before any HermitShell rules)
        jump custom_forward_early

        # Blocked devices: drop all traffic
        ether saddr @blocked_macs drop
        ether daddr @blocked_macs drop

        # Allow established/related
        ct state established,related accept

        # ICMP forwarding (required for path MTU discovery)
        ip protocol icmp accept
        ip6 nexthdr icmpv6 icmpv6 type {
            destination-unreachable,
            packet-too-big,
            time-exceeded,
            parameter-problem,
            echo-request,
            echo-reply
        } accept

        # Apply group isolation policy
        jump group_policy

        # Custom rules (late - last chance before drop)
        jump custom_forward_late

        # Log and drop anything else
        log prefix "[HERMIT:FORWARD:DROP] " drop
    }

    # ============ GROUP ISOLATION POLICY ============
    chain group_policy {
        # Trusted: full access to internet and LAN
        ether saddr @trusted_macs accept

        # Servers: full access to internet and LAN
        ether saddr @server_macs accept

        # IoT: internet only, no LAN initiation
        # (trusted can initiate TO iot, but iot can't initiate TO trusted)
        ether saddr @iot_macs oifname $WAN accept
        ether saddr @iot_macs ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
        ether daddr @iot_macs ether saddr @trusted_macs accept

        # Guest: internet only, isolated from all LAN including other guests
        ether saddr @guest_macs oifname $WAN accept
        ether saddr @guest_macs ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop

        # Quarantine: internet only, fully isolated
        ether saddr @quarantine_macs oifname $WAN accept
        ether saddr @quarantine_macs ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
    }

    # ============ PER-DEVICE RULES ============
    chain device_rules {
        # Dynamically populated by hermitshell
        # Example: Allow specific IoT device to reach a server
        # ether saddr AA:BB:CC:DD:EE:FF ip daddr 192.168.1.50 accept
    }

    # ============ OUTPUT CHAIN ============
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Custom rules
        jump custom_output
    }
}

table ip nat {
    # ============ CUSTOM NAT CHAINS (user-managed) ============
    chain custom_prerouting {}
    chain custom_postrouting {}

    chain prerouting {
        type nat hook prerouting priority -100; policy accept;

        # Custom rules (before HermitShell NAT)
        jump custom_prerouting

        # Force all DNS to local resolver (flat network)
        iifname $LAN tcp dport 53 redirect to :53
        iifname $LAN udp dport 53 redirect to :53

        # Block DoT (DNS-over-TLS) to prevent bypassing
        iifname $LAN tcp dport 853 drop
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;

        # Custom rules (before masquerade)
        jump custom_postrouting

        # Masquerade outbound traffic
        oifname $WAN masquerade
    }
}

table inet accounting {
    chain traffic {
        type filter hook forward priority -50; policy accept;

        # Per-device counters populated dynamically
        # Example: ether saddr AA:BB:CC:DD:EE:FF counter name "dev:AA:BB:CC:DD:EE:FF:tx"
        # Example: ether daddr AA:BB:CC:DD:EE:FF counter name "dev:AA:BB:CC:DD:EE:FF:rx"
    }
}
```

#### 7.4.2 Group Isolation Matrix

| Source → Dest | Trusted | IoT | Servers | Guest | Quarantine | Internet |
|---------------|---------|-----|---------|-------|------------|----------|
| Trusted       | ✓       | ✓   | ✓       | ✓     | ✓          | ✓        |
| IoT           | ✗       | ✗   | ✗       | ✗     | ✗          | ✓        |
| Servers       | ✓       | ✓   | ✓       | ✗     | ✗          | ✓        |
| Guest         | ✗       | ✗   | ✗       | ✗     | ✗          | ✓        |
| Quarantine    | ✗       | ✗   | ✗       | ✗     | ✗          | ✓        |

**Notes:**
- Trusted and Servers can initiate connections to any device
- IoT devices can only reach internet; trusted devices can initiate TO IoT (e.g., to control smart devices)
- Guest and Quarantine are fully isolated—internet only, can't even see other guests

#### 7.4.3 Per-Device Blocks

When a device is blocked via the API, the agent adds:

```nft
# In chain device_rules
ether saddr AA:BB:CC:DD:EE:FF log prefix "[HERMIT:BLOCKED] " drop
```

### 7.5 DNS Override Prevention

The agent must prevent the ISP from overwriting DNS settings via DHCP:

```bash
# /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate
# This hook runs BEFORE dhclient takes action

# Override the function that updates resolv.conf
make_resolv_conf() { :; }
```

As a safety net, make resolv.conf immutable:

```bash
# Set static DNS
cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
nameserver ::1
EOF

# Prevent modification
chattr +i /etc/resolv.conf
```

**dhclient hook types:**
- `dhclient-enter-hooks.d/` - Scripts run BEFORE dhclient actions (can override functions)
- `dhclient-exit-hooks.d/` - Scripts run AFTER dhclient actions (can react to lease info)

### 7.6 Service Restart Ordering

When the `networking.service` recreates interfaces, the `ifindex` changes. Services bound to the old ifindex (via `SO_BINDTODEVICE`) fail silently. The agent must ensure proper restart ordering.

**Problem:**
```
# dnsmasq binds to br0 with ifindex 47
# networking.service restarts, deletes/recreates br0
# New br0 has ifindex 48
# dnsmasq's socket still bound to ifindex 47 → silently fails
```

**Solution - systemd unit overrides:**

```ini
# /etc/systemd/system/dnsmasq.service.d/hermitshell.conf
[Unit]
# Restart dnsmasq when networking restarts
PartOf=networking.service

# /etc/systemd/system/networking.service.d/hermitshell.conf
[Unit]
# networking.service controls these
ConsistsOf=dnsmasq.service hermitshell-agent.service
```

The agent creates these overrides during installation.

### 7.7 Custom Rules & Advanced Networking

HermitShell manages the default nftables ruleset, but advanced users can add custom rules for scenarios like:

- 1:1 NAT (map external IP to internal device)
- Port forwarding with complex conditions
- Traffic marking for QoS
- Custom logging
- Policy-based routing

#### Custom Chain Architecture

The generated ruleset includes `custom_*` chains that HermitShell never modifies:

```nft
table inet filter {
    # HermitShell-managed chains
    chain input { ... }
    chain forward { ... }
    chain output { ... }
    
    # User-managed chains - HermitShell NEVER touches these
    chain custom_input {}
    chain custom_forward {}
    chain custom_output {}
}

table ip nat {
    chain prerouting { ... }
    chain postrouting { ... }
    
    # User-managed NAT chains
    chain custom_prerouting {}
    chain custom_postrouting {}
}
```

The managed chains jump to custom chains at appropriate points:

```nft
chain forward {
    type filter hook forward priority 0; policy drop;
    
    # Early custom rules (before HermitShell rules)
    jump custom_forward_early
    
    # ... HermitShell-managed rules ...
    
    # Late custom rules (after HermitShell rules, before final drop)
    jump custom_forward_late
}
```

#### Persistence

Custom rules are stored in `/etc/hermitshell/custom-rules.nft` and loaded on every ruleset regeneration:

```
/etc/hermitshell/
├── hermitshell.toml          # Static config
├── hermitshell.db            # SQLite
├── generated-rules.nft       # Auto-generated (DO NOT EDIT)
└── custom-rules.nft          # User rules (survives upgrades)
```

**Workflow:**

1. User edits `/etc/hermitshell/custom-rules.nft`
2. User runs `hermitshell-agent reload` or calls API
3. Agent validates syntax: `nft -c -f custom-rules.nft`
4. Agent regenerates full ruleset including custom rules
5. Agent applies atomically: `nft -f generated-rules.nft`

If validation fails, custom rules are skipped and agent logs a warning.

#### API for Custom Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/firewall/custom | Get current custom rules |
| PUT | /api/firewall/custom | Replace custom rules (validates first) |
| POST | /api/firewall/custom/validate | Validate rules without applying |

**Example: 1:1 NAT**

```nft
# /etc/hermitshell/custom-rules.nft

# Map external IP 203.0.113.50 to internal device at 10.0.42.2
# (Assumes you have multiple public IPs from your ISP)

chain custom_prerouting {
    ip daddr 203.0.113.50 dnat to 10.0.42.2
}

chain custom_postrouting {
    ip saddr 10.0.42.2 oif eth0 snat to 203.0.113.50
}

chain custom_forward {
    # Allow inbound to the NAT'd device
    ip daddr 10.0.42.2 ct state new accept
}
```

**Example: Hairpin NAT (access internal server via external IP from LAN)**

```nft
chain custom_prerouting {
    # External access (from WAN)
    iif eth0 ip daddr 203.0.113.50 tcp dport 443 dnat to 10.0.42.2:443
    
    # Hairpin (from LAN, accessing external IP)
    iif eth1 ip daddr 203.0.113.50 tcp dport 443 dnat to 10.0.42.2:443
}

chain custom_postrouting {
    # Hairpin: masquerade so return traffic comes back through router
    ip saddr 10.0.0.0/16 ip daddr 10.0.42.2 tcp dport 443 masquerade
}
```

**Example: Policy-based routing (send specific device through VPN)**

```nft
chain custom_forward {
    # Mark traffic from device 10.0.15.2 (device ID 15)
    ip saddr 10.0.15.2 meta mark set 0x1
}

# Then use ip rule + routing table:
# ip rule add fwmark 0x1 table vpn
# ip route add default via 10.8.0.1 table vpn
```

#### What You Can Break

Custom rules run with full nftables privileges. You can:

- **Lock yourself out** - Be careful with input chain rules
- **Break device isolation** - Custom forward rules can bypass group policy
- **Create routing loops** - Misconfigured NAT can cause loops
- **Conflict with HermitShell rules** - Custom rules that duplicate or contradict managed rules

**Recovery:**

If you lock yourself out:
1. Physical console access
2. `rm /etc/hermitshell/custom-rules.nft`
3. `systemctl restart hermitshell-agent`

The agent will regenerate the default ruleset without custom rules.

#### UI Integration

The Settings page has an "Advanced" section with:

- **Custom Rules** - Syntax-highlighted editor for nftables rules
- **Validate** button - Check syntax before applying
- **Apply** button - Apply validated rules
- **Reset** button - Remove all custom rules

The editor shows warnings for rules that may conflict with HermitShell's isolation policy.

---

## 11. User Interface

### Pages

1. **Dashboard**
   - Stats cards: devices online, quarantined, bandwidth today
   - Traffic chart (24h)
   - Devices by group (Trusted, IoT, Guest, etc.)
   - Recent activity (new devices, blocks)

2. **Devices**
   - List with filters (group, status, search)
   - Quick actions: approve, block, move to group

3. **Device Detail**
   - Info: MAC, IP, hostname, vendor, first/last seen
   - Traffic chart
   - Top destinations (by bytes)
   - Actions: approve, block, edit, forget

4. **Firewall**
   - Rules table (sortable by priority)
   - Add/edit rule
   - Default policy display

5. **Device Groups**
   - List with device counts
   - Edit isolation policy, allowed communications

6. **Settings**
   - Network mode (flat vs VLAN)
   - Interfaces
   - Agent status
   - Backup/restore

### Design

- Dark theme (gray-900)
- Accent: blue-500
- Status: green=online, gray=offline, red=blocked, yellow=quarantine
- Responsive

---

## 12. Deployment

### 9.1 Prerequisites

- Linux host (Debian 12+, Ubuntu 22.04+)
- Docker + Docker Compose v2
- Two NICs (WAN + LAN)

**Optional (for VLAN mode):**
- Managed switch with VLAN support
- VLAN-capable WiFi AP

### 9.2 Quick Install

```bash
# One-liner install
curl -sSL https://install.hermitshell.dev | bash

# Non-interactive (for automation)
curl -sSL https://install.hermitshell.dev | bash -s -- --yes

# With custom options
curl -sSL https://install.hermitshell.dev | bash -s -- \
    --wan eth0 \
    --lan eth1 \
    --data-dir /data/hermitshell

# Upgrade existing installation
curl -sSL https://install.hermitshell.dev | bash -s -- --upgrade

# Uninstall (preserves data by default)
curl -sSL https://install.hermitshell.dev | bash -s -- --uninstall
curl -sSL https://install.hermitshell.dev | bash -s -- --uninstall --purge  # Remove data too
```

**Installer steps:**
1. Check prerequisites (Docker, kernel version, NICs)
2. Create `hermitshell-agent` user and group
3. Install agent binary to `/usr/local/bin/`
4. Create directory structure under `/etc/hermitshell/`
5. Install sudoers whitelist
6. Configure sysctl flags
7. Enable and start agent systemd service
8. Pull Docker images
9. Generate default config
10. Start Docker Compose stack
11. Print access URL and default credentials

### 9.3 Manual Install

```bash
# Clone
git clone https://github.com/youruser/hermitshell
cd hermitshell

# Configure
cp .env.example .env
nano .env

# Install agent
sudo ./scripts/install-agent.sh

# Start
docker compose up -d

# Open
echo "Access at http://$(hostname -I | awk '{print $1}'):8080"
```

### 9.4 Files

```
/etc/hermitshell/
├── agent.toml              # Agent config
├── backups/                # Auto-backup before changes
├── scripts/                # Helper scripts
└── sudoers.d/hermitshell   # Copied to /etc/sudoers.d/

/data/hermitshell/
├── config/hermitshell.toml
├── db/hermitshell.db
├── dnsmasq/*.conf
├── leases/*.leases
└── backups/

/usr/local/bin/hermitshell-agent
/lib/systemd/system/hermitshell-agent.service
```

### 9.5 Default Credentials

| Setting | Default |
|---------|---------|
| Web UI URL | http://IP:8080 |
| Username | admin |
| Password | hermitshell |
| Agent secret | (randomly generated) |

**Change these immediately after install.**

---

## 13. Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Rust, Axum, SQLite |
| Frontend | Rust, Leptos, Tailwind |
| Charts | ApexCharts (via apexcharts-rs) |
| Agent | Rust (single static binary) |
| DHCP | dnsmasq |
| Firewall | nftables |

---

## 14. Project Structure

```
hermitshell/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── hermitshell/              # Main app
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── api/
│       ├── db/
│       ├── services/
│       └── web/
├── hermitshell-agent/        # Host agent
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── nftables.rs
│       ├── conntrack.rs
│       ├── dns_log.rs
│       └── systemd.rs
├── scripts/
│   ├── install-agent.sh
│   └── setup-vlans.sh
├── tests/
│   ├── vm/                   # VM-based integration tests
│   └── fixtures/
└── docs/
    └── SPEC.md
```

---

## 15. UI Design

**Anti-patterns to avoid:**
- Grafana-style dashboards (too generic, too abstract, dashboard fatigue)
- Enterprise complexity (OPNsense's 50 clicks to create a VLAN)
- Information overload (every metric ever, all the time)

**Design goals:**
- Show what you need to see, nothing more
- Actionable over informational
- Glanceable status, drill-down for details
- Mobile-friendly from day one

### 15.1 Core Screens

| Screen | Purpose | Key Elements |
|--------|---------|--------------|
| **Dashboard** | At-a-glance network health | Active devices count, quarantine alerts, bandwidth sparkline, recent events |
| **Devices** | Device list and management | Table with status/group/bandwidth, click to expand details, approve/block actions |
| **Device Detail** | Single device deep-dive | Traffic graph, connection log, DNS queries, group assignment, notes |
| **Groups** | Device categories | Trusted, IoT, Guest groups with device counts, isolation policy between groups |
| **Quarantine** | Pending approvals | New devices awaiting approval, one-click approve to target group |
| **DNS Log** | Query visibility | Per-device DNS queries, filterable, "what is this device talking to?" |
| **Settings** | System config | WAN/LAN config, DNS upstream, backup/restore |

### 15.2 Design References

Study these for inspiration (not copy):
- **Firewalla** - Consumer-friendly network security UI
- **Unifi** - Clean device management (ignore the enterprise complexity)
- **Linear** - Modern web app aesthetics, information density done right
- **Tailscale admin** - Simple, focused, no clutter

### 15.3 First-Run Experience

```
git clone https://github.com/youruser/hermitshell
cd hermitshell
docker compose up -d
```

User opens `http://router-ip:8080`:

1. **Welcome** - "Let's set up your network"
2. **Interfaces** - Auto-detect WAN/LAN, confirm or override
3. **Groups** - Show defaults (Trusted, IoT, Guest), allow customization
4. **Admin** - Set password
5. **Done** - Redirect to dashboard, show existing devices in quarantine

No CLI wizards. Everything through the UI.

---

## 16. Testing

### 13.1 VM-Based Integration Testing

Router testing without breaking your actual network:

```
┌─────────────────────────────────────────────────────────┐
│                    Test Host                             │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │   WAN VM     │    │  Router VM   │    │  LAN VM   │  │
│  │  (fake ISP)  │◄──►│ (HermitShell)│◄──►│ (clients) │  │
│  │              │    │              │    │           │  │
│  └──────────────┘    └──────────────┘    └───────────┘  │
│         │                   │                   │        │
│         └───────────────────┴───────────────────┘        │
│                    Virtual Networks                      │
└─────────────────────────────────────────────────────────┘
```

**Tools:**
- **libvirt/QEMU** or **VirtualBox** for VMs
- **Vagrant** for reproducible VM provisioning
- **pytest** or Rust test harness for assertions

**Test scenarios:**
- New device appears → lands in quarantine with temporary /30 subnet
- Approve device → assigned to group, gets permanent /30 subnet
- Block device → loses connectivity
- Quarantine isolation → device can't see other quarantine devices
- Group isolation → IoT devices can't initiate connections to Trusted devices
- DNS queries logged correctly
- DoT upstream working
- Firewall rules applied correctly

### 13.2 Unit Tests

Standard Rust tests for:
- Config parsing
- nftables rule generation
- API request/response
- Database operations

### 13.3 CI Pipeline

**GitHub Actions:**

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace
      
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - uses: docker/build-push-action@v5
        with:
          push: false
          tags: hermitshell:test

  integration:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - name: Start test VMs
        run: ./tests/vm/setup.sh
      - name: Run integration tests
        run: ./tests/vm/run.sh
      - name: Teardown
        run: ./tests/vm/teardown.sh
```

**Release process:**
- Tag triggers release build
- Build agent binary (Linux x86_64)
- Build Docker image
- Push to ghcr.io
- Create GitHub release with changelog

---

## 17. Future (V2+)

### 17.1 Core Enhancements

- [ ] **IPv6 dual-stack support** (GUA + ULA, radvd, DHCPv6-PD)
- [ ] **WireGuard VPN** for remote access
- [ ] Device profiles / security groups (Neutron-style)
- [ ] Bandwidth quotas
- [ ] Scheduled rules (parental controls)
- [ ] Home Assistant integration
- [ ] Mobile app / PWA

### 17.2 runZero Integration

[runZero](https://www.runzero.com/) provides network discovery and asset inventory. Their free tier covers home use.

**What runZero does:**
- Active + passive device discovery
- Deep fingerprinting (OS, firmware version, device type)
- Asset classification ("Nest Thermostat", "Synology NAS DS920+")
- Vulnerability correlation (device X has CVE-Y)
- They maintain an IoT knowledge base across deployments

**What HermitShell does:**
- Network segmentation (VLANs, firewall)
- Policy enforcement (quarantine, isolation, blocking)
- Traffic monitoring (bandwidth, connections, DNS)
- Real-time visibility

**Integration model:**
```
┌─────────────────┐         ┌─────────────────┐
│     runZero     │         │   HermitShell   │
│                 │         │                 │
│ • Discovery     │────────►│ • Segmentation  │
│ • Fingerprint   │  API    │ • Firewall      │
│ • CVE lookup    │         │ • Monitoring    │
│ • Asset types   │         │ • Policy        │
└─────────────────┘         └─────────────────┘
```

**Data flow:**
1. runZero scans network, identifies "Ring Doorbell Pro, firmware 1.4.26"
2. HermitShell pulls asset data via runZero API
3. HermitShell enriches device record with runZero classification
4. UI shows: device type, firmware, known vulnerabilities
5. Optional: auto-assign VLAN based on device type (all Ring devices → IoT VLAN)

**Why not build fingerprinting into HermitShell?**
- runZero has years of fingerprint data across thousands of deployments
- Maintaining an IoT knowledge base is a full-time job
- Their free tier is sufficient for home use
- Focus on what we do well (network policy), use best-of-breed for discovery

### 17.3 Behavioral Analysis (ExtraHop-inspired)

Neither runZero nor V1 HermitShell answers: "is this device acting weird?"

runZero tells you *what* a device is. HermitShell controls *where* it can go. But neither watches for behavioral anomalies over time.

**Behavioral baselines:**

Using conntrack + DNS logs we're already collecting, build per-device profiles:

```
Device: Ring Doorbell (10.0.20.15)
Normal behavior (learned over 30 days):
  - Talks to: 52.*.*.* (AWS), 54.*.*.* (AWS), ntp.ubuntu.com
  - Ports: 443 (HTTPS), 123 (NTP), 8555 (Ring proprietary)
  - Daily upload: ~500MB
  - DNS queries: ring.com, amazonaws.com, time.google.com
  - Active hours: 24/7 (motion-triggered spikes)
```

**Anomaly detection:**

Alert when device deviates from baseline:
- New destination IP/domain not seen before
- New port usage
- Traffic volume spike (10x normal)
- Connection to another internal device (lateral movement)
- DNS queries to suspicious domains

```
⚠️ Anomaly: Ring Doorbell
  - First time connecting to 185.234.xx.xx (Russia)
  - Device normally only talks to AWS
  - Recommend: investigate or block
```

**Lateral movement detection:**

IoT devices rarely need to talk to other internal devices. Alert when:
- IoT device initiates connection to Trusted group device
- Any device scans multiple internal IPs
- Quarantine device attempts internal connection

This is the gap between "asset inventory" (runZero) and "network policy" (HermitShell) - continuous behavioral monitoring.

### 17.4 Privacy-Focused Features

These differentiate HermitShell from consumer routers:

#### Outbound Firewall + Data Exfiltration Detection
Most consumer routers only filter inbound. Privacy users care about what's *leaving*:
- Flag unexpected destinations
- Detect unusual upload volumes
- Alert on devices "phoning home" to sketchy endpoints
- Detect IoT devices ignoring DHCP-assigned DNS and falling back to hardcoded resolvers (8.8.8.8)

#### DNS as a Full Privacy Layer
Not just "set your DNS server" but the complete stack:
- Local recursive resolution via Unbound (no third-party trust)
- DNS-over-HTTPS/TLS for forwarded queries
- **Transparent DNS interception** (force ALL port 53 traffic through router, even when devices hardcode their own resolvers)
- Per-device DNS policies (kids get filtered, your laptop gets unfiltered)
- Ad/tracker blocking built in
- Block DoH to external resolvers (prevent bypass of DNS filtering)

#### Network-Level VPN Kill Switch
App-based kill switches fail when the VPN app crashes. Firewall-based:
- If VPN tunnel drops, no route exists → traffic blocked entirely (not leaked to ISP)
- Per-device VPN routing (this device through Mullvad, that device direct, IoT gets no VPN)
- Currently requires significant manual nftables work

#### TLS Fingerprinting (JA3/JA4) Without Decryption
Identify client process by fingerprinting TLS Client Hello:
- "This is Chrome," "This is a Python script," "This matches known malware"
- No decryption required
- If your Nest thermostat suddenly makes connections that look like Python rather than its firmware → strong anomaly signal
- This is what Cisco sells as "Encrypted Visibility Engine"

#### Encrypted Client Hello (ECH) Awareness
ECH encrypts SNI, hiding actual destination from network observers:
- Support ECH for user devices (protect from ISP snooping)
- **Flag** when IoT devices use ECH (why is your smart plug making ECH connections?)
- Understand when you're losing visibility vs. gaining privacy

#### MAC Randomization Handling
Modern phones randomize MACs, breaking device tracking (good for privacy, bad for management):
- Correlate randomized MACs to persistent device identities
- Use DHCP fingerprint, HTTP user agent, connection patterns
- Don't undermine the privacy benefit

#### Network-Wide Ad/Tracker Blocking with Bypass Detection
Beyond Pi-hole:
- Block devices trying to bypass DNS blocking via DoH to external resolvers
- Block QUIC to known ad servers
- Block direct IP connections to tracking infrastructure

#### ISP Snooping Countermeasures
- Enforce encrypted DNS
- ECH passthrough
- Optional WireGuard wrap for all traffic
- Goal: make ISP-level surveillance functionally useless

### 17.5 Advanced Security

#### Automatic Firmware/CVE Monitoring
If runZero identifies "Synology NAS firmware 7.1.1":
- Cross-reference against vulnerability databases
- Alert: "Your NAS has 3 unpatched CVEs, consider updating"
- Make device fingerprinting data actionable, not just informational

#### Suricata IDS Integration

Network intrusion detection without blocking traffic (IDS mode, not IPS):

**Why IDS not IPS?** An IPS blocks traffic automatically, which requires extensive tuning to avoid breaking things. An IDS alerts only, giving you visibility without risk of self-inflicted outages.

```bash
apt install suricata suricata-update
```

**Configuration** (`/etc/suricata/suricata.yaml`):
```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0    # WAN
    threads: auto
  - interface: eth1    # LAN trunk
    threads: auto

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules     # Managed by suricata-update
```

**Rule sources** (free):
```bash
suricata-update enable-source et/open              # Emerging Threats open ruleset
suricata-update enable-source oisf/trafficid       # Traffic identification
suricata-update enable-source sslbl/ssl-fp-blacklist  # Malicious SSL certs
suricata-update enable-source sslbl/ja3-fingerprints  # Malicious JA3 fingerprints
suricata-update enable-source tgreen/hunting       # Threat hunting rules
suricata-update
```

**Auto-update rules** (cron):
```bash
# /etc/cron.d/suricata-rules
0 */6 * * * root suricata-update && kill -USR2 $(pidof suricata)
```

**JSON logs** for integration:
Suricata writes structured JSON to `/var/log/suricata/eve.json`, which the agent can:
- Correlate alerts with device/flow data
- Forward to the web UI for display
- Ship to external logging (Elasticsearch, Grafana Loki)

**UI integration:**
- Alerts timeline with device attribution
- "This device triggered X alerts in the past 24h"
- Severity-based notifications

### 17.6 Zero Cloud Philosophy

The anti-Securifi, anti-Firewalla play:
- Everything works locally
- No account creation
- No phone-home telemetry
- No "service discontinued" risk
- Remote access via WireGuard tunnel you control, not vendor cloud relay

### 17.7 Safe Updates with Auto-Rollback

Inspired by [router7](https://router7.org/) (Michael Stapelberg's pure-Go router):

**Problem:** Router updates that break connectivity leave you locked out.

**Solution:** Diagnostics daemon monitors connectivity; auto-rollback on failure.

```
Update flow:
1. Backup current config
2. Apply update
3. Diagnostics daemon pings external hosts (1.1.1.1, 8.8.8.8)
4. If connectivity lost for >60s → automatic rollback
5. If connectivity OK for 5min → commit update
```

**Additional router7 patterns worth adopting:**
- **State as JSON files** - All config in `/perm` partition as human-readable JSON, easy to backup/restore
- **Ring buffer for debug packets** - Store recent DHCP/RA packets, stream to Wireshark for debugging
- **Fast updates via kexec** - Only ~13 seconds of connectivity loss during kernel updates
- **Services communicate via files + signals** - Simple IPC: write state file, send SIGUSR1

### 17.8 NAT Type Configuration

**Problem identified on Lobsters:** OpenBSD's pf only does Symmetric/Endpoint-Dependent NAT, breaking P2P applications (gaming, WebRTC, torrents).

nftables can do Full Cone (Endpoint-Independent) NAT:

```nft
# Full cone NAT - any external host can send to the mapped port
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "eth0" masquerade persistent,fully-random
    }
}
```

**Configuration option:**
```toml
[nat]
# "symmetric" = strict, most secure (default)
# "full_cone" = permissive, better for gaming/P2P
type = "symmetric"

# Per-device override
[[nat.overrides]]
device = "gaming-pc"
type = "full_cone"
```

### 17.9 Alpine-Style Diskless Mode

For SD card reliability (Raspberry Pi deployments), inspired by Lobsters discussion:

**Problem:** SD cards wear out from writes; corruption loses config.

**Solution:** Read-only root, config as overlay:
- Boot files (kernel, initramfs) - easy to recreate
- APK/deb package cache - easy to refetch
- Config overlay (apkovl-style) - tiny, easy to backup everywhere

```
/
├── boot/           # Read-only
├── rootfs/         # Read-only SquashFS
└── perm/           # Small ext4 for config only
    ├── hermitshell.toml
    ├── devices.json
    └── backups/
```

### 17.10 Priority for V2

**Highest impact** (what generates the most excitement in privacy communities):
1. Outbound firewall + data exfiltration detection
2. Network-level VPN kill switch with per-device routing
3. JA3/JA4 TLS fingerprinting
4. Transparent DNS interception (force hardcoded DNS through router)
5. Safe updates with auto-rollback

---

## 18. System Architecture (Learned from Reference Systems)

This section addresses architectural concerns learned from studying production Linux routers: [router7](https://router7.org/), [koduinternet-cpe](https://github.com/tonusoo/koduinternet-cpe), and community implementations.

### 18.1 Failure Modes & Resilience

**Critical principle:** A router crash should not break the network. nftables rules persist in kernel memory; systemd-networkd maintains DHCP leases independently.

#### Agent Crash

| Symptom | Impact | Recovery |
|---------|--------|----------|
| Agent process dies | UI unavailable, no new config changes | Network continues working (rules in kernel). systemd restarts agent (`Restart=always`) |
| Agent unable to start | Same as above | Boot into recovery, check logs, fix config |

**Design decision:** Agent is stateless runtime—it reads config, applies it, then monitors. If it crashes, existing network state persists.

#### Container Crash

| Symptom | Impact | Recovery |
|---------|--------|----------|
| Docker daemon dies | Web UI unavailable | SSH still works (host), network still works (kernel rules). `systemctl restart docker` |
| hermitshell container dies | UI unavailable | Network works. Docker restarts container automatically |

**Critical:** SSH access is via host network, not container. Container death doesn't lock you out.

#### Systemd Service Failures

| Service | If it fails | Network impact | Recovery |
|---------|-------------|----------------|----------|
| systemd-networkd | VLANs may not come up on reboot | Existing VLANs persist until reboot | `systemctl restart systemd-networkd` |
| systemd-resolved | DNS stops | No DNS resolution | `systemctl restart systemd-resolved`, clients retry |
| nftables.service | Rules may not load on boot | If after boot: rules persist. On boot: no firewall | `nft -f /etc/nftables.conf` |

#### Disk Corruption / Full Disk

**SQLite corruption:**
- Agent detects on startup, refuses to start
- Recovery: restore from `/etc/hermitshell/backups/` or delete and rebuild from network state

**Log disk full:**
- Agent logs to journald (auto-rotated)
- conntrack logs rotation: configurable, default 7 days
- DNS logs rotation: configurable, default 7 days

#### Boot-Order Dependencies (from koduinternet-cpe)

```ini
# /lib/systemd/system/hermitshell-agent.service
[Unit]
Description=HermitShell Network Agent
After=network-online.target systemd-networkd.service systemd-resolved.service nftables.service
Wants=network-online.target
Requires=systemd-networkd.service

[Service]
Type=simple
User=hermitshell-agent
Group=hermitshell-agent
ExecStart=/usr/local/bin/hermitshell-agent
Restart=always
RestartSec=5

# Don't start until network is really up
ExecStartPre=/usr/lib/systemd/systemd-networkd-wait-online --any

[Install]
WantedBy=multi-user.target
```

### 18.2 State Management & Source of Truth

**Principle:** Single source of truth prevents drift. SQLite is authoritative; systemd configs are derived.

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   SQLite DB     │──────│     Agent       │──────│  Systemd/nft    │
│  (authoritative)│      │   (derives)     │      │   (applied)     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

| Data | Source of Truth | Derived From |
|------|-----------------|--------------|
| Device groups | SQLite `device_groups` table | → nftables routing policy |
| Device subnets | SQLite `devices` table (id → subnet) | → Interface addresses, DHCP reservations |
| Firewall policy | SQLite `device_groups.isolation` + `devices.blocked` | → nftables ruleset |
| DNS upstream | `hermitshell.toml` | → resolved.conf.d/ |
| DHCP leases | dnsmasq (runtime) | Observed by agent |

#### Reconciliation on Startup

Agent startup sequence (inspired by router7):

```
1. Load hermitshell.toml (static config)
2. Open SQLite database
3. Read current system state:
   - `ip addr show` → existing gateway addresses on LAN interface
   - `nft list ruleset` → existing rules
   - `resolvectl status` → DNS state
4. Compare DB state to system state
5. Apply diff:
   - Missing gateway addresses → add (for each approved device)
   - Firewall rules → regenerate and apply (atomic)
   - DHCP reservations → regenerate dnsmasq config
6. Start monitoring (conntrack, nflog, DHCP events)
```

**On drift detection:**
- Log warning: "Gateway address 10.0.99.1 exists but no device in database"
- Don't auto-delete (safety)
- UI shows "orphaned" resources for manual cleanup

#### State Persistence (from router7)

router7 stores all state as JSON files in `/perm`. We adopt a hybrid:

```
/etc/hermitshell/
├── hermitshell.toml      # Static config (interfaces, DNS upstream)
├── hermitshell.db        # SQLite (devices, groups, rules)
├── state/                # Runtime state (JSON, not authoritative)
│   ├── connectivity.json # Last connectivity check result
│   ├── wan_lease.json    # Current WAN DHCP lease
│   └── devices_seen.json # Recently seen MACs (cache)
└── backups/              # Timestamped backups
    ├── hermitshell.db.2025-02-03T14:00:00
    └── nftables.nft.2025-02-03T14:00:00
```

### 18.3 Data Flow Diagrams

#### New Device Connection

```
┌─────────┐    ┌──────────────┐    ┌────────────┐    ┌─────────────┐
│ Device  │    │   Switch     │    │  Router    │    │   Agent     │
│ (new)   │    │   (VLAN)     │    │  (kernel)  │    │             │
└────┬────┘    └──────┬───────┘    └─────┬──────┘    └──────┬──────┘
     │                │                   │                   │
     │ DHCP Discover  │                   │                   │
     │ (untagged)     │                   │                   │
     │───────────────>│ Tags as VLAN 40   │                   │
     │                │ (Quarantine)      │                   │
     │                │──────────────────>│                   │
     │                │                   │ DHCP Offer        │
     │                │                   │ (from networkd)   │
     │<───────────────│<──────────────────│                   │
     │                │                   │                   │
     │                │                   │ dhcp-event hook   │
     │                │                   │──────────────────>│
     │                │                   │                   │ INSERT device
     │                │                   │                   │ (approved=0)
     │                │                   │ Regenerate rules  │
     │                │                   │<──────────────────│
     │                │                   │                   │
     │ (Can reach     │                   │ Quarantine rules: │
     │  internet but  │                   │ - Internet: ACCEPT│
     │  not LAN)      │                   │ - Intra-VLAN: DROP│
     │                │                   │ - Other VLANs:DROP│
```

#### Device Approval

```
┌─────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────────┐
│  Admin  │    │  Web UI     │    │   Agent   │    │   Kernel     │
│         │    │             │    │           │    │              │
└────┬────┘    └──────┬──────┘    └─────┬─────┘    └──────┬───────┘
     │                │                  │                  │
     │ "Approve to    │                  │                  │
     │  Trusted"      │                  │                  │
     │───────────────>│ POST /devices/   │                  │
     │                │ {group: "trusted"}                  │
     │                │─────────────────>│                  │
     │                │                  │ UPDATE devices   │
     │                │                  │ SET group_id=1,  │
     │                │                  │     approved=1   │
     │                │                  │                  │
     │                │                  │ Add gateway addr │
     │                │                  │ 10.0.{id}.1/30   │
     │                │                  │─────────────────>│
     │                │                  │                  │ ip addr add
     │                │                  │                  │
     │                │                  │ Regenerate rules │
     │                │                  │─────────────────>│
     │                │                  │                  │ nft -f rules.nft
     │                │                  │                  │
     │                │                  │ Update DHCP      │
     │                │                  │ reservation      │
     │                │                  │─────────────────>│
     │                │                  │                  │ kill -HUP dnsmasq
     │                │ 200 OK           │                  │
     │                │<─────────────────│                  │
     │ "Device moved  │                  │                  │
     │  to Trusted"   │                  │                  │
     │<───────────────│                  │                  │
     │                │                  │                  │
     │ (Device gets   │                  │                  │
     │  permanent /30 │                  │                  │
     │  via DHCP)     │                  │                  │
```

### 18.4 Upgrade & Migration

#### Agent Upgrade (No Downtime)

```bash
# 1. Download new binary
curl -L https://github.com/.../hermitshell-agent -o /tmp/hermitshell-agent

# 2. Verify signature
gpg --verify /tmp/hermitshell-agent.sig

# 3. Backup current
cp /usr/local/bin/hermitshell-agent /usr/local/bin/hermitshell-agent.bak

# 4. Replace (agent restarts via systemd)
mv /tmp/hermitshell-agent /usr/local/bin/
chmod +x /usr/local/bin/hermitshell-agent
systemctl restart hermitshell-agent
```

**Network impact:** ~2 seconds (systemd restarts process). Kernel rules persist. Existing connections unaffected.

#### Database Schema Migrations

Agent handles migrations on startup:

```rust
fn migrate_db(conn: &Connection) -> Result<()> {
    let version: i32 = conn.query_row(
        "SELECT version FROM schema_version", [], |r| r.get(0)
    ).unwrap_or(0);
    
    if version < 1 {
        conn.execute_batch(include_str!("migrations/001_initial.sql"))?;
    }
    if version < 2 {
        conn.execute_batch(include_str!("migrations/002_add_notes.sql"))?;
    }
    // ...
    conn.execute("UPDATE schema_version SET version = ?", [CURRENT_VERSION])?;
    Ok(())
}
```

**Safety:** Migrations are idempotent. Failed migration = agent won't start = network keeps working.

#### Config Format Versioning

```toml
# /etc/hermitshell/hermitshell.toml
version = 1  # Config format version

[network]
# ...
```

Agent refuses to start if `version` is higher than it understands (forward compatibility).

### 18.5 Observability

#### Agent Logs

Structured JSON to journald:

```json
{"ts":"2025-02-03T14:00:00Z","level":"info","msg":"Device approved","mac":"aa:bb:cc:dd:ee:ff","vlan":"trusted"}
{"ts":"2025-02-03T14:00:01Z","level":"warn","msg":"Blocked connection attempt","src":"10.0.20.15","dst":"10.0.10.5","reason":"IoT→Trusted denied"}
```

Query:
```bash
journalctl -u hermitshell-agent -o json | jq 'select(.level=="warn")'
```

#### Health Checks

Agent exposes `/health` endpoint (localhost only):

```json
{
  "status": "healthy",
  "checks": {
    "database": "ok",
    "networkd": "ok",
    "resolved": "ok",
    "wan_connectivity": "ok",
    "last_wan_check": "2025-02-03T14:00:00Z"
  },
  "uptime_seconds": 86400,
  "version": "0.1.0"
}
```

UI shows health status. External monitoring can poll this endpoint.

#### Metrics (Optional, V2)

Prometheus metrics at `/metrics`:

```
hermitshell_devices_total{vlan="trusted"} 5
hermitshell_devices_total{vlan="iot"} 12
hermitshell_devices_total{vlan="quarantine"} 2
hermitshell_wan_rx_bytes_total 123456789
hermitshell_wan_tx_bytes_total 987654321
hermitshell_dns_queries_total{type="A"} 10000
hermitshell_dns_queries_blocked_total 500
```

### 18.6 Resource Limits & Capacity

| Resource | Expected Usage | Limit | Mitigation |
|----------|----------------|-------|------------|
| Devices | Typical home: 20-50 | Tested to 500 | SQLite handles it fine |
| conntrack entries | ~50k typical | 262144 (sysctl) | Increase if needed |
| DNS log entries | ~10k/day | 7 days default | Auto-rotation |
| SQLite DB size | ~10MB typical | 100MB warning | Prune old logs |
| Agent memory | ~20MB | 100MB limit | systemd MemoryMax |

```ini
# /lib/systemd/system/hermitshell-agent.service
[Service]
MemoryMax=100M
MemoryHigh=80M
```

### 18.7 Time & Clock Dependencies

**Problem:** DHCP leases, log timestamps, and TLS certificates require accurate time.

**Solution (from koduinternet-cpe):**

1. **Hardware clock:** Set on install, survives reboots
2. **systemd-timesyncd:** Syncs NTP on boot
3. **Graceful degradation:** If NTP unreachable, use hardware clock

```ini
# /etc/systemd/timesyncd.conf
[Time]
NTP=time.cloudflare.com time.google.com
FallbackNTP=0.pool.ntp.org 1.pool.ntp.org
```

**Boot sequence:**
```
1. systemd-timesyncd starts
2. Attempts NTP sync (timeout 30s)
3. If fails: use RTC (logged warning)
4. systemd-networkd starts (DHCP can work without accurate time)
5. systemd-resolved starts
6. Agent starts
```

### 18.8 Security Threat Model

#### In Scope (We Defend Against)

| Threat | Mitigation |
|--------|------------|
| Compromised IoT device attacking LAN | VLAN isolation, nftables inter-VLAN rules |
| Malicious device on network | Quarantine by default, must be approved |
| DNS-based tracking by ISP | DoT upstream, DNSSEC validation |
| UI vulnerabilities | Container isolation, agent validates all input |
| Local attacker with network access | Admin auth required, HTTPS optional |
| Failed update bricks router | Auto-rollback on connectivity loss |

#### Out of Scope (Not Defended)

| Threat | Why |
|--------|-----|
| Physical access to router | Game over. Attacker can reset, reflash, etc. |
| Compromised upstream DNS | Use trusted resolver (Cloudflare, Quad9). DNSSEC helps but not perfect |
| Nation-state adversary | Traffic analysis, timing attacks. Use Tor/VPN for high-threat model |
| Supply chain attack on dependencies | Reproducible builds help. Audit critical deps |
| Side-channel attacks | Not a high-security device. Use dedicated hardware for secrets |

#### Trust Hierarchy

```
Most Trusted                              Least Trusted
     │                                          │
     ▼                                          ▼
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│ Host OS │──│  Agent  │──│ Web UI  │──│Trusted  │──│  IoT    │
│ (root)  │  │(limited │  │(contain-│  │ VLAN    │  │  VLAN   │
│         │  │ sudo)   │  │  er)    │  │         │  │         │
└─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘
```

---

## 19. Open Questions

### Resolved

| Question | Decision |
|----------|----------|
| conntrack volume | Sampling OK for V1; add full logging if needed |
| Counter granularity | Per-MAC sufficient for V1 |
| Agent auth | Unix socket (filesystem permissions, no secret needed) |
| ARM64 / Raspberry Pi | Not supported in V1 |
| IPv6 | Defer to V2 |
| DNS/DHCP stack | Pure systemd (networkd + resolved) |
| DNS query logging | nflog at firewall level (resolved lacks per-device attribution) |
| Ad blocking | External (Pi-hole) or upstream filter (AdGuard DNS) for V1; local blocking V2 |

### Still Open

1. **Installer UX**: Interactive CLI wizard or just documentation?
2. **Backup/restore format**: JSON dump? SQLite copy? Both?
3. **Log rotation**: How long to retain conntrack/DNS logs? User configurable?
4. **systemd-resolved patch**: Contribute structured query logging upstream?

---

## 20. Security

### 20.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER CONTAINER                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  hermitshell (web UI + API)                               │  │
│  │  - Isolated filesystem                                    │  │
│  │  - No CAP_NET_ADMIN                                       │  │
│  │  - No access to host binaries                             │  │
│  │  - Can ONLY talk to agent via unix socket                 │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Unix socket (/run/hermitshell/agent.sock)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AGENT (SECURITY BOUNDARY)                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  hermitshell-agent                                        │  │
│  │  - Validates ALL input before executing                   │  │
│  │  - Sudoers whitelist (explicit commands only)             │  │
│  │  - Socket permissions enforce access control              │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ sudo (whitelisted commands)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         HOST KERNEL                             │
│  nftables, ip, conntrack, vnstat, sysctl                        │
└─────────────────────────────────────────────────────────────────┘
```

**The agent is the security boundary.** A compromised container can only send requests to the agent via the unix socket. The agent must validate everything.

### 20.2 What Docker Provides (No Extra Work Needed)

| Threat | Docker mitigation |
|--------|-------------------|
| Web app writes to host filesystem | Container filesystem isolated |
| Web app executes host commands | No access to host binaries |
| Web app modifies systemd units | Can't see `/lib/systemd/system/` |
| Web app touches nftables directly | No `CAP_NET_ADMIN` |
| Web app escalates to root | No setuid binaries in container |

CVE-2024-41637 (RaspAP privilege escalation via systemd file write) **cannot happen** because the web app runs in a container with no host filesystem access.

### 20.3 What We Must Implement (Agent Security)

The agent runs on the host and is the only path from container to kernel. These protections are critical:

**1. Input validation (most important):**
```rust
// Agent must validate nftables rules before applying
fn apply_rules(rules: &str) -> Result<()> {
    // Parse and validate syntax
    validate_nft_syntax(rules)?;
    
    // Check for dangerous patterns
    reject_if_contains(rules, &["#!/", "$(", "`", "&&", "||", ";"])?;
    
    // Write to temp file, apply with nft -c (check mode) first
    let temp = write_temp_file(rules)?;
    run_command(&["nft", "-c", "-f", &temp])?;  // Dry run
    run_command(&["sudo", "nft", "-f", &temp])?; // Apply
    Ok(())
}
```

**2. Sudoers whitelist:**
```sudoers
# /etc/sudoers.d/hermitshell
# Explicit commands only - no wildcards for arguments that matter

hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/nft -c -f /tmp/hermitshell-*.nft
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/nft -f /tmp/hermitshell-*.nft
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/nft list counters
hermitshell-agent ALL=(ALL) NOPASSWD: /sbin/ip link add link eth1 name eth1.* type vlan id *
hermitshell-agent ALL=(ALL) NOPASSWD: /sbin/ip link del eth1.*
hermitshell-agent ALL=(ALL) NOPASSWD: /sbin/ip link set eth1.* up
hermitshell-agent ALL=(ALL) NOPASSWD: /sbin/ip addr add */24 dev eth1.*
hermitshell-agent ALL=(ALL) NOPASSWD: /bin/systemctl restart dnsmasq
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/sbin/conntrack -E -o xml
hermitshell-agent ALL=(ALL) NOPASSWD: /usr/bin/vnstat --json *
```

**3. Shared secret authentication:**
```rust
// Every request to agent must include secret
fn authenticate(req: &Request) -> Result<()> {
    let provided = req.header("X-Agent-Secret")?;
    let expected = config.secret;
    
    // Constant-time comparison
    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err(AuthError::InvalidSecret);
    }
    Ok(())
}
```

**4. Localhost binding:**
```toml
# /etc/hermitshell/agent.toml
listen = "127.0.0.1:9999"  # NEVER 0.0.0.0
```

### 20.4 dnsmasq Container

dnsmasq runs with `network_mode: host` and `CAP_NET_ADMIN`. This is necessary for DHCP but increases risk:

| Concern | Mitigation |
|---------|------------|
| Config injection | hermitshell writes config files, dnsmasq only reads them |
| Process escape | Minimal attack surface (dnsmasq is well-audited) |
| Network access | Expected - it's the DHCP server |

We do NOT mount Docker socket into any container.

### 20.5 Automatic Security Updates

Automatic updates ensure the router stays patched without manual intervention:

```bash
# Install unattended-upgrades
apt install unattended-upgrades apt-listchanges
```

```ini
# /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

```ini
# /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};

// Auto-remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Reboot at 3am if required (brief network outage)
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

This makes the router more secure than most consumer routers, which rarely receive updates.

### 20.6 Backup Before Changes

Agent backs up configs before modification:

```bash
/etc/hermitshell/backups/
├── network-2025-02-02T14:00:00/
│   ├── 10-wan.network
│   ├── 30-vlan-trusted.network
│   └── ...
├── resolved-2025-02-02T14:00:00/
│   └── hermitshell.conf
└── nftables-2025-02-02T14:00:00.nft
```

30-day retention, configurable.

### 20.7 Summary

| Component | Where | Key protection |
|-----------|-------|----------------|
| hermitshell (web) | Container | Docker isolation (automatic) |
| hermitshell-agent | Host | Input validation + sudoers whitelist |
| systemd-networkd | Host | Agent generates configs, systemd applies |
| systemd-resolved | Host | Agent generates configs, validated |
| Docker socket | Not mounted | N/A |

---

## 21. Community Notes

Collected from Lobsters discussions, HN threads, and other sources. These represent real-world experience from people running custom routers.

### 15.1 Why Custom Over Commercial

> "The ISP-provided box is now sufficiently good that the incremental benefit of doing something custom is small... [but] one big bonus you get with a custom router is that you control LAN DNS. So you can have FQDNs, SSLs issued by LE or ZeroSSL using the DNS01 auth scheme."

> "Consumer routers like TP-Link, Netgear, D-Link et al usually have terrible software. I'd only consider buying these if I was going to replace the software with something like OpenWRT. Without replacing the software, expect these to be flakey and unreliable."

> "Most commercial routers are Linux based but don't use queues to optimize the connection like FQ-Codel, CAKE, etc."

### 15.2 OPNsense/pfSense Complexity

> "OPNSense has lost its luster for me over time. It's super complex for my use case as a home user. And even slightly advanced features like creating a VLAN are like 50 clicks across three different UI flows."

This validates our design goal: simple UI for common tasks, full control when needed.

### 15.3 systemd-networkd Endorsement

> "I setup a Debian system like this a few weeks ago. N100 board with 4x2.5G and 6 SATA means it's both serving as router/gateway/firewall and my local NAS. systemd-networkd configures the lan bridge and forwarding for the needed devices. DHCPv6 towards my ISP for PD and RA on the lan is also handled with systemd-networkd. Simple nftables script for firewall."

Multiple commenters confirmed systemd-networkd handles VLANs, bridges, DHCP client, and even DHCP server adequately.

### 15.4 Web UI Security Warning

> "Interactive web interfaces are just massive security holes. If you let someone access it (e.g. if they can plug into your ethernet or use your wifi) you have effectively given them control over your whole network."

This reinforces our Docker isolation approach and the importance of the agent security boundary.

### 15.5 DoH Privacy Limitation

> "People who truly need privacy, like journalists in countries with a privacy compromising policy, cannot trust DoH! The IP address of the destination server cannot be hidden with DoH, even if everything about the traffic itself is encrypted."

This is why ECH (Encrypted Client Hello) matters for V2 - it hides SNI, which DoH doesn't address.

### 15.6 Separation of Concerns

> "If you use separate devices for each function [router, switch, WiFi AP, modem], you have more control over your networking setup and you can optimize for the features you care about. For example, I used to shop for all-in-one routers based on how many Ethernet jacks they had, but that's ridiculous because you can buy a $20 switch to add more jacks."

HermitShell assumes this architecture: dedicated router box + external managed switch + external WiFi APs.

### 15.7 Hardware Recommendations

From community consensus:

| Hardware | Notes |
|----------|-------|
| **N100 mini PCs** (Topton, etc.) | Current favorite. 4x 2.5GbE, low power, ~$150-200 |
| **Protectli Vault** | Premium option. 4-6 ports, fanless, ~$300-400 |
| **PC Engines APU2** | Older but proven. 3x 1GbE, ~$150. May struggle with gigabit + VPN |
| **Qotom Q190G4** | Fanless x86, 4x 1GbE. Used by jsravn article |
| **Raspberry Pi 4** | Budget option. Needs USB Ethernet adapter. SD card reliability concerns |
| **GL-iNet devices** | Good for travel/secondary. "User friendly UI + full OpenWRT if you want it" |
| **Turris Omnia** | Premium OpenWRT. "Fantastic opt-in support features, regular updates" |

> "I love having mainline security support, the ability to run any Debian package I please, and never having to worry if my router is a network bottleneck."

### 15.8 VyOS Mention

> "x86 hardware for routing & firewall, currently running VyOS (and configured using an ansible playbook I wrote when learning ansible). Using a few vlans to segment the network."

VyOS is worth studying for its CLI-first, Ansible-friendly configuration model.

### 15.9 NixOS Router Pattern

> "If you're running a complex routing setup or dealing with multiple VLANs, you might want to look into my zone-based-firewall script... Part of the zone firewall is a low-level way to add rules to an nftables firewall from different places."

Declarative, reproducible router config is appealing. HermitShell's TOML config aims for similar benefits without requiring NixOS.

---

## 22. References

### Architecture & Implementation
- [Building a Router from Scratch with Debian](https://tongkl.com/building-a-router-from-scratch-part-1/) - VLAN and ARP troubleshooting
- [koduinternet-cpe](https://github.com/tonusoo/koduinternet-cpe) - Production Linux router; sysctl, dhclient hooks, service restart ordering
- [Puomi](https://puomi.liw.fi/) - Debian router using systemd-networkd and Ansible
- [RaspAP](https://raspap.com/) - Installer patterns, privilege separation, vnstat integration
- [Building Your Own Low Latency Home Router](https://jsravn.com/2018/06/12/building-your-own-low-latency-home-router/) - fq_codel, ethtool offloads, unattended upgrades
- [Linux Router, Firewall and IDS Appliance](https://nbailey.ca/post/linux-firewall-ids/) - Suricata IDS integration, ansible automation
- [router7](https://router7.org/) - Pure-Go router; auto-rollback, state-as-JSON, fast kexec updates

### Network Stack (systemd)
- [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd.network.html) - Network configuration + DHCP server
- [systemd-resolved](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html) - DNS resolver with DoT, DNSSEC
- [ArchWiki: systemd-networkd](https://wiki.archlinux.org/title/Systemd-networkd) - DHCPServer configuration examples
- [ArchWiki: systemd-resolved](https://wiki.archlinux.org/title/Systemd-resolved) - DoT setup, DNSStubListenerExtra
- [CAKE qdisc](https://www.bufferbloat.net/projects/codel/wiki/Cake/) - Modern queue discipline for bufferbloat prevention
- [cake-autorate](https://github.com/lynxthecat/cake-autorate) - Dynamic bandwidth adjustment for variable connections

### DNS Query Logging
- [nflog target](https://wiki.nftables.org/wiki-nftables/index.php/Logging_traffic) - nftables packet logging to userspace
- [systemd-resolved monitor feature request](https://github.com/systemd/systemd/issues/20264) - Upstream issue for structured query logging

### V2 Candidates
- [Kea DHCP](https://www.isc.org/kea/) - ISC's modern DHCP server with REST API
- [Unbound](https://nlnetlabs.nl/projects/unbound/about/) - Recursive DNS resolver with query logging
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) - Lightweight DHCP + DNS with log-queries

### Security
- [Home Router Security Report 2020](https://www.fkie.fraunhofer.de/content/dam/fkie/de/documents/HomeRouter/HomeRouterSecurity_2020_Bericht.pdf) - Fraunhofer FKIE analysis of consumer router vulnerabilities
- [Suricata IDS](https://suricata.io/) - Open source intrusion detection
- [RFC 4890](https://tools.ietf.org/html/rfc4890) - ICMPv6 filtering recommendations
- [Linux ARP sysctl](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt) - ARP hardening
- [Linux IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) - ICMP rate limiting, rp_filter
- [CVE-2024-41637](https://nvd.nist.gov/vuln/detail/CVE-2024-41637) - RaspAP privilege escalation (what not to do)

### Firewall
- [nftables wiki](https://wiki.nftables.org/)
- [Simple ruleset for a home router](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_home_router)

### Community Discussions
- [Lobsters: Home router recommendations](https://lobste.rs/s/7hxrjv/home_router_recommendations)
- [Lobsters: What do you use for your home networking setup?](https://lobste.rs/s/dbr7yu/what_do_you_use_for_your_home_networking)
- [Lobsters: OpenBSD Router Guide](https://lobste.rs/s/lae80y/openbsd_router_guide)
- [Lobsters: First Router Designed Specifically For OpenWrt](https://lobste.rs/s/gxj1h4/first_router_designed_specifically_for)

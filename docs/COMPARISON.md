# HermitShell vs. Alternatives

How HermitShell compares to the platforms most home and prosumer users actually choose.

## Philosophy

| | HermitShell | OpenWrt | Firewalla | Ubiquiti UniFi |
|---|---|---|---|---|
| **Model** | Software on your hardware | Firmware on supported routers | Proprietary appliance | Proprietary appliance + APs |
| **Cloud dependency** | None | None | Optional (local mode available) | Required for remote management |
| **Source code** | MIT, full source | GPL, full source | Closed | Closed |
| **Target user** | Privacy-focused home/prosumer | Tinkerers, embedded devs | Non-technical home users | Prosumer, small business |
| **Price** | Free + your hardware | Free + supported router | $228-$579 (appliance) | $299-$599 (gateway) + APs |

## Feature Comparison

| Feature | HermitShell | OpenWrt | Firewalla | Ubiquiti |
|---|---|---|---|---|
| **Per-device isolation** | /32 subnets, each device gets its own network | VLANs (manual config) | Microsegmentation (Gold+) | VLANs via controller |
| **Device groups** | 6 built-in (trusted, IoT, servers, guest, quarantine, blocked) | Manual VLAN/firewall rules | Flexible groups | Profiles via controller |
| **DNS ad blocking** | Built-in (Blocky) | Packages (adblock, AGH) | Built-in | Not built-in |
| **WireGuard VPN** | Built-in, dual-stack | Package | Built-in | Built-in |
| **Behavioral analysis** | Built-in (anomaly detection, alerts) | Not built-in | IDS/IPS (Suricata-based) | IDS/IPS |
| **QoS** | CAKE + fq_codel, per-device DSCP | SQM (package) | Smart Queue | Not built-in |
| **IPv6** | Dual-stack, RA, DHCPv6-PD, ULA, pinholes | Full | Full | Full |
| **Port forwarding** | Manual + UPnP/NAT-PMP/PCP | Manual + packages | GUI | GUI |
| **mDNS across VLANs** | Built-in proxy with group filtering | Avahi package | Automatic | mDNS reflector |
| **Connection logging** | Built-in, syslog/webhook export | Packages | Built-in | Built-in |
| **Backup/restore** | JSON export, optional AES-256-GCM encryption | Sysupgrade backup | Cloud backup | Cloud backup |
| **Web UI** | Built-in (Leptos SSR) | LuCI | Mobile app + web | UniFi controller |
| **WiFi AP management** | TP-Link EAP720 only | Native (runs on the AP) | Not applicable (wired only) | UniFi APs only |
| **Multi-WAN failover** | Not yet | Packages (mwan3) | Built-in | Built-in |
| **Setup** | Install script + web wizard | Flash firmware, LuCI | Plug in, app setup | Plug in, app setup |
| **Updates** | Manual (installer --upgrade) | Sysupgrade | Automatic OTA | Automatic OTA |
| **Multi-admin** | Single admin | Multi-user | Multi-user | Multi-user |

## Where HermitShell is Stronger

**Device isolation without configuration.** Every device gets its own /32 subnet with proxy ARP. Devices cannot see each other at L2 or L3 unless explicitly allowed by group policy. OpenWrt, Firewalla, and UniFi require manual VLAN setup to achieve similar isolation.

**No cloud, no account, no telemetry.** The router works entirely offline. There is no vendor account, no cloud dependency, no usage telemetry. Firewalla and Ubiquiti both phone home by default.

**Transparent security model.** Every security compromise is documented in [SECURITY.md](SECURITY.md) with what, why, risk, and proper fix. No other consumer router platform publishes this level of detail about their security trade-offs.

**Behavioral analysis built in.** Traffic anomaly detection, DHCP fingerprint change alerts, and DNS reputation monitoring ship out of the box. OpenWrt has no equivalent; Firewalla and Ubiquiti offer IDS but not behavioral baselines.

**Full source, permissive license.** MIT licensed. Inspect, modify, and redistribute without restriction. OpenWrt is GPL (copyleft); Firewalla and Ubiquiti are closed source.

## Where HermitShell is Weaker

**WiFi AP support is limited.** Currently only TP-Link EAP720 standalone mode. OpenWrt runs directly on APs. Ubiquiti has a full AP ecosystem. Firewalla is wired-only but pairs with any AP. If you have existing APs that aren't EAP720s, you'll manage WiFi separately.

**Fewer supported hardware platforms.** x86_64 and aarch64 only. OpenWrt runs on MIPS, ARM32, and hundreds of specific router boards. HermitShell requires a mini PC or SBC with two network interfaces.

**No automatic updates.** You must run the upgrade command manually. Firewalla and Ubiquiti push updates automatically.

**Debian only.** The installer requires Debian 12 or Raspbian. OpenWrt is its own OS; Firewalla and Ubiquiti ship their own firmware.

**Newer project.** Smaller community, less battle-tested in production. OpenWrt has 20+ years of history. Firewalla and Ubiquiti have dedicated support teams.

**Single admin.** One admin account, no RBAC. Fine for a home user, limiting for families or small offices that want delegated access.

## When to Choose HermitShell

- You want automatic per-device isolation without configuring VLANs
- You don't want your router phoning home to a cloud service
- You have a spare mini PC or SBC and prefer running open-source software you can audit
- You want behavioral analysis and DNS monitoring without a subscription
- You're comfortable with Debian and a CLI install process

## When to Choose Something Else

- You need plug-and-play with a mobile app (Firewalla)
- You want a full AP ecosystem managed from one controller (Ubiquiti)
- You want to run the router OS directly on a consumer WiFi router (OpenWrt)
- You need multi-WAN failover or multi-admin today

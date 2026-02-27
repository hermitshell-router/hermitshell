# HermitShell vs. Alternatives

How HermitShell compares to the platforms most home and prosumer users actually choose.

## Philosophy

| | HermitShell | OpenWrt | OPNsense | Firewalla | Ubiquiti UniFi | RaspAP | VyOS |
|---|---|---|---|---|---|---|---|
| **Model** | Software on your hardware | Firmware on supported routers | Software on your hardware | Proprietary appliance | Proprietary appliance + APs | Software on Raspberry Pi / Debian | Software on your hardware |
| **Cloud dependency** | None | None | None | Optional (local mode available) | Required for remote management | None | None |
| **Source code** | MIT, full source | GPL, full source | BSD, full source | Closed | Closed | GPL, full source | GPL, full source (rolling); proprietary (LTS) |
| **Target user** | Privacy-focused home/prosumer | Tinkerers, embedded devs | Sysadmins, small business | Non-technical home users | Prosumer, small business | Pi hobbyists, WiFi tinkerers | Network engineers, enterprise |
| **Price** | Free + your hardware | Free + supported router | Free + your hardware | $228-$579 (appliance) | $299-$599 (gateway) + APs | Free + Raspberry Pi | Free (rolling) or paid (LTS) |

## Feature Comparison

| Feature | HermitShell | OpenWrt | OPNsense | Firewalla | Ubiquiti | RaspAP | VyOS |
|---|---|---|---|---|---|---|---|
| **Per-device isolation** | /32 subnets, each device gets its own network | VLANs (manual config) | VLANs (manual config) | Microsegmentation (Gold+) | VLANs via controller | Not built-in | VLANs + zones (CLI) |
| **Device groups** | 6 built-in (trusted, IoT, servers, guest, quarantine, blocked) | Manual VLAN/firewall rules | Manual aliases/groups | Flexible groups | Profiles via controller | Not built-in | Firewall groups (CLI) |
| **DNS ad blocking** | Built-in (Blocky) | Packages (adblock, AGH) | Plugin (Unbound + blocklists) | Built-in | Not built-in | Built-in (Ad blocking toggle) | Not built-in |
| **WireGuard VPN** | Built-in, dual-stack | Package | Built-in | Built-in | Built-in | Built-in | Built-in |
| **Behavioral analysis** | Built-in (anomaly detection, alerts) | Not built-in | Suricata IDS/IPS plugin | IDS/IPS (Suricata-based) | IDS/IPS | Not built-in | Not built-in |
| **QoS** | CAKE + fq_codel, per-device DSCP | SQM (package) | Traffic shaper (ALTQ/pf) | Smart Queue | Not built-in | Not built-in | Traffic policy (CLI) |
| **IPv6** | Dual-stack, RA, DHCPv6-PD, ULA, pinholes | Full | Full | Full | Full | Basic | Full |
| **Port forwarding** | Manual + UPnP/NAT-PMP/PCP | Manual + packages | GUI + UPnP plugin | GUI | GUI | Not built-in | CLI |
| **mDNS across VLANs** | Built-in proxy with group filtering | Avahi package | Avahi plugin | Automatic | mDNS reflector | Not built-in | Not built-in |
| **Connection logging** | Built-in, syslog/webhook export | Packages | Built-in (Insight) | Built-in | Built-in | Minimal | CLI + syslog |
| **Backup/restore** | JSON export, optional AES-256-GCM encryption | Sysupgrade backup | XML export, encrypted option | Cloud backup | Cloud backup | Manual | CLI (save/load config) |
| **Web UI** | Built-in (Leptos SSR) | LuCI | Full GUI (Bootstrap) | Mobile app + web | UniFi controller | Built-in (PHP) | Minimal (optional) |
| **WiFi AP management** | TP-Link EAP720 only | Native (runs on the AP) | Not built-in | Not applicable (wired only) | UniFi APs only | Native (hostapd, the device IS the AP) | Not built-in |
| **Multi-WAN failover** | Not yet | Packages (mwan3) | Built-in (gateway groups) | Built-in | Built-in | Not built-in | Built-in (load balancing) |
| **Setup** | Install script + web wizard | Flash firmware, LuCI | ISO install + web wizard | Plug in, app setup | Plug in, app setup | Install script + web UI | ISO install + CLI |
| **Updates** | GUI one-click + auto-update (opt-in) | Sysupgrade | GUI one-click + firmware mirrors | Automatic OTA | Automatic OTA | apt upgrade | apt (rolling) or image (LTS) |
| **Multi-admin** | Single admin | Multi-user | Multi-user + RBAC | Multi-user | Multi-user | Single admin | Multi-user + RBAC |

## Where HermitShell is Stronger

**Device isolation without configuration.** Every device gets its own /32 subnet with proxy ARP. Devices cannot see each other at L2 or L3 unless explicitly allowed by group policy. OpenWrt, OPNsense, VyOS, Firewalla, and UniFi all require manual VLAN setup to achieve similar isolation. RaspAP has no device isolation.

**No cloud, no account, no telemetry.** The router works entirely offline. There is no vendor account, no cloud dependency, no usage telemetry. Firewalla and Ubiquiti both phone home by default. OPNsense, OpenWrt, RaspAP, and VyOS are also cloud-free.

**Transparent security model.** Every security compromise is documented in [SECURITY.md](SECURITY.md) with what, why, risk, and proper fix. No other consumer router platform publishes this level of detail about their security trade-offs.

**Behavioral analysis built in.** Traffic anomaly detection, DHCP fingerprint change alerts, and DNS reputation monitoring ship out of the box. OpenWrt, RaspAP, and VyOS have no equivalent; OPNsense, Firewalla, and Ubiquiti offer IDS/IPS but not behavioral baselines.

**Full source, permissive license.** MIT licensed. Inspect, modify, and redistribute without restriction. OpenWrt, RaspAP, and VyOS (rolling) are GPL; OPNsense is BSD; VyOS LTS is proprietary; Firewalla and Ubiquiti are closed source.

## Where HermitShell is Weaker

**WiFi AP support is limited.** Currently only TP-Link EAP720 standalone mode. OpenWrt runs directly on APs. Ubiquiti has a full AP ecosystem. RaspAP turns a Raspberry Pi into a WiFi AP via hostapd. OPNsense, VyOS, and Firewalla are wired-only but pair with any AP. If you have existing APs that aren't EAP720s, you'll manage WiFi separately.

**Fewer supported hardware platforms.** x86_64 and aarch64 only. OpenWrt runs on MIPS, ARM32, and hundreds of specific router boards. OPNsense and VyOS support x86_64 only but have mature installers. RaspAP targets Raspberry Pi and Debian-based ARM boards. HermitShell requires a mini PC or SBC with two network interfaces.

**No signed updates.** GUI one-click and opt-in auto-update are available, but releases are verified by SHA256 checksum only — no GPG signature. Firewalla and Ubiquiti sign their firmware. OPNsense signs packages with `pkg` keys.

**Debian only.** The installer requires Debian 12 or Raspbian. OpenWrt is its own OS; OPNsense is FreeBSD-based; VyOS is Debian-based with its own installer; RaspAP runs on Raspberry Pi OS / Debian; Firewalla and Ubiquiti ship their own firmware.

**Newer project.** Smaller community, less battle-tested in production. OpenWrt has 20+ years of history. OPNsense forked from pfSense in 2015 and has a large community. VyOS descends from Vyatta (2006). Firewalla and Ubiquiti have dedicated support teams.

**Single admin.** One admin account, no RBAC. Fine for a home user, limiting for families or small offices that want delegated access. OPNsense and VyOS have full multi-user with RBAC.

**Not a WiFi access point.** HermitShell is a wired router that manages external APs. If you want to turn a Raspberry Pi into a WiFi hotspot, RaspAP does that directly. HermitShell manages routing, firewalling, and device isolation — WiFi is handled by separate hardware.

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
- You want a mature FreeBSD firewall with extensive plugin ecosystem (OPNsense)
- You want a CLI-first enterprise router with BGP, OSPF, and MPLS (VyOS)
- You want to turn a Raspberry Pi into a WiFi hotspot (RaspAP)
- You need multi-WAN failover or multi-admin today

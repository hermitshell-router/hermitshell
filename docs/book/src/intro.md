# Introduction

Open-source router platform. No cloud, no controller, runs on commodity hardware.

Every device on your network gets its own isolated subnet automatically — no
VLANs to configure. HermitShell handles routing, firewalling, DHCP, DNS ad
blocking, WireGuard VPN, WiFi AP management, behavioral analysis, and more
through a web UI. Runs on any x86_64 or aarch64 Linux box with two NICs.

## Features

| Category | Details |
|---|---|
| **Device isolation** | Every device gets a /32 subnet with proxy ARP. No device sees another at L2 or L3 unless allowed by group policy. |
| **Device groups** | Trusted, IoT, servers, guest, quarantine, blocked — each with distinct firewall policies. |
| **DNS ad blocking** | Built-in, using configurable blocklists via Unbound. |
| **WireGuard VPN** | Dual-stack (IPv4 + IPv6), managed through the web UI. |
| **WiFi AP management** | UniFi controllers (OS + legacy) and TP-Link EAP standalone APs. SSID config, radio tuning, client visibility, kick/block. |
| **Behavioral analysis** | Traffic anomaly detection, DHCP fingerprint changes, DNS reputation monitoring. |
| **QoS** | CAKE + fq_codel with per-device DSCP marking for bufferbloat prevention. |
| **IPv6** | Dual-stack with RA, DHCPv6-PD, ULA, and pinhole management. |
| **Connection logging** | Full connection and DNS query logging with syslog and webhook export. |
| **mDNS proxy** | Cross-subnet service discovery with group-based filtering. |
| **UPnP/NAT-PMP/PCP** | Automatic port mapping for trusted devices. |
| **TLS** | Self-signed (default), custom cert, Tailscale, or ACME DNS-01 (Cloudflare). |
| **Backup/restore** | JSON export with optional AES-256-GCM encryption for secrets. |
| **Updates** | One-click GUI updates with staged restart and automatic rollback on failure. |

## Architecture

```
hermitshell/          Web UI (Leptos 0.8 + Axum 0.8, ports 80/443)
hermitshell-agent/    Router daemon: nftables, DHCP, Unbound DNS, WireGuard, WiFi, logging, IPv6
hermitshell-common/   Shared wire types (Device, Alert, PortForward, etc.)
hermitshell-dhcp/     DHCP server (DHCPv4 + DHCPv6)
```

The agent is an async Rust daemon exposing a Unix socket API. Socket handlers
are split by domain under `hermitshell-agent/src/socket/`. The DHCP server runs
as a separate process and communicates with the agent over the socket.

## Next steps

Pick your hardware in [Hardware](getting-started/hardware.md), then follow the
[Installation](getting-started/installation.md) guide.

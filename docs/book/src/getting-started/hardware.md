# Hardware Requirements

HermitShell runs on commodity x86_64 or aarch64 hardware with two network interfaces. You supply the hardware; HermitShell provides the router software.

## Minimum Requirements

| Component | Minimum | Notes |
|---|---|---|
| **CPU** | x86_64 or aarch64, 2 cores | Intel N97/N100, ARM Cortex-A72 or better |
| **RAM** | 1 GB | Enough for routing + DNS + web UI |
| **Storage** | 2 GB | SQLite DB, logs, blocklists |
| **NICs** | 2 Ethernet ports | One WAN, one LAN |
| **OS** | Any Linux (Debian/Ubuntu for APT; any distro via Docker or static binaries) | Install script checks for Debian/Ubuntu/Raspbian; Docker and binaries are distro-agnostic |

## Recommended Specs

| Component | Recommended | Why |
|---|---|---|
| **CPU** | 4 cores, 2+ GHz | Headroom for WireGuard encryption, QoS (CAKE), and behavioral analysis |
| **RAM** | 2-4 GB | Comfortable with connection logging, large device counts, and DNS caching |
| **Storage** | 16+ GB SSD/eMMC | Room for extended connection/DNS logs |
| **NICs** | 2x 2.5GbE | Matches modern ISP speeds; 1GbE works fine for most connections |

## What to Look For

**Two physical Ethernet ports.** This is the hard requirement. One port connects to your modem/ISP (WAN), the other to your switch or access point (LAN). USB Ethernet adapters work but add latency and reduce throughput — built-in dual NICs are strongly preferred.

**Fanless/passive cooling.** A router runs 24/7. Fans fail and make noise. Look for passively cooled enclosures with metal heatsink cases.

**Low power draw.** 10-25W is typical for a mini PC router. Your electricity bill will thank you compared to repurposing an old desktop.

**x86_64 vs aarch64.** Both are fully supported. x86_64 mini PCs are more widely available with dual NICs. aarch64 SBCs (like Raspberry Pi 5 with a USB-to-Ethernet adapter or HAT) work but may have fewer built-in Ethernet ports.

## Common Form Factors

### Mini PCs with Dual NICs

The most popular option. Small fanless boxes with 2-4 Ethernet ports, Intel N100/N305 or similar CPUs, 4-16 GB RAM. Available from many vendors for $100-250. Search for "fanless mini PC dual NIC" or "firewall appliance."

Typical specs: Intel N100, 8 GB RAM, 128 GB eMMC, 2x 2.5GbE, 10-15W idle. These handle gigabit routing with WireGuard and QoS easily.

### Single-Board Computers

Raspberry Pi 5 (aarch64) works with a USB 3.0 Ethernet adapter for the second NIC. More affordable ($60-100 total) but USB Ethernet is a compromise — fine for connections under 500 Mbps.

Other aarch64 SBCs with dual Ethernet (Orange Pi, NanoPi R5S/R6S) work well and avoid the USB limitation.

### Repurposed Thin Clients / Desktops

Old thin clients or small-form-factor desktops with an added PCIe NIC work. Check that the machine supports Debian 12 and has at least two network interfaces (one built-in + one PCIe or USB).

## What About WiFi?

HermitShell is a wired router. For WiFi, connect one or more access points to the LAN port (via a switch if needed).

HermitShell can manage **UniFi** APs (via UniFi OS or legacy controllers, including UDM, UDR, and Cloud Key) and **TP-Link EAP** APs (standalone mode) directly from the web UI — SSID configuration, radio tuning, client lists with signal strength, and client kick/block.

Other AP brands work fine on the network but are managed through their own interface.

A typical setup: mini PC (HermitShell) → Ethernet switch → WiFi access point(s).

## Architecture Support

| Architecture | Status |
|---|---|
| x86_64 | Fully supported, pre-built binaries available |
| aarch64 | Fully supported, pre-built binaries available |
| ARM32 (armv7) | Not supported |
| MIPS | Not supported |

## Performance Expectations

HermitShell adds minimal overhead to routing. On an Intel N100:

- **NAT throughput:** Line rate (2.5 Gbps)
- **WireGuard:** 1-2 Gbps depending on peer count
- **QoS (CAKE):** Line rate at typical home bandwidths (under 1 Gbps)
- **Behavioral analysis:** Negligible CPU impact (event-driven, not packet inspection)
- **Memory usage:** ~100-200 MB typical (agent + DHCP + DNS + web UI)

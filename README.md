# HermitShell

Open-source router platform. No cloud, no controller, runs on commodity hardware.

Every device on your network gets its own isolated subnet automatically — no VLANs to configure. HermitShell handles routing, firewalling, DHCP, DNS ad blocking, WireGuard VPN, WiFi AP management (UniFi and TP-Link EAP), behavioral analysis, and more through a web UI.

Runs on any x86_64 or aarch64 Linux box with two NICs.

## What You Need

- A machine with **two Ethernet ports** (mini PC, SBC, or repurposed thin client — see [docs/HARDWARE.md](docs/HARDWARE.md))
- **Linux** — Debian/Ubuntu/Raspbian for the install script or APT repo, or any distro via Docker or static binaries

## Install

There are several ways to install HermitShell. See [docs/INSTALL.md](docs/INSTALL.md) for full details.

### APT Repository (Debian/Ubuntu)

```bash
curl -fsSL https://hermitshell.github.io/hermitshell/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hermitshell.gpg
echo "deb [signed-by=/usr/share/keyrings/hermitshell.gpg] https://hermitshell.github.io/hermitshell/ stable main" \
  | sudo tee /etc/apt/sources.list.d/hermitshell.list
sudo apt update && sudo apt install hermitshell
```

Then configure your interfaces in `/etc/default/hermitshell` and start the services:

```bash
sudo sed -i 's/^WAN_IFACE=.*/WAN_IFACE=eth0/' /etc/default/hermitshell
sudo sed -i 's/^LAN_IFACE=.*/LAN_IFACE=eth1/' /etc/default/hermitshell
sudo systemctl enable --now hermitshell-agent hermitshell-ui
```

### Docker (Any Linux Distro)

```bash
docker run -d --name hermitshell \
  --privileged --network host \
  -e WAN_IFACE=eth0 -e LAN_IFACE=eth1 \
  -v /var/lib/hermitshell:/var/lib/hermitshell \
  -v /run/hermitshell:/run/hermitshell \
  ghcr.io/hermitshell/hermitshell:latest
```

### Install Script (Debian/Ubuntu)

```bash
curl -fsSL https://github.com/hermitshell/hermitshell/releases/latest/download/install.sh -o install.sh
sudo bash install.sh --wan eth0 --lan eth1
```

### After Install

Open **https://\<LAN-IP\>** in your browser. You'll see a self-signed certificate warning on first visit — this is expected. The setup wizard walks you through interface selection, LAN configuration, and setting an admin password.

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
hermitshell/          Web UI (Leptos 0.8 + Axum 0.8, ports 8080/8443)
hermitshell-agent/    Router daemon: nftables, DHCP, Unbound DNS, WireGuard, WiFi, logging, IPv6
hermitshell-common/   Shared wire types (Device, Alert, PortForward, etc.)
hermitshell-dhcp/     DHCP server (DHCPv4 + DHCPv6)
```

The agent is an async Rust daemon exposing a Unix socket API. Socket handlers are split by domain under `hermitshell-agent/src/socket/`. The DHCP server runs as a separate process and communicates with the agent over the socket.

## Building from Source

Requires Rust (stable) and the musl target:

```bash
rustup target add x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
./scripts/build-agent.sh
```

This produces static binaries, a `.deb` package (if cargo-deb is installed), and a Docker image (if Docker is available). See [docs/INSTALL.md](docs/INSTALL.md) for details on each output.

## Testing

Integration tests use Vagrant to spin up a 3-VM test network (router, LAN client, WAN upstream):

```bash
cd tests
sudo -E vagrant up        # Start VMs
sudo -E ./run.sh           # Run all tests
bash tests/cases/04-agent-socket.sh  # Run a single test
sudo -E vagrant destroy -f # Tear down
```

Tests run on the host and exercise real network paths (e.g., curl from the LAN VM, not localhost).

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) — Installation guide (all methods)
- [docs/HARDWARE.md](docs/HARDWARE.md) — Hardware requirements and buying guide
- [docs/COMPARISON.md](docs/COMPARISON.md) — HermitShell vs. OpenWrt, OPNsense, Firewalla, UniFi, etc.
- [docs/ROADMAP.md](docs/ROADMAP.md) — Completed phases and future work
- [docs/SECURITY.md](docs/SECURITY.md) — Documented security trade-offs
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Common issues and solutions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and submit changes.

## License

MIT. See [LICENSE](LICENSE).

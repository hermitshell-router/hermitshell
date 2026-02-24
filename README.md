# HermitShell

Open-source router platform. No cloud, no controller, runs on commodity hardware.

## Features

- **WAN/LAN networking** with nftables firewall
- **DHCP** — DHCPv4 (/32 point-to-point) and DHCPv6 stateful (/128 ULA)
- **Per-device isolation** — each LAN device gets its own /32 subnet, enforced by nftables (no VLANs needed)
- **DNS ad blocking** with custom blocklists
- **WireGuard VPN** — agent manages wg0 directly; peers get /30 subnets
- **IPv6 dual-stack** — RA sender, DHCPv6-PD
- **Connection and DNS logging** with syslog and webhook export
- **Behavioral analysis** for connected devices
- **QoS / bufferbloat prevention**
- **runZero asset sync**
- **TLS certificate management** — self-signed, custom, Tailscale, and ACME DNS-01
- **WiFi AP management** — adopt TP-Link EAP access points, manage SSIDs and radios
- **First-run setup wizard** — select WAN/LAN interfaces and set admin password from the browser
- **Update notifications** — background check against GitHub releases, shown in the dashboard
- **Encrypted credentials** — WiFi AP passwords encrypted at rest with AES-256-GCM
- **Web UI** — Leptos + Axum, SSR-only, served over HTTPS

## Architecture

```
hermitshell/          Web UI (Leptos 0.8 + Axum 0.8, Docker, ports 8080/8443)
hermitshell-agent/    Router daemon: nftables, DHCP, DNS, WireGuard, logging, IPv6
hermitshell-common/   Shared wire types (Device, Alert, PortForward, etc.)
hermitshell-dhcp/     DHCP server (DHCPv4 + DHCPv6)
```

The agent is an async Rust daemon exposing a Unix socket API. Socket handlers are split by domain under `hermitshell-agent/src/socket/` (auth, config, devices, logs, network, setup, wifi, wireguard). The DHCP server runs as a separate process and communicates with the agent over the socket.

## Quick Start

HermitShell runs on a Linux box with two network interfaces (WAN and LAN). Build the agent as a static musl binary and deploy it to your router:

```bash
./scripts/build-agent.sh
```

The web UI runs in Docker on ports 8080 (HTTP) and 8443 (HTTPS).

## Building from Source

Requires Rust (stable). Build the entire workspace:

```bash
cargo build --workspace
```

For a static musl binary (suitable for deployment):

```bash
./scripts/build-agent.sh
```

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

## License

Not yet specified.

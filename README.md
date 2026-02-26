# HermitShell

Open-source router platform. No cloud, no controller, runs on commodity hardware.

Per-device network isolation, DNS ad blocking, WireGuard VPN, WiFi AP management, behavioral analysis, and a web UI — all self-hosted on a Linux box with two NICs. See [docs/ROADMAP.md](docs/ROADMAP.md) for the full feature list.

## Architecture

```
hermitshell/          Web UI (Leptos 0.8 + Axum 0.8, Docker, ports 8080/8443)
hermitshell-agent/    Router daemon: nftables, DHCP, DNS, WireGuard, logging, IPv6
hermitshell-common/   Shared wire types (Device, Alert, PortForward, etc.)
hermitshell-dhcp/     DHCP server (DHCPv4 + DHCPv6)
```

The agent is an async Rust daemon exposing a Unix socket API. Socket handlers are split by domain under `hermitshell-agent/src/socket/`. The DHCP server runs as a separate process and communicates with the agent over the socket.

## Quick Start

Build the agent as a static musl binary and deploy it to your router:

```bash
./scripts/build-agent.sh
```

The web UI runs in Docker on ports 8080 (HTTP) and 8443 (HTTPS).

## Building from Source

Requires Rust (stable):

```bash
cargo build --workspace
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

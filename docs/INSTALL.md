# Installing HermitShell

HermitShell can be installed via APT, Docker, an install script, a `.deb` package, or static binaries. All methods produce the same result: the agent daemon, DHCP server, and web UI running on your router.

All release artifacts are built for both **x86_64** and **aarch64**.

## Before You Start

You need:

- A Linux machine with **two Ethernet ports** (one WAN, one LAN)
- Root / sudo access
- Your WAN and LAN interface names (run `ip link` to list them)

The WAN port connects to your modem or ISP. The LAN port connects to your switch or access point.

## Method 1: APT Repository (Debian / Ubuntu / Raspbian)

The APT repo is GPG-signed and updated automatically on each release. This is the recommended method for Debian-based systems — upgrades happen via `apt upgrade`.

```bash
# Add the GPG key
curl -fsSL https://hermitshell.github.io/hermitshell/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hermitshell.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/hermitshell.gpg] https://hermitshell.github.io/hermitshell/ stable main" \
  | sudo tee /etc/apt/sources.list.d/hermitshell.list

# Install
sudo apt update
sudo apt install hermitshell
```

After install, configure your interfaces:

```bash
sudo nano /etc/default/hermitshell
# Set WAN_IFACE and LAN_IFACE to your interface names

sudo systemctl enable --now hermitshell-agent hermitshell-ui
```

**Upgrades:** `sudo apt update && sudo apt upgrade`

## Method 2: Docker (Any Linux Distro)

The all-in-one Docker image is Alpine-based and includes the agent, DHCP server, web UI, and all dependencies (nftables, WireGuard tools, Unbound DNS). It runs on any Linux distro with Docker installed.

```bash
docker run -d --name hermitshell \
  --privileged --network host \
  --restart unless-stopped \
  -e WAN_IFACE=eth0 \
  -e LAN_IFACE=eth1 \
  -v /var/lib/hermitshell:/var/lib/hermitshell \
  -v /run/hermitshell:/run/hermitshell \
  ghcr.io/hermitshell/hermitshell:latest
```

Replace `eth0` and `eth1` with your actual interface names.

The container requires `--privileged` and `--network host` because it manages nftables rules, WireGuard interfaces, and DHCP directly on the host network stack.

**Upgrades:** `docker pull ghcr.io/hermitshell/hermitshell:latest` and recreate the container. Data persists in `/var/lib/hermitshell`.

## Method 3: Install Script (Debian / Ubuntu / Raspbian)

A single script that downloads the latest release, installs system dependencies, and creates systemd services.

```bash
# Download and run
curl -fsSL https://github.com/hermitshell/hermitshell/releases/latest/download/install.sh -o install.sh
sudo bash install.sh --wan eth0 --lan eth1
```

The script:
1. Installs system dependencies (`nftables`, `wireguard-tools`, `unbound`, etc.)
2. Downloads the latest release tarball and verifies its SHA256 checksum
3. Installs static binaries to `/opt/hermitshell/`
4. Creates a `hermitshell` system user for the web UI
5. Installs and enables systemd services with security hardening

**Upgrades:** `sudo bash install.sh --upgrade`

**Uninstall:** `sudo bash install.sh --uninstall` (preserves data at `/var/lib/hermitshell`)

You can also install from a local tarball (useful for air-gapped systems):

```bash
sudo bash install.sh --wan eth0 --lan eth1 --local hermitshell-v1.0.0-x86_64-linux.tar.gz
```

## Method 4: .deb Package (Manual)

Each GitHub release includes `.deb` packages for amd64 and arm64. Download from the [releases page](https://github.com/hermitshell/hermitshell/releases).

```bash
sudo dpkg -i hermitshell_*.deb
sudo apt-get install -f -y   # Install dependencies

# Configure interfaces
sudo nano /etc/default/hermitshell
# Set WAN_IFACE and LAN_IFACE

sudo systemctl enable --now hermitshell-agent hermitshell-ui
```

## Method 5: Static Binaries (Any Linux Distro)

Every release includes static musl-linked binaries that run on any Linux distro without runtime dependencies. Download the tarball for your architecture from the [releases page](https://github.com/hermitshell/hermitshell/releases).

The tarball contains:
- `hermitshell-agent` — the router daemon
- `hermitshell-dhcp` — the DHCP server
- `hermitshell` — the web UI

You'll need to install the system dependencies yourself using your distro's package manager:
- `nftables`, `conntrack-tools`, `wireguard-tools`, `iproute2`, `unbound`

Then run the agent with the appropriate environment variables:

```bash
WAN_IFACE=eth0 LAN_IFACE=eth1 ./hermitshell-agent
```

The web UI needs `LEPTOS_OUTPUT_NAME=hermitshell` set in its environment.

## After Installation

1. Open **https://\<LAN-IP\>** in your browser
2. Accept the self-signed certificate warning (expected on first visit)
3. The setup wizard walks you through network configuration and setting an admin password
4. After setup, the web UI is available at the same address with your admin credentials

**Logs:** `journalctl -u hermitshell-agent -f` (systemd installs) or `docker logs -f hermitshell` (Docker)

**Data directory:** `/var/lib/hermitshell/` — contains the SQLite database, DNS blocklists, and backups. Preserved across upgrades and uninstalls.

**Socket:** `/run/hermitshell/agent.sock` — the Unix domain socket used by the web UI to communicate with the agent.

## Building from Source

Requires Rust (stable) and the musl target:

```bash
rustup target add x86_64-unknown-linux-musl
./scripts/build-agent.sh
```

The build script compiles all three components (agent, DHCP server, web UI) as static musl binaries, then packages them:

| Output | Location | Notes |
|---|---|---|
| Static binaries | `target/release/hermitshell-agent`, `hermitshell-dhcp`, `hermitshell` | Portable across any Linux distro |
| Install tarball | `target/release/hermitshell-local.tar.gz` | For use with `install.sh --local` |
| Docker image | `target/release/hermitshell-container.tar` | Built automatically if Docker is available |
| .deb package | `target/release/hermitshell_*.deb` | Built automatically if `cargo-deb` is installed |
| Systemd unit | `target/release/hermitshell-agent.service` | Copied from `systemd/` |

### Cross-compiling for aarch64

The CI uses [cross](https://github.com/cross-rs/cross) for aarch64 builds. To cross-compile locally:

```bash
cargo install cross --git https://github.com/cross-rs/cross
LEPTOS_OUTPUT_NAME=hermitshell cross build --release \
  -p hermitshell-agent -p hermitshell-dhcp -p hermitshell \
  --target aarch64-unknown-linux-musl
```

### Building without packaging

To build the workspace for development without the musl target or packaging:

```bash
cargo build --workspace
```

This builds with the default toolchain (not statically linked) and is faster for local development, but the binaries won't be portable across distros.

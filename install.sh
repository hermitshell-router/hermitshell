#!/bin/bash
set -euo pipefail

REPO="hermitshell/hermitshell"
INSTALL_DIR="/opt/hermitshell"
DATA_DIR="/data/hermitshell"
RUN_DIR="/run/hermitshell"

usage() {
    echo "Usage: $0 [--wan IFACE] [--lan IFACE] [--local TARBALL] [--uninstall] [--upgrade]"
    echo ""
    echo "Options:"
    echo "  --wan IFACE      WAN interface name (required for install)"
    echo "  --lan IFACE      LAN interface name (required for install)"
    echo "  --local TARBALL  Install from local tarball instead of GitHub"
    echo "  --uninstall      Remove HermitShell (preserves data)"
    echo "  --upgrade        Upgrade to latest release"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: must run as root" >&2
        exit 1
    fi
}

check_distro() {
    if [ ! -f /etc/os-release ]; then
        echo "Error: cannot detect OS" >&2
        exit 1
    fi
    . /etc/os-release

    case "$ID" in
        debian|raspbian) KNOWN_VERSIONS="12 13" ;;
        ubuntu)          KNOWN_VERSIONS="22.04 24.04" ;;
        *)
            echo "Error: unsupported OS (detected: $ID)" >&2
            echo "  Supported: Debian 12+, Ubuntu 22.04+, Raspbian" >&2
            exit 1
            ;;
    esac

    local known=false
    for v in $KNOWN_VERSIONS; do
        [ "${VERSION_ID:-}" = "$v" ] && known=true
    done
    if ! $known; then
        echo "Warning: tested on $ID $KNOWN_VERSIONS (detected: ${VERSION_ID:-unknown})" >&2
    fi
}

check_iface() {
    local name="$1" label="$2"
    if [ -z "$name" ]; then
        echo "Error: --$label is required" >&2
        usage
    fi
    if [ ! -d "/sys/class/net/$name" ]; then
        echo "Error: interface '$name' not found" >&2
        echo "Available interfaces:"
        ls /sys/class/net/ | grep -v lo
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "x86_64" ;;
        aarch64) echo "aarch64" ;;
        *)
            echo "Error: unsupported architecture $(uname -m)" >&2
            exit 1
            ;;
    esac
}

get_latest_version() {
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4
}

do_install() {
    local wan="$1" lan="$2"

    check_distro
    check_iface "$wan" "wan"
    check_iface "$lan" "lan"

    local arch
    arch=$(detect_arch)

    echo "Installing HermitShell..."
    echo "  WAN: $wan"
    echo "  LAN: $lan"
    echo "  Arch: $arch"

    # Install system dependencies
    apt-get update -qq
    apt-get install -y -qq nftables conntrack wireguard-tools iproute2 curl >/dev/null

    # On Ubuntu, install ifupdown (replaces Netplan for interface management)
    . /etc/os-release
    if [ "$ID" = "ubuntu" ]; then
        apt-get install -y -qq ifupdown >/dev/null
    fi

    # Install binaries
    mkdir -p "$INSTALL_DIR"
    if [ -n "$LOCAL_TARBALL" ]; then
        echo "  Source: $LOCAL_TARBALL"
        tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1
    else
        # Download latest release
        local version
        version=$(get_latest_version)
        if [ -z "$version" ]; then
            echo "Error: could not determine latest version" >&2
            exit 1
        fi
        echo "  Version: $version"

        local tarball="hermitshell-${version}-${arch}-linux.tar.gz"
        local url="https://github.com/$REPO/releases/download/${version}/${tarball}"
        local checksum_url="${url}.sha256"

        local tmp
        tmp=$(mktemp -d)
        curl -fsSL -o "$tmp/$tarball" "$url"
        curl -fsSL -o "$tmp/$tarball.sha256" "$checksum_url"
        (cd "$tmp" && sha256sum -c "$tarball.sha256")
        tar -xzf "$tmp/$tarball" -C "$INSTALL_DIR" --strip-components=1
        rm -rf "$tmp"
    fi
    chmod +x "$INSTALL_DIR"/hermitshell-agent "$INSTALL_DIR"/hermitshell-dhcp \
              "$INSTALL_DIR"/hermitshell "$INSTALL_DIR"/blocky

    # Create data and runtime directories
    mkdir -p "$DATA_DIR/db" "$DATA_DIR/blocky" "$RUN_DIR"

    # Create hermitshell user for web UI (if not exists)
    if ! id hermitshell &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin hermitshell
    fi

    # Install systemd services
    cat > /etc/systemd/system/hermitshell-agent.service <<UNIT
[Unit]
Description=HermitShell Router Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/hermitshell-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hermitshell-agent
Environment=RUST_LOG=info
Environment=WAN_IFACE=$wan
Environment=LAN_IFACE=$lan
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $RUN_DIR /tmp
PrivateTmp=yes
NoNewPrivileges=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
UNIT

    cat > /etc/systemd/system/hermitshell-ui.service <<UNIT
[Unit]
Description=HermitShell Web UI
After=hermitshell-agent.service
BindsTo=hermitshell-agent.service
PartOf=hermitshell-agent.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/hermitshell
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hermitshell-ui
Environment=LEPTOS_OUTPUT_NAME=hermitshell
User=hermitshell
Group=hermitshell

[Install]
WantedBy=multi-user.target
UNIT

    # Enable and start
    systemctl daemon-reload
    systemctl enable --now hermitshell-agent hermitshell-ui

    echo ""
    echo "HermitShell installed successfully."
    echo ""
    echo "Tip: For easier upgrades, use the apt repository instead:"
    echo "  https://github.com/hermitshell/hermitshell#install-via-apt"
    echo "  Web UI: https://10.0.0.1:8443 (self-signed cert)"
    echo "  Logs:   journalctl -u hermitshell-agent -f"
}

do_uninstall() {
    echo "Uninstalling HermitShell..."
    systemctl stop hermitshell-ui hermitshell-agent 2>/dev/null || true
    systemctl disable hermitshell-ui hermitshell-agent 2>/dev/null || true
    rm -f /etc/systemd/system/hermitshell-agent.service
    rm -f /etc/systemd/system/hermitshell-ui.service
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    echo "Removed. Data preserved at $DATA_DIR"
}

do_upgrade() {
    echo "Upgrading HermitShell..."
    local arch
    arch=$(detect_arch)
    local version
    version=$(get_latest_version)
    echo "  Latest: $version"

    local tarball="hermitshell-${version}-${arch}-linux.tar.gz"
    local url="https://github.com/$REPO/releases/download/${version}/${tarball}"
    local checksum_url="${url}.sha256"

    local tmp
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/$tarball" "$url"
    curl -fsSL -o "$tmp/$tarball.sha256" "$checksum_url"
    (cd "$tmp" && sha256sum -c "$tarball.sha256")

    systemctl stop hermitshell-ui hermitshell-agent
    tar -xzf "$tmp/$tarball" -C "$INSTALL_DIR" --strip-components=1
    chmod +x "$INSTALL_DIR"/hermitshell-agent "$INSTALL_DIR"/hermitshell-dhcp \
              "$INSTALL_DIR"/hermitshell "$INSTALL_DIR"/blocky
    rm -rf "$tmp"
    systemctl start hermitshell-agent hermitshell-ui

    echo "Upgraded to $version"
}

# Parse arguments
WAN=""
LAN=""
LOCAL_TARBALL=""
ACTION="install"

while [ $# -gt 0 ]; do
    case "$1" in
        --wan) WAN="$2"; shift 2 ;;
        --lan) LAN="$2"; shift 2 ;;
        --local) LOCAL_TARBALL="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --upgrade) ACTION="upgrade"; shift ;;
        *) usage ;;
    esac
done

check_root

case "$ACTION" in
    install)   do_install "$WAN" "$LAN" ;;
    uninstall) do_uninstall ;;
    upgrade)   do_upgrade ;;
esac

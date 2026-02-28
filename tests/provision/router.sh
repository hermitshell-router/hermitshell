#!/bin/bash
set -e

apt-get update

# On Ubuntu: install ifupdown, stop Netplan from managing non-Vagrant interfaces
if grep -q '^ID=ubuntu' /etc/os-release; then
    apt-get install -y ifupdown
    # Remove Netplan configs so it won't manage interfaces on next boot.
    # Do NOT run 'netplan apply' — that kills eth0 (Vagrant management).
    rm -f /etc/netplan/*.yaml
    # Disable networkd renderer (Netplan's backend) for non-eth0 interfaces
    systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
fi

apt-get install -y nftables docker.io socat conntrack curl dnsutils wireguard-tools binutils
usermod -aG docker vagrant

# eth1 = WAN (gets IP from wan-vm via DHCP)
# eth2 = LAN (static IP, runs DHCP server)

# Configure WAN interface to use DHCP
cat > /etc/network/interfaces.d/wan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

# Configure LAN interface (agent adds addresses at startup)
cat > /etc/network/interfaces.d/lan <<EOF
auto eth2
iface eth2 inet manual
EOF

# Enable IP forwarding (IPv4 and IPv6)
cat > /etc/sysctl.d/99-forward.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl -p /etc/sysctl.d/99-forward.conf

# Basic nftables for NAT (fallback)
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "eth1" masquerade
    }
}
EOF

# Agent handles DHCP for LAN (no dnsmasq needed)

# Bring up interfaces
ifup eth1 || true
ifup eth2 || true

# Fix default route to go through WAN (eth1) instead of Vagrant management (eth0)
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true
ip route add default via 192.168.100.2 dev eth1 2>/dev/null || true

# Create directories for agent
mkdir -p /var/lib/hermitshell/unbound/blocklists
mkdir -p /run/hermitshell

# Install unbound (DNS resolver replaces blocky)
apt-get install -y -qq unbound 2>/dev/null || true
# Stop system unbound — agent manages its own instance
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
unbound-control-setup 2>/dev/null || true

# Run hermitshell-agent as daemon (nohup prevents SIGHUP on session close)
if [ -f /opt/hermitshell/hermitshell-agent ]; then
    setsid /opt/hermitshell/hermitshell-agent > /var/log/hermitshell-agent.log 2>&1 &
    # Wait for agent socket to appear
    for i in $(seq 1 30); do test -S /run/hermitshell/agent.sock && break; done
    # Relax socket permissions for test access
    chmod 666 /run/hermitshell/agent.sock 2>/dev/null || true
else
    echo "Warning: hermitshell-agent not found, using static rules"
    nft -f /etc/nftables.conf
fi

# Load and run container if image exists
if [ -f /opt/hermitshell/hermitshell-container.tar ]; then
    docker load -i /opt/hermitshell/hermitshell-container.tar
    # Remove existing container if any
    docker rm -f hermitshell 2>/dev/null || true
    # Use --network host to avoid iptables conflicts with nftables
    docker run -d \
        --name hermitshell \
        --network host \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        -v /run/hermitshell:/run/hermitshell \
        hermitshell:latest
fi

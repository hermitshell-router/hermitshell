#!/bin/bash
set -e

apt-get update
apt-get install -y nftables dnsmasq docker.io socat

# eth1 = WAN (gets IP from wan-vm via DHCP)
# eth2 = LAN (static IP, runs DHCP server)

# Configure WAN interface to use DHCP
cat > /etc/network/interfaces.d/wan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

# Configure LAN interface with static IP
cat > /etc/network/interfaces.d/lan <<EOF
auto eth2
iface eth2 inet static
    address 10.0.0.1
    netmask 255.255.255.0
EOF

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-forward.conf
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

# Configure dnsmasq for LAN DHCP
cat > /etc/dnsmasq.conf <<EOF
interface=eth2
dhcp-range=10.0.0.100,10.0.0.200,24h
dhcp-option=option:router,10.0.0.1
dhcp-option=option:dns-server,10.0.0.1
EOF

systemctl restart dnsmasq

# Bring up interfaces
ifup eth1 || true
ifup eth2 || true

# Fix default route to go through WAN (eth1) instead of Vagrant management (eth0)
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true
ip route add default via 192.168.100.1 dev eth1 2>/dev/null || true

# Create directories for agent
mkdir -p /data/hermitshell/db
mkdir -p /run/hermitshell

# Run hermitshell-agent as daemon
if [ -f /opt/hermitshell/hermitshell-agent ]; then
    /opt/hermitshell/hermitshell-agent &
    sleep 2
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
        -v /run/hermitshell/agent.sock:/run/hermitshell/agent.sock \
        hermitshell:latest
fi

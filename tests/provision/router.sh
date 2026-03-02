#!/bin/bash
set -e

# Ensure NICs are named eth0/eth1/eth2.  Some boxes (cloud-image/ubuntu)
# use "ensX" names.  Rename the non-management NICs at runtime so the
# rest of this script and the test suite see eth1 (WAN) / eth2 (LAN).
if ! ip link show eth1 &>/dev/null; then
    # Collect en* interfaces sorted by name (PCI slot order).
    # First is management (skip — SSH runs over it), 2nd → eth1, 3rd → eth2.
    mapfile -t nics < <(ls -1d /sys/class/net/en* 2>/dev/null | sort | xargs -I{} basename {})
    if [ "${#nics[@]}" -ge 3 ]; then
        ip link set "${nics[1]}" down 2>/dev/null || true
        ip link set "${nics[1]}" name eth1 2>/dev/null || true
        ip link set "${nics[2]}" down 2>/dev/null || true
        ip link set "${nics[2]}" name eth2 2>/dev/null || true
    fi
    # Persist for future boots
    if [ -f /etc/default/grub ]; then
        sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /etc/default/grub
        update-grub 2>/dev/null || true
    fi
fi

apt-get update

# On Ubuntu: install ifupdown, stop Netplan from managing non-Vagrant interfaces
if grep -q '^ID=ubuntu' /etc/os-release; then
    apt-get install -y ifupdown
    # Remove Netplan configs so it won't manage interfaces on next boot.
    # Do NOT run 'netplan apply' — that kills eth0 (Vagrant management).
    rm -f /etc/netplan/*.yaml
    # Disable networkd renderer (Netplan's backend) for non-eth0 interfaces
    systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
    # generic/ubuntu2204 ships with IPv6 disabled; unbound needs ::0 to bind
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0
    sed -i '/disable_ipv6/d' /etc/sysctl.conf 2>/dev/null || true
fi

apt-get install -y nftables docker.io socat conntrack curl dnsutils wireguard-tools binutils unbound
usermod -aG docker vagrant

# eth1 = WAN (gets IP from wan-vm via DHCP)
# eth2 = LAN (static IP, runs DHCP server)

# Configure WAN interface (agent handles DHCP)
cat > /etc/network/interfaces.d/wan <<EOF
auto eth1
iface eth1 inet manual
EOF

# Configure LAN interface (agent adds addresses at startup)
cat > /etc/network/interfaces.d/lan <<EOF
auto eth2
iface eth2 inet manual
EOF

# Load ifb module for QoS (agent systemd unit has ProtectKernelModules=yes)
modprobe ifb 2>/dev/null || true
echo ifb >> /etc/modules 2>/dev/null || true

# Load 8021q module for VLAN subinterfaces
modprobe 8021q 2>/dev/null || true
echo 8021q >> /etc/modules 2>/dev/null || true

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

# Fix default route to go through WAN (eth1) instead of Vagrant management NIC.
# The management NIC may be eth0 (bento/generic boxes) or ens5 (cloud-image).
ip route del default 2>/dev/null || true
ip route add default via 192.168.100.2 dev eth1 2>/dev/null || true

# Create directories for agent
mkdir -p /var/lib/hermitshell/unbound/blocklists
mkdir -p /run/hermitshell

# Stop system unbound — agent manages its own instance (installed above)
systemctl stop unbound 2>/dev/null || true
systemctl disable unbound 2>/dev/null || true
# Allow Unbound to access HermitShell config/data directory via AppArmor
if [ -d /etc/apparmor.d/local ]; then
    cat > /etc/apparmor.d/local/usr.sbin.unbound <<APPARMOR
  /var/lib/hermitshell/unbound/** rw,
APPARMOR
    apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
fi

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

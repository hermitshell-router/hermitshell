#!/bin/bash
set -e

# eth1 = LAN (gets IP from router via DHCP)

# Configure LAN interface to use DHCP from router
cat > /etc/network/interfaces.d/lan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

ifup eth1 || true

# Fix default route to go through router (eth1) instead of Vagrant management (eth0)
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true
ip route add default via 10.0.0.1 dev eth1 2>/dev/null || true

#!/bin/bash
set -e

# eth1 = LAN (gets IP from router via DHCP)

# Configure LAN interface to use DHCP from router
cat > /etc/network/interfaces.d/lan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

ifup eth1 || true

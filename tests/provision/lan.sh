#!/bin/bash
set -e

apt-get update
apt-get install -y dnsutils

# eth1 = LAN (gets IP from router via DHCP)

# Configure LAN interface to use DHCP from router
cat > /etc/network/interfaces.d/lan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

ifup eth1 || true

# Fix default route to go through router (eth1) instead of Vagrant management (eth0)
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true

# Ensure default route via DHCP gateway exists
# dhclient sometimes doesn't set the default route when another exists
gateway=$(grep -oP 'option routers \K[0-9.]+' /var/lib/dhcp/dhclient.eth1.leases 2>/dev/null | tail -1)
if [ -n "$gateway" ]; then
    ip route replace default via "$gateway" dev eth1 2>/dev/null || true
fi

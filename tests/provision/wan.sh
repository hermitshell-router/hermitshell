#!/bin/bash
set -e

apt-get update
apt-get install -y dnsmasq

# Configure dnsmasq as DHCP server for router's WAN interface
cat > /etc/dnsmasq.conf <<EOF
interface=eth1
dhcp-range=192.168.100.100,192.168.100.200,24h
dhcp-option=option:router,192.168.100.1
dhcp-option=option:dns-server,192.168.100.1
EOF

# Enable IP forwarding (WAN VM simulates internet access)
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-forward.conf
sysctl -p /etc/sysctl.d/99-forward.conf

# NAT for "internet" access (via Vagrant's default NAT interface)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

systemctl restart dnsmasq

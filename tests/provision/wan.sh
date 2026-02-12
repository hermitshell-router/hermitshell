#!/bin/bash
set -e

apt-get update
apt-get install -y dnsmasq nftables

# Configure dnsmasq as DHCP server for router's WAN interface
cat > /etc/dnsmasq.conf <<EOF
interface=eth1
dhcp-range=192.168.100.100,192.168.100.200,24h
dhcp-option=option:router,192.168.100.1
dhcp-option=option:dns-server,192.168.100.1
no-resolv
server=4.2.2.1
server=4.2.2.2
address=/ads.test.hermitshell/93.184.216.34
EOF

# Disable DNSSEC trust anchors that cause "Not Ready" REFUSED responses
rm -f /usr/share/dns/root.ds

# Enable IP forwarding (WAN VM simulates internet access)
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-forward.conf
sysctl -p /etc/sysctl.d/99-forward.conf

# NAT for "internet" access (via Vagrant's default NAT interface)
nft add table ip nat
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule ip nat postrouting oifname "eth0" masquerade

systemctl restart dnsmasq

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

# The LAN VM should have a DHCPv6-assigned ULA address.
# This exercises the neighbor-cache MAC resolution path since
# the LAN VM's DHCPv6 client sends a DUID (type varies by OS)
# and the DHCP server resolves the MAC from the neighbor cache.

lan_ipv6=$(vm_exec lan "ip -6 addr show dev eth1 scope global" 2>/dev/null | grep -oP 'inet6 \K[0-9a-f:]+' | head -1)
assert_match "$lan_ipv6" "^fd" "LAN client got ULA IPv6 address via DHCPv6"

# Verify the device record has both IPv4 and IPv6
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
args=$(_vm_ssh_args router)
result=$(ssh $SSH_COMMON $args "sudo bash -c 'echo \"{\\\"method\\\":\\\"get_device\\\",\\\"mac\\\":\\\"$lan_mac\\\"}\" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock'" 2>/dev/null)
assert_contains "$result" '"ipv6_ula"' "Device record has IPv6 ULA address"

# Verify the neighbor cache on the router has the LAN client's link-local → MAC mapping
lan_ll=$(vm_exec lan "ip -6 addr show dev eth1 scope link" 2>/dev/null | grep -oP 'inet6 \K[0-9a-f:]+' | head -1)
neigh_mac=$(vm_sudo router "ip -6 neigh show $lan_ll" 2>/dev/null | grep -oP 'lladdr \K[0-9a-f:]+')
assert_match "$neigh_mac" "^[0-9a-f]" "Router neighbor cache has LAN client MAC for link-local"

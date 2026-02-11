#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get the LAN VM's MAC address
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

# Approve device to trusted group
result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"trusted\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "set_device_group succeeds"

# Verify group changed in device list
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"trusted"' "Device group updated to trusted"

# Trusted device should still reach internet
assert_success "Trusted device can ping WAN" vm_exec lan "ping -c1 -W2 192.168.100.1"

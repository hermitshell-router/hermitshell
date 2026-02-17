#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get LAN device MAC
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
assert_match "$lan_mac" "^[0-9a-f]" "LAN MAC is valid"

# Set reservation for current IP
result=$(vm_exec router "echo '{\"method\":\"set_dhcp_reservation\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "set_dhcp_reservation succeeds"

# List reservations
result=$(vm_exec router 'echo "{\"method\":\"list_dhcp_reservations\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dhcp_reservations succeeds"
assert_match "$result" "$lan_mac" "reservation contains LAN MAC"

# Remove reservation
result=$(vm_exec router "echo '{\"method\":\"remove_dhcp_reservation\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "remove_dhcp_reservation succeeds"

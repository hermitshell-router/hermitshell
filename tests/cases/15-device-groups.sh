#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get the LAN VM's MAC address
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

# Test each untested device group
for group in iot guest servers; do
    # Set device to group
    result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"$group\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
    assert_match "$result" '"ok":true' "set_device_group($group) succeeds"

    # Verify group in device list
    devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
    assert_match "$devices" "\"device_group\":\"$group\"" "Device group shows $group"

    # Verify device can still reach WAN
    assert_success "$group device can reach WAN" vm_exec lan "ping -c1 -W3 192.168.100.1"
done

# Restore device to quarantine for subsequent tests
result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"quarantine\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "Restored device to quarantine"

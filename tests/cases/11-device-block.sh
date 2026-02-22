#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get the LAN VM's MAC address
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")

# Ensure device is not already blocked (idempotency)
vm_exec router "echo '{\"method\":\"unblock_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1

# Block the device
result=$(vm_exec router "echo '{\"method\":\"block_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "block_device succeeds"

# Verify device is blocked
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"blocked"' "Device group is blocked"

# Blocked device should NOT be able to reach internet (nftables drops)
assert_failure "Blocked device cannot reach WAN" \
    vm_exec lan "ping -c1 -W3 192.168.100.2"
block_test=$?

# Unblock the device (restore for any subsequent tests)
result=$(vm_exec router "echo '{\"method\":\"unblock_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "unblock_device succeeds"

# Verify device is back to quarantine
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"quarantine"' "Device restored to quarantine after unblock"

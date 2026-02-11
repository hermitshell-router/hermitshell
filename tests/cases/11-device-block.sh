#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get the LAN VM's MAC address
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")

# Block the device
result=$(vm_exec router "echo '{\"method\":\"block_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "block_device succeeds"

# Verify device is blocked
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"blocked"' "Device group is blocked"

# Flush conntrack so existing connections don't bypass the block
vm_exec router "sudo conntrack -F 2>/dev/null || true" >/dev/null 2>&1

# Blocked device should NOT be able to reach internet (nftables drops)
if vm_exec lan "ping -c1 -W3 192.168.100.1" >/dev/null 2>&1; then
    echo -e "${RED}FAIL${NC}: Blocked device should not reach WAN"
    # Note: test continues (don't exit) - unblock below to restore state
else
    echo -e "${GREEN}PASS${NC}: Blocked device cannot reach WAN"
fi

# Unblock the device (restore for any subsequent tests)
result=$(vm_exec router "echo '{\"method\":\"unblock_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "unblock_device succeeds"

# Verify device is back to quarantine
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"quarantine"' "Device restored to quarantine after unblock"

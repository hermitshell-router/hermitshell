#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_nftables

# Get the LAN VM's MAC and IP
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Test each device group: verify API, nftables, and connectivity
for group in iot guest servers; do
    # Set device to group
    result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"$group\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
    assert_match "$result" '"ok":true' "set_device_group($group) succeeds"

    # Verify group in device list
    devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
    assert_match "$devices" "\"device_group\":\"$group\"" "Device group shows $group"

    # Verify nftables verdict map updated to correct chain
    vmap=$(vagrant ssh router -c "sudo nft list map inet filter device_groups_v4" 2>/dev/null || echo "")
    assert_contains "$vmap" "${device_ip} : jump ${group}_fwd" "nftables map shows ${group}_fwd for $group"

    # Verify the group's forward chain exists and has WAN-only policy (like quarantine)
    chain=$(vagrant ssh router -c "sudo nft list chain inet filter ${group}_fwd" 2>/dev/null || echo "")
    assert_match "$chain" 'oifname.*accept' "${group}_fwd allows WAN egress"
    assert_match "$chain" 'drop' "${group}_fwd drops non-WAN traffic"

    # Verify device can still reach WAN
    assert_success "$group device can reach WAN" vm_exec lan "ping -c1 -W3 192.168.100.2"
done

# Restore device to quarantine for subsequent tests
result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"quarantine\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "Restored device to quarantine"

# Verify nftables restored to quarantine
vmap=$(vagrant ssh router -c "sudo nft list map inet filter device_groups_v4" 2>/dev/null || echo "")
assert_contains "$vmap" "${device_ip} : jump quarantine_fwd" "nftables restored to quarantine_fwd"

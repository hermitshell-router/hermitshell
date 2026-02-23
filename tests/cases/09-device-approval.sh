#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_nftables

# Get the LAN VM's MAC and IP
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Reset device to quarantine (idempotency: prior run may have left it in trusted)
vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"quarantine\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1

# Verify device starts in quarantine nftables map
vmap_before=$(vm_nft "list map inet filter device_groups_v4" || echo "")
assert_contains "$vmap_before" "${device_ip} : jump quarantine_fwd" "Device in quarantine_fwd before approval"

# Approve device to trusted group
result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"trusted\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "set_device_group succeeds"

# Verify group changed in device list
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"trusted"' "Device group updated to trusted"

# Verify nftables verdict map changed to trusted_fwd
vmap_after=$(vm_nft "list map inet filter device_groups_v4" || echo "")
assert_contains "$vmap_after" "${device_ip} : jump trusted_fwd" "nftables map updated to trusted_fwd"

# Trusted device should still reach internet
assert_success "Trusted device can ping WAN" vm_exec lan "ping -c1 -W2 192.168.100.2"

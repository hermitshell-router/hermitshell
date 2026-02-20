#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_nftables

# LAN VM should be in quarantine group by default
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"quarantine"' "New device starts in quarantine"

# Get LAN device IP for nftables verification
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Verify nftables verdict map routes this device to quarantine_fwd chain
vmap=$(vagrant ssh router -c "sudo nft list map inet filter device_groups_v4" 2>/dev/null || echo "")
assert_contains "$vmap" "${device_ip} : jump quarantine_fwd" "Device IP mapped to quarantine_fwd in nftables"

# Verify quarantine_fwd chain structure: allows WAN, drops everything else
chain=$(vagrant ssh router -c "sudo nft list chain inet filter quarantine_fwd" 2>/dev/null || echo "")
assert_match "$chain" 'oifname.*accept' "quarantine_fwd allows outbound to WAN"
assert_match "$chain" 'drop' "quarantine_fwd drops non-WAN traffic"

# Quarantined device should reach internet (WAN)
assert_success "Quarantined device can ping WAN" vm_exec lan "ping -c1 -W2 192.168.100.2"

# Quarantined device should also resolve DNS (basic connectivity)
assert_success "Quarantined device can resolve DNS" vm_exec lan "dig +short +time=2 +tries=1 @10.0.0.1 example.com"

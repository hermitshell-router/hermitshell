#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_nftables

# Ensure device starts in quarantine (idempotency: prior run may have changed group)
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"quarantine\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1

# LAN VM should be in quarantine group
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"quarantine"' "Device is in quarantine"

# Get LAN device IP for nftables verification
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Verify nftables verdict map routes this device to quarantine_fwd chain
vmap=$(vm_nft "list map inet filter device_groups_v4" || echo "")
assert_contains "$vmap" "${device_ip} : jump quarantine_fwd" "Device IP mapped to quarantine_fwd in nftables"

# Verify quarantine_fwd chain structure: allows WAN, drops everything else
chain=$(vm_nft "list chain inet filter quarantine_fwd" || echo "")
assert_match "$chain" 'oifname.*accept' "quarantine_fwd allows outbound to WAN"
assert_match "$chain" 'drop' "quarantine_fwd drops non-WAN traffic"

# Quarantined device should reach internet (WAN)
assert_success "Quarantined device can ping WAN" vm_exec lan "ping -c1 -W2 192.168.100.2"

# Quarantined device should also resolve DNS (basic connectivity)
assert_success "Quarantined device can resolve DNS" vm_exec lan "dig +short +time=2 +tries=1 @10.0.0.1 example.com"

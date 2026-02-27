#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

# Verify the DHCP server uses neighbor-cache MAC resolution instead of DUID parsing.
# The test VMs don't have IPv6 enabled so we can't exercise the DHCPv6 path directly.
# Instead we verify: (1) the binary contains the new code path, (2) DHCPv4 still works,
# and (3) the device record has the expected ULA allocation.

# The DHCP binary should reference "neigh" (resolve_mac_from_neigh) and NOT
# reference "extract_mac_from_duid" (removed).
dhcp_bin="/opt/hermitshell/hermitshell-dhcp"
assert_success "DHCP binary contains neigh resolution path" \
    vm_sudo router "strings $dhcp_bin | grep -q 'neigh show'"
assert_failure "DHCP binary no longer contains DUID extraction" \
    vm_sudo router "strings $dhcp_bin | grep -q 'extract_mac_from_duid'"

# DHCPv4 path should still work — LAN client has an IP and device record
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
args=$(_vm_ssh_args router)
result=$(ssh $SSH_COMMON $args "sudo bash -c 'echo \"{\\\"method\\\":\\\"get_device\\\",\\\"mac\\\":\\\"$lan_mac\\\"}\" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock'" 2>/dev/null)
assert_contains "$result" '"ok":true' "Device record exists for LAN client"
assert_contains "$result" '"ipv4":"10.0.' "Device has IPv4 address from DHCPv4"
assert_contains "$result" '"ipv6_ula":"fd' "Device has allocated ULA IPv6 address"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# LAN VM should be in quarantine group by default
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"device_group":"quarantine"' "New device starts in quarantine"

# Quarantined device should reach internet (WAN)
assert_success "Quarantined device can ping WAN" vm_exec lan "ping -c1 -W2 192.168.100.1"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Router should get IP from WAN (fake ISP)
wan_ip=$(vm_exec router "ip -4 addr show eth1 | grep -oP 'inet \K[0-9.]+'" || echo "")
assert_match "$wan_ip" "^192\.168\.100\." "Router got WAN IP from fake ISP"

# Router should be able to ping WAN gateway
assert_success "Router can ping WAN gateway" vm_exec router "ping -c1 -W2 192.168.100.1"

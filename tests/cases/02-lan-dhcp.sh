#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# LAN client should get IP from router
lan_ip=$(vm_exec lan "ip -4 addr show eth1 | grep -oP 'inet \K[0-9.]+'" || echo "")
assert_match "$lan_ip" "^10\.0\.0\." "LAN client got IP from router"

# LAN client should be able to ping router
assert_success "LAN client can ping router" vm_exec lan "ping -c1 -W2 10.0.0.1"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_wan
require_lan_ip

# LAN client should be able to reach WAN (simulated internet)
assert_success "LAN client can ping WAN gateway" vm_exec lan "ping -c1 -W2 192.168.100.2"

# LAN client should be able to resolve DNS (via router)
assert_success "LAN client can resolve DNS" vm_exec lan "host google.com"

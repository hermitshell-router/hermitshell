#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# LAN VM should have a /32 point-to-point address
lan_mask=$(vm_exec lan "ip -4 addr show eth1 | grep -oP 'inet [0-9.]+/\K[0-9]+'" || echo "")
assert_match "$lan_mask" "^32$" "LAN client has /32 netmask"

# LAN VM should have a subnet_id in the device record
devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"subnet_id":' "Device has subnet_id assigned"

# LAN VM's default gateway should be reachable via classless static route
lan_gw=$(vm_exec lan "ip route show default | grep -oP 'via \K[0-9.]+'" || echo "")
assert_match "$lan_gw" "^10\.0\." "Default gateway is in 10.0.0.0/16 range"
assert_success "LAN client can ping gateway" vm_exec lan "ping -c1 -W2 $lan_gw"

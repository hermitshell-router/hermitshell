#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

# Force DHCP renewal with hostname
vm_exec lan "sudo dhclient -r eth1 2>/dev/null; sudo dhclient eth1 -H testhost 2>/dev/null" || true

# Wait for DHCP assignment to complete
dhcp_done() {
    vm_exec lan "ip -4 addr show eth1" | grep -q '10\.0\.'
}
wait_for 10 "DHCP lease acquired" dhcp_done

# Verify the API works
result=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_devices returns ok after DHCP renewal"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Force DHCP renewal with hostname
vm_exec lan "sudo dhclient -r eth1 2>/dev/null; sudo dhclient eth1 -H testhost 2>/dev/null" || true
sleep 3

# Verify the API works
result=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_devices returns ok after DHCP renewal"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Generate some traffic from LAN VM
vm_exec lan "curl -s http://192.168.100.1 || true" >/dev/null 2>&1

# Wait for counters to appear
counters_present() {
    local devices
    devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
    echo "$devices" | grep -q '"tx_bytes":[1-9]'
}
wait_for 15 "Bandwidth counters non-zero" counters_present

devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"tx_bytes":' "Bandwidth counters present"

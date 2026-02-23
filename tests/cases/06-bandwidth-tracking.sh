#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get LAN device IP for targeted validation
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "^10\." "LAN device has 10.x IP"

# Generate some traffic from LAN VM (curl produces both tx and rx bytes)
vm_exec lan "curl -s http://192.168.100.2 || true" >/dev/null 2>&1

# Wait for tx counters to appear for this specific device
counters_present() {
    local devices
    devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
    echo "$devices" | grep -q '"tx_bytes":[1-9]'
}
wait_for 15 "Bandwidth counters non-zero" counters_present

devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')

# Verify tx_bytes is present and nonzero
assert_match "$devices" '"tx_bytes":[1-9]' "tx_bytes counter is nonzero"

# Verify rx_bytes is also tracked
assert_match "$devices" '"rx_bytes":' "rx_bytes counter is present"

# Verify the counters are on the correct device (match IP to counters)
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
device=$(vm_exec router "echo '{\"method\":\"get_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$device" '"tx_bytes":[1-9]' "tx_bytes tied to correct device MAC"
assert_contains "$device" "\"ipv4\":\"$device_ip\"" "Device IP matches in record"

# Verify nftables counter sets actually contain the device IP
tx_set=$(vm_nft "list set inet traffic tx_devices" || echo "")
assert_contains "$tx_set" "$device_ip" "Device IP in nftables tx_devices counter set"

rx_set=$(vm_nft "list set inet traffic rx_devices" || echo "")
assert_contains "$rx_set" "$device_ip" "Device IP in nftables rx_devices counter set"

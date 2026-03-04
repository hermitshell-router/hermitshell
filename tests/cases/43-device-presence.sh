#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")

# Generate traffic to ensure device is seen
vm_exec lan "curl -s http://192.168.100.2 || true" >/dev/null 2>&1
sleep 12  # Wait for 2 poll cycles (10s each) to register activity

# Test get_device_presence returns ok
presence=$(vm_exec router "echo '{\"method\":\"get_device_presence\",\"device_mac\":\"$lan_mac\",\"period\":\"24h\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$presence" '"ok":true' "get_device_presence returns ok"
assert_match "$presence" '"uptime_pct":' "Response contains uptime_pct"
assert_match "$presence" '"records":\[' "Response contains records array"
assert_match "$presence" '"period_start":' "Response contains period_start"

# Device should show as online (has recent traffic)
echo "$presence" | grep -qF '"state":"online"'
result=$?
assert_match "$result" "0" "Device shows online state"

# Device detail page renders uptime section
detail_ok() {
    local page
    page=$(vm_exec lan "curl -sk -b /tmp/cookies 'https://10.0.0.1:8443/devices/$lan_mac' 2>/dev/null || curl -sk -b /tmp/cookies 'http://10.0.0.1:8080/devices/$lan_mac' 2>/dev/null || true")
    echo "$page" | grep -q 'Uptime'
}
wait_for 15 "Device detail shows uptime section" detail_ok

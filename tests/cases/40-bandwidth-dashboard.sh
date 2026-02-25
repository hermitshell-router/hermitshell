#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "^10\." "LAN device has 10.x IP"

lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")

# Generate traffic from LAN VM
vm_exec lan "curl -s http://192.168.100.2 || true" >/dev/null 2>&1
vm_exec lan "curl -s http://192.168.100.2/index.html || true" >/dev/null 2>&1

# Trigger bandwidth rollup
rollup_ok() {
    local result
    result=$(vm_exec router "echo '{\"method\":\"run_bandwidth_rollup\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
    echo "$result" | grep -q '"ok":true'
}
wait_for 10 "Bandwidth rollup succeeds" rollup_ok

# Verify get_bandwidth_history returns data
history=$(vm_exec router "echo '{\"method\":\"get_bandwidth_history\",\"period\":\"24h\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$history" '"ok":true' "get_bandwidth_history returns ok"
assert_match "$history" '"bandwidth_history":\[' "Response contains bandwidth_history array"

# Verify get_bandwidth_realtime returns data
realtime=$(vm_exec router "echo '{\"method\":\"get_bandwidth_realtime\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$realtime" '"ok":true' "get_bandwidth_realtime returns ok"
assert_match "$realtime" '"bandwidth_realtime":\[' "Response contains bandwidth_realtime array"

# Verify get_top_destinations for device
top_dests=$(vm_exec router "echo '{\"method\":\"get_top_destinations\",\"device_mac\":\"$lan_mac\",\"period\":\"24h\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$top_dests" '"ok":true' "get_top_destinations returns ok"
assert_match "$top_dests" '"top_destinations":\[' "Response contains top_destinations array"

# Verify Traffic page renders with SVG chart (requires auth cookie from earlier test)
traffic_page_ok() {
    local page
    page=$(vm_exec lan "curl -sk -b /tmp/cookies https://10.0.0.1:8443/traffic 2>/dev/null || curl -sk -b /tmp/cookies http://10.0.0.1:8080/traffic 2>/dev/null || true")
    echo "$page" | grep -q '<svg'
}
wait_for 15 "Traffic page contains SVG chart" traffic_page_ok

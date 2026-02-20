#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_wan
require_lan_ip
require_nftables

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Make a specific outbound connection to a known destination
vm_exec lan "curl -s -o /dev/null http://192.168.100.2/ 2>/dev/null" || true

# Wait for the connection to appear in logs (conntrack processes async)
conn_logged() {
    vm_exec router "echo '{\"method\":\"list_connection_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" | grep -q '"dest_ip":"192.168.100.2"'
}
wait_for 15 "Connection logged in database" conn_logged

# Query connection logs for this device
result=$(vm_exec router "echo '{\"method\":\"list_connection_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "list_connection_logs succeeds"
assert_contains "$result" '"connection_logs"' "response has connection_logs field"

# Verify the logged connection has correct fields
assert_contains "$result" '"dest_ip":"192.168.100.2"' "Log has correct dest IP"
assert_contains "$result" '"dest_port":80' "Log has correct dest port"
assert_contains "$result" '"protocol":"tcp"' "Log has correct protocol"
assert_contains "$result" "\"device_ip\":\"$device_ip\"" "Log has correct source device IP"
assert_contains "$result" '"started_at":' "Log has started_at timestamp"

# Query without filter returns results too
result=$(vm_exec router 'echo "{\"method\":\"list_connection_logs\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "Unfiltered list_connection_logs succeeds"
assert_contains "$result" '"dest_ip"' "Unfiltered results contain log entries"

# Query with offset
result=$(vm_exec router 'echo "{\"method\":\"list_connection_logs\",\"limit\":10,\"offset\":0}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_connection_logs with offset succeeds"

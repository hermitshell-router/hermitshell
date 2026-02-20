#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_wan
require_lan_ip
require_nftables

# LAN device makes an outbound connection (triggers conntrack NEW)
vm_exec lan "curl -s -o /dev/null http://1.1.1.1/ 2>/dev/null" || true

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Query connection logs for this device
result=$(vm_exec router "echo '{\"method\":\"list_connection_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "list_connection_logs succeeds"
assert_match "$result" '"connection_logs"' "response contains connection_logs"

# Query connection logs without filter
result=$(vm_exec router 'echo "{\"method\":\"list_connection_logs\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_connection_logs without filter succeeds"

# Query with offset
result=$(vm_exec router 'echo "{\"method\":\"list_connection_logs\",\"limit\":10,\"offset\":0}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_connection_logs with offset succeeds"

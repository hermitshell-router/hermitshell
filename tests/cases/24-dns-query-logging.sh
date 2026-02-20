#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip
require_blocky

# LAN device resolves a domain (generates DNS log entry if Blocky CSV ingest is active)
vm_exec lan "dig +short example.com @10.0.0.1 2>/dev/null" || true

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Query DNS logs for this device
result=$(vm_exec router "echo '{\"method\":\"list_dns_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "list_dns_logs succeeds"
assert_match "$result" '"dns_logs"' "response contains dns_logs"

# Query DNS logs without filter
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs without filter succeeds"

# Query with offset
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":10,\"offset\":0}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs with offset succeeds"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip
require_dns

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Make a specific DNS query we can identify in logs
vm_exec lan "dig +short dns-log-test.example.com @10.0.0.1 2>/dev/null" || true

# Flush unbound's buffered log output (1.19+ buffers writes) and trigger ingest.
# ingest_dns_logs requires root (admin-only method) and sends SIGHUP internally.
sleep 1
vm_sudo router 'echo "{\"method\":\"ingest_dns_logs\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null
dns_logged() {
    vm_sudo router 'echo "{\"method\":\"ingest_dns_logs\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null 2>&1
    vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":100}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q 'dns-log-test'
}
wait_for 15 "DNS query logged in database" dns_logged

# Query DNS logs (unfiltered)
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":100}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs succeeds"
assert_contains "$result" '"dns_logs"' "response has dns_logs field"

# Verify the logged query has correct fields
assert_contains "$result" 'dns-log-test' "Log has correct queried domain"
assert_contains "$result" '"domain"' "Log entries have domain field"
assert_contains "$result" '"ts":' "Log has timestamp"

# Query with offset
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":10,\"offset\":0}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs with offset succeeds"

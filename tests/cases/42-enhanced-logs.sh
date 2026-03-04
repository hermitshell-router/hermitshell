#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Generate traffic
vm_exec lan "curl -s http://192.168.100.2 || true" >/dev/null 2>&1
sleep 2

now=$(date +%s)
since=$((now - 3600))

# Test list_connection_logs with since filter
logs=$(vm_exec router "echo '{\"method\":\"list_connection_logs\",\"since\":$since,\"limit\":10}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$logs" '"ok":true' "list_connection_logs with since filter returns ok"

# Test list_connection_logs with protocol filter
logs=$(vm_exec router "echo '{\"method\":\"list_connection_logs\",\"protocol\":\"tcp\",\"limit\":10}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$logs" '"ok":true' "list_connection_logs with protocol filter returns ok"

# Test count_connection_logs
stats=$(vm_exec router "echo '{\"method\":\"count_connection_logs\",\"since\":$since}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$stats" '"ok":true' "count_connection_logs returns ok"
assert_match "$stats" '"total":' "count_connection_logs contains total"
assert_match "$stats" '"unique_destinations":' "count_connection_logs contains unique_destinations"

# Test count_dns_logs
stats=$(vm_exec router "echo '{\"method\":\"count_dns_logs\",\"since\":$since}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$stats" '"ok":true' "count_dns_logs returns ok"
assert_match "$stats" '"total":' "count_dns_logs contains total"

# Test list_dns_logs with since filter
logs=$(vm_exec router "echo '{\"method\":\"list_dns_logs\",\"since\":$since,\"limit\":10}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$logs" '"ok":true' "list_dns_logs with since filter returns ok"

# Logs page renders with stats
logs_page_ok() {
    local page
    page=$(vm_exec lan "curl -sk -b /tmp/cookies 'https://10.0.0.1:8443/logs?range=24h' 2>/dev/null || curl -sk -b /tmp/cookies 'http://10.0.0.1:8080/logs?range=24h' 2>/dev/null || true")
    echo "$page" | grep -q 'connections'
}
wait_for 15 "Logs page renders with stats" logs_page_ok

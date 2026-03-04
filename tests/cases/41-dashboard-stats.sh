#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Test get_dashboard_stats API
stats=$(vm_exec router "echo '{\"method\":\"get_dashboard_stats\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$stats" '"ok":true' "get_dashboard_stats returns ok"
assert_match "$stats" '"connections_24h":' "Response contains connections_24h"
assert_match "$stats" '"dns_queries_24h":' "Response contains dns_queries_24h"
assert_match "$stats" '"unacked_alerts":' "Response contains unacked_alerts"
assert_match "$stats" '"top_talkers":\[' "Response contains top_talkers array"

# Dashboard page renders sparkline and stats
dashboard_ok() {
    local page
    page=$(vm_exec lan "curl -sk -b /tmp/cookies https://10.0.0.1:8443/ 2>/dev/null || curl -sk -b /tmp/cookies http://10.0.0.1:8080/ 2>/dev/null || true")
    echo "$page" | grep -q '<svg' && echo "$page" | grep -q 'Connections (24h)'
}
wait_for 15 "Dashboard renders sparkline and activity stats" dashboard_ok

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_dns

# Verify unbound process is running
unbound_pid=$(vm_exec router "pgrep unbound" || echo "")
assert_match "$unbound_pid" "^[0-9]+" "Unbound process is running"

# Wait for unbound to be ready (listening on DNS port)
unbound_ready() {
    vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" | grep -q '[0-9]'
}
wait_for 10 "Unbound is listening" unbound_ready

# Verify unbound resolves normal DNS
normal=$(vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" || echo "")
assert_match "$normal" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Unbound resolves normal DNS"

# Add a test-specific custom DNS rule to block ads.test.hermitshell
result=$(vm_exec router 'echo "{\"method\":\"add_dns_rule\",\"name\":\"ads.test.hermitshell\",\"key\":\"A\",\"value\":\"0.0.0.0\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "Add test blocklist rule"

# Verify the custom rule resolves to 0.0.0.0
rule_blocked() {
    local result
    result=$(vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 ads.test.hermitshell" || echo "")
    [ "$result" = "0.0.0.0" ]
}
wait_for 10 "Custom rule applied" rule_blocked
pass "Custom rule domain resolves to 0.0.0.0"

# Toggle ad blocking off via API
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(false) succeeds"

# Verify ad blocking toggle reported correctly
status=$(vm_exec router 'echo "{\"method\":\"get_ad_blocking\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$status" '"ad_blocking_enabled":false' "get_ad_blocking reports disabled"

# Toggle ad blocking back on
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(true) succeeds"

status=$(vm_exec router 'echo "{\"method\":\"get_ad_blocking\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$status" '"ad_blocking_enabled":true' "get_ad_blocking reports enabled"

# Clean up test rule
result=$(vm_exec router 'echo "{\"method\":\"list_dns_rules\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
# Extract the ID of our test rule and remove it
rule_id=$(echo "$result" | python3 -c "import sys,json; rules=json.loads(sys.stdin.read()).get('dns_custom_rules',[]); print(next((r['id'] for r in rules if r['domain']=='ads.test.hermitshell'), ''))" 2>/dev/null || echo "")
if [ -n "$rule_id" ]; then
    vm_exec router "echo '{\"method\":\"remove_dns_rule\",\"id\":$rule_id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1
fi

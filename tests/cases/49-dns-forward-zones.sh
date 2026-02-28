#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_dns

# Add a forward zone
result=$(vm_exec router 'echo "{\"method\":\"add_dns_forward\",\"name\":\"test.local\",\"value\":\"10.0.0.1\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "add_dns_forward succeeds"

# List forward zones and verify
result=$(vm_exec router 'echo "{\"method\":\"list_dns_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "list_dns_forwards succeeds"
assert_contains "$result" 'test.local' "Forward zone domain present"
assert_contains "$result" '10.0.0.1' "Forward zone address present"

# Extract ID of our zone
zone_id=$(echo "$result" | python3 -c "import sys,json; zones=json.loads(sys.stdin.read()).get('dns_forward_zones',[]); print(next((z['id'] for z in zones if z['domain']=='test.local'), ''))" 2>/dev/null || echo "")
assert_match "$zone_id" "^[0-9]+" "Forward zone has numeric ID"

# Remove the forward zone
result=$(vm_exec router "echo '{\"method\":\"remove_dns_forward\",\"id\":$zone_id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "remove_dns_forward succeeds"

# Verify it's gone
result=$(vm_exec router 'echo "{\"method\":\"list_dns_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
if echo "$result" | grep -q 'test.local'; then
    fail "Forward zone not removed"
fi
pass "Forward zone removed successfully"

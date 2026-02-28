#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_dns

# Add custom rule: myhost.home -> 10.0.1.50
result=$(vm_exec router 'echo "{\"method\":\"add_dns_rule\",\"name\":\"myhost.home\",\"key\":\"A\",\"value\":\"10.0.1.50\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "add_dns_rule succeeds"

# Wait for Unbound to reload and serve the record
rule_resolves() {
    local r
    r=$(vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 myhost.home" || echo "")
    [ "$r" = "10.0.1.50" ]
}
wait_for 10 "Custom rule resolves" rule_resolves

# Verify resolution
resolved=$(vm_exec router "dig +short +time=2 +tries=1 @10.0.0.1 myhost.home" || echo "")
assert_match "$resolved" "10\.0\.1\.50" "Custom rule resolves to correct IP"

# List rules and verify
result=$(vm_exec router 'echo "{\"method\":\"list_dns_rules\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "list_dns_rules succeeds"
assert_contains "$result" 'myhost.home' "Custom rule domain present"
assert_contains "$result" '10.0.1.50' "Custom rule value present"

# Extract ID and remove
rule_id=$(echo "$result" | python3 -c "import sys,json; rules=json.loads(sys.stdin.read()).get('dns_custom_rules',[]); print(next((r['id'] for r in rules if r['domain']=='myhost.home'), ''))" 2>/dev/null || echo "")
assert_match "$rule_id" "^[0-9]+" "Custom rule has numeric ID"

result=$(vm_exec router "echo '{\"method\":\"remove_dns_rule\",\"id\":$rule_id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "remove_dns_rule succeeds"

# Verify rule no longer resolves (should get NXDOMAIN or empty)
rule_gone() {
    local r
    r=$(vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 myhost.home" || echo "")
    [ "$r" != "10.0.1.50" ]
}
wait_for 10 "Custom rule removed from DNS" rule_gone
pass "Custom rule removed and no longer resolves"

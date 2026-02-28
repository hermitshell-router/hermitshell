#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_nftables

# Verify nftables has DoT/DoH rules loaded
nft_rules=$(vm_sudo router "nft list ruleset" || echo "")
assert_contains "$nft_rules" "doh_block_v4" "nftables has DoH block set"

# From LAN device (quarantine group by default), attempt DoT connection to 1.1.1.1:853
# This should fail/timeout because nftables drops port 853 for quarantine group
dot_result=$(vm_exec lan "timeout 3 bash -c 'echo Q | openssl s_client -connect 1.1.1.1:853 2>&1'" 2>&1 || echo "TIMEOUT")
# The connection should fail — either timeout, connection refused, or error
if echo "$dot_result" | grep -qE "CONNECTED.*SSL"; then
    fail "DoT connection to 1.1.1.1:853 succeeded (should be blocked)"
fi
pass "DoT (port 853) blocked for quarantine device"

# Verify DNS still works through the router's Unbound (port 53 redirected to Unbound)
dns_ok() {
    vm_exec lan "dig +short +time=2 +tries=1 @10.0.0.1 example.com" | grep -q '[0-9]'
}
wait_for 10 "DNS via Unbound works" dns_ok
resolved=$(vm_exec lan "dig +short +time=2 +tries=1 @10.0.0.1 example.com" || echo "")
assert_match "$resolved" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Normal DNS resolution works through Unbound"

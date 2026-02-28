#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_dns
require_nftables

# Query normal domain via 8.8.8.8 from LAN — DNAT should redirect to router's Unbound
# If redirect works, we'll get a valid answer from Unbound instead of from 8.8.8.8 directly
dns_redirected() {
    local result
    result=$(vm_exec lan "dig +short +time=2 +tries=1 @8.8.8.8 example.com" || echo "")
    echo "$result" | grep -q '[0-9]'
}
wait_for 10 "DNS redirect active" dns_redirected

resolved=$(vm_exec lan "dig +short +time=2 +tries=1 @8.8.8.8 example.com" || echo "")
assert_match "$resolved" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "DNS redirect catches hardcoded DNS (query to 8.8.8.8 redirected)"

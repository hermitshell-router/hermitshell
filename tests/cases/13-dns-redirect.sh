#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Query ad domain via 8.8.8.8 from LAN — should still be blocked via DNAT
dns_redirected() {
    local result
    result=$(vm_exec lan "dig +short @8.8.8.8 ads.test.hermitshell" || echo "")
    echo "$result" | grep -q '0\.0\.0\.0'
}
wait_for 10 "DNS redirect active" dns_redirected

blocked=$(vm_exec lan "dig +short @8.8.8.8 ads.test.hermitshell" || echo "")
assert_match "$blocked" "0\.0\.0\.0" "DNS redirect catches hardcoded DNS (ad domain blocked via 8.8.8.8)"

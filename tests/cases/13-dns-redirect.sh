#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Query ad domain via 8.8.8.8 from LAN — should still be blocked via DNAT
blocked=$(vm_exec lan "dig +short @8.8.8.8 ads.test.hermitshell" || echo "")
assert_match "$blocked" "0\.0\.0\.0" "DNS redirect catches hardcoded DNS (ad domain blocked via 8.8.8.8)"

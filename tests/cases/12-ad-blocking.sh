#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Verify blocky process is running
blocky_pid=$(vm_exec router "pgrep blocky" || echo "")
assert_match "$blocky_pid" "^[0-9]+" "Blocky process is running"

# Verify blocky resolves normal DNS
normal=$(vm_exec router "dig +short @10.0.0.1 example.com" || echo "")
assert_match "$normal" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Blocky resolves normal DNS"

# Verify ad domain is blocked (returns 0.0.0.0)
blocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$blocked" "0\.0\.0\.0" "Ad domain blocked by blocky"

# Toggle ad blocking off via API
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(false) succeeds"

# After disabling, ad domain should resolve normally
sleep 1
unblocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$unblocked" "93\.184\.216\.34" "Ad domain resolves when blocking disabled"

# Toggle ad blocking back on
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(true) succeeds"

# Verify ad domain is blocked again
sleep 1
reblocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$reblocked" "0\.0\.0\.0" "Ad domain blocked again after re-enable"

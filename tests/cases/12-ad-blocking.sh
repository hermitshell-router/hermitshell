#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_blocky

# Verify blocky process is running
blocky_pid=$(vm_exec router "pgrep blocky" || echo "")
assert_match "$blocky_pid" "^[0-9]+" "Blocky process is running"

# Wait for blocky to be ready (listening on DNS port)
blocky_ready() {
    vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" | grep -q '[0-9]'
}
wait_for 10 "Blocky is listening" blocky_ready

# Verify blocky resolves normal DNS
normal=$(vm_exec router "dig +short @10.0.0.1 example.com" || echo "")
assert_match "$normal" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Blocky resolves normal DNS"

# Verify ad domain is blocked (returns 0.0.0.0)
ad_blocked() {
    local result
    result=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
    echo "$result" | grep -q '0\.0\.0\.0'
}
wait_for 10 "Ad domain blocked by blocky" ad_blocked

blocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$blocked" "0\.0\.0\.0" "Ad domain blocked by blocky"

# Toggle ad blocking off via API
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(false) succeeds"

# After disabling, ad domain should resolve normally
ad_unblocked() {
    local result
    result=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
    echo "$result" | grep -q '93\.184\.216\.34'
}
wait_for 10 "Ad domain resolves after disable" ad_unblocked

unblocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$unblocked" "93\.184\.216\.34" "Ad domain resolves when blocking disabled"

# Toggle ad blocking back on
result=$(vm_exec router 'echo "{\"method\":\"set_ad_blocking\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_ad_blocking(true) succeeds"

# Verify ad domain is blocked again
wait_for 10 "Ad domain re-blocked after enable" ad_blocked

reblocked=$(vm_exec router "dig +short @10.0.0.1 ads.test.hermitshell" || echo "")
assert_match "$reblocked" "0\.0\.0\.0" "Ad domain blocked again after re-enable"

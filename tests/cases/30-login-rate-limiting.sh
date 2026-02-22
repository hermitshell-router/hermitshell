#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK=/run/hermitshell/agent.sock

# First wrong attempt: should return false (no rate limit yet)
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrong1\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$resp" '"config_value":"false"' "First wrong attempt not rate-limited"

# Second wrong attempt immediately
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrong2\"}' | socat - UNIX-CONNECT:$SOCK")
echo "Second attempt: $resp"

# Third attempt should be rate-limited (2s backoff from 2 failures)
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrong3\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$resp" 'Too many attempts' "Third rapid attempt is rate-limited"

# Correct password also blocked during cooldown
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"testpass123\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$resp" 'Too many attempts' "Correct password blocked during cooldown"

# Wait for backoff to expire
sleep 3

# Correct password works after cooldown and resets counter
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"testpass123\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$resp" '"config_value":"true"' "Correct password works after cooldown"

# After reset, wrong attempt is not rate-limited
resp=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrong4\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$resp" '"config_value":"false"' "Wrong attempt after reset not rate-limited"

# Web UI rate limiting
require_docker

login_action=$(vm_exec router "curl -s -k -L https://localhost:8443/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi

# Send several wrong logins to trigger web UI rate limiting
for i in 1 2 3; do
    vm_exec router "curl -s -k -o /dev/null -X POST -d 'password=wrongwebui' https://localhost:8443${login_action}"
done

# Next attempt should get 429
http_code=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=wrongwebui' https://localhost:8443${login_action}")
assert_match "$http_code" "429" "Web UI returns 429 after repeated failures"

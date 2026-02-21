#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK=/run/hermitshell/agent.sock

# --- create_session returns new token format ---
result=$(vm_exec router "echo '{\"method\":\"create_session\"}' | socat - UNIX-CONNECT:$SOCK")
assert_match "$result" '"ok":true' "create_session succeeds"

# New format: admin:CREATED:LAST_ACTIVE.HMAC (two colons before the dot)
cookie=$(echo "$result" | sed 's/.*"config_value":"\([^"]*\)".*/\1/')
assert_match "$cookie" '^admin:[0-9]+:[0-9]+\.' "create_session returns new token format"

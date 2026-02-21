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

# --- verify_session accepts fresh token ---
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"$cookie\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$result" '"config_value":"true"' "verify_session accepts fresh new-format token"

# --- verify_session rejects token with expired absolute timeout ---
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"admin:0.badsig\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$result" '"config_value":"false"' "verify_session rejects bad signature"

# --- verify_session rejects old format tokens ---
old_format="admin:1234567890.fakesig"
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"$old_format\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$result" '"config_value":"false"' "verify_session rejects old single-timestamp format"

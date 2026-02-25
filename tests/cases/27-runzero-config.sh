#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# Disable runzero (idempotency: prior run may have left it enabled)
vm_exec router 'echo "{\"method\":\"set_runzero_config\",\"value\":\"{\\\"runzero_enabled\\\":\\\"false\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null 2>&1

# --- runZero config defaults ---
result=$(vm_exec router "echo '{\"method\":\"get_runzero_config\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_runzero_config succeeds"
assert_match "$result" '"enabled":false' "runzero disabled by default"

# --- set_runzero_config ---
result=$(vm_exec router 'echo "{\"method\":\"set_runzero_config\",\"value\":\"{\\\"runzero_url\\\":\\\"https://runzero.lan:8443\\\",\\\"runzero_token\\\":\\\"XT-test123\\\",\\\"runzero_sync_interval\\\":\\\"1800\\\",\\\"runzero_enabled\\\":\\\"true\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_runzero_config succeeds"

# --- get_runzero_config masks token ---
result=$(vm_exec router "echo '{\"method\":\"get_runzero_config\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_runzero_config after set succeeds"
assert_match "$result" 'runzero.lan:8443' "url persisted"
assert_match "$result" '"1800"' "sync interval persisted"
assert_match "$result" '"enabled":true' "enabled persisted"
# Token should NOT appear in plain text
if echo "$result" | grep -qF "XT-test123"; then
    echo -e "${RED}FAIL${NC}: get_runzero_config leaks token in plaintext"
else
    echo -e "${GREEN}PASS${NC}: get_runzero_config masks token"
fi

# --- runzero_token is blocked in get_config ---
result=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"runzero_token\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "get_config blocks runzero_token"
assert_match "$result" 'access denied' "get_config runzero_token returns access denied"

# --- set_config blocks runzero_token ---
result=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"runzero_token\",\"value\":\"hack\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "set_config blocks runzero_token"

# --- sync_runzero starts (fire-and-forget, url+token are set) ---
result=$(vm_exec router "echo '{\"method\":\"sync_runzero\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "sync_runzero accepts when configured"
assert_match "$result" 'sync started' "sync_runzero returns sync started"

# --- list_devices includes runzero fields (all null for now) ---
result=$(vm_exec router "echo '{\"method\":\"list_devices\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "list_devices succeeds with new schema"

# --- export_config includes runzero settings ---
result=$(vm_exec router "echo '{\"method\":\"export_config\"}' | socat - $SOCK")
assert_contains "$result" '"ok":true' "export_config succeeds"
assert_contains "$result" 'runzero_url' "export includes runzero_url"
assert_contains "$result" 'runzero_sync_interval' "export includes runzero_sync_interval"
assert_contains "$result" 'runzero_enabled' "export includes runzero_enabled"
# Token must NOT be in export
if echo "$result" | grep -qF "XT-test123"; then
    echo -e "${RED}FAIL${NC}: export_config leaks runzero_token"
else
    echo -e "${GREEN}PASS${NC}: export_config does not leak runzero_token"
fi

# --- generate test CA cert ---
TEST_CA_PEM=$(vm_exec router 'openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 1 -nodes -subj "/CN=testca" 2>/dev/null')

# --- set runzero CA cert ---
CA_JSON=$(python3 -c "import json; print(json.dumps({'runzero_ca_cert': '''$TEST_CA_PEM'''}))")
REQ_JSON=$(python3 -c "import json; print(json.dumps({'method': 'set_runzero_config', 'value': '''$CA_JSON'''}))")
result=$(echo "$REQ_JSON" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_runzero_config with CA cert succeeds"

# --- get_runzero_config shows has_ca_cert ---
result=$(vm_exec router "echo '{\"method\":\"get_runzero_config\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":true' "get_runzero_config shows has_ca_cert"

# --- runzero_ca_cert blocked in get_config ---
result=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"runzero_ca_cert\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "get_config blocks runzero_ca_cert"

# --- invalid PEM rejected ---
INVALID_JSON=$(python3 -c "import json; print(json.dumps({'runzero_ca_cert': 'not-a-cert'}))")
INVALID_REQ=$(python3 -c "import json; print(json.dumps({'method': 'set_runzero_config', 'value': '''$INVALID_JSON'''}))")
result=$(echo "$INVALID_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "set_runzero_config rejects invalid PEM"

# --- clear CA cert ---
CLEAR_JSON=$(python3 -c "import json; print(json.dumps({'runzero_ca_cert': ''}))")
CLEAR_REQ=$(python3 -c "import json; print(json.dumps({'method': 'set_runzero_config', 'value': '''$CLEAR_JSON'''}))")
result=$(echo "$CLEAR_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_runzero_config clears CA cert"

result=$(vm_exec router "echo '{\"method\":\"get_runzero_config\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":false' "get_runzero_config shows has_ca_cert false after clear"

# --- export includes runzero_ca_cert ---
# Set it again for export test
result=$(echo "$REQ_JSON" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
result=$(vm_exec router "echo '{\"method\":\"export_config\"}' | socat - $SOCK")
assert_contains "$result" 'runzero_ca_cert' "export includes runzero_ca_cert"

# --- clear for subsequent tests ---
result=$(echo "$CLEAR_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')

# --- Disable runzero for subsequent tests ---
vm_exec router 'echo "{\"method\":\"set_runzero_config\",\"value\":\"{\\\"runzero_enabled\\\":\\\"false\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null

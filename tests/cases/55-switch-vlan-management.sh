#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 55: SNMP switch management API ==="

# --- Add an SNMP switch ---
ADD_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_add\",\"name\":\"test-switch\",\"key\":\"192.168.1.100\",\"value\":\"public\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$ADD_RESULT" '"ok":true' "switch_add accepted"

# --- List switches ---
LIST_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$LIST_RESULT" '"ok":true' "switch_list succeeds"
assert_match "$LIST_RESULT" "test-switch" "switch_list shows added switch"
assert_match "$LIST_RESULT" "192\.168\.1\.100" "switch_list shows host"

# --- Remove switch ---
REMOVE_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_remove\",\"name\":\"test-switch\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$REMOVE_RESULT" '"ok":true' "switch_remove succeeds"

# --- Verify removal ---
LIST_EMPTY=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$LIST_EMPTY" '"ok":true' "switch_list after remove succeeds"
if echo "$LIST_EMPTY" | grep -q "test-switch"; then
    echo -e "${RED}FAIL${NC}: switch still in list after remove"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: switch removed from list"
fi

# --- Add a v3 SNMP switch ---
V3_JSON=$(python3 -c "import json; print(json.dumps({
    'method': 'switch_add',
    'name': 'v3-switch',
    'key': '192.168.1.200',
    'snmp_version': '3',
    'v3_username': 'snmpuser',
    'v3_auth_pass': 'authpass123',
    'v3_priv_pass': 'privpass123',
    'v3_auth_protocol': 'sha256',
    'v3_cipher': 'aes128'
}))")
V3_ADD=$(vm_sudo router "echo '$V3_JSON' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$V3_ADD" '"ok":true' "v3 switch_add accepted"

# --- List shows v3 switch with version ---
V3_LIST=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$V3_LIST" '"ok":true' "switch_list with v3 succeeds"
assert_match "$V3_LIST" "v3-switch" "switch_list shows v3 switch"
assert_match "$V3_LIST" '"version":"3"' "v3 switch shows version 3"
assert_match "$V3_LIST" '"v3_username":"snmpuser"' "v3 switch shows username"

# --- Remove v3 switch ---
V3_REMOVE=$(vm_sudo router 'echo "{\"method\":\"switch_remove\",\"name\":\"v3-switch\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$V3_REMOVE" '"ok":true' "v3 switch_remove succeeds"

echo "=== Test 55 complete ==="

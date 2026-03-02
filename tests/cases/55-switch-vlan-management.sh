#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 55: Switch VLAN management API ==="

# --- Add a switch provider ---
ADD_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_add\",\"name\":\"test-switch\",\"key\":\"192.168.1.100\",\"value\":\"admin\",\"description\":\"admin123\",\"group\":\"cisco_ios\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$ADD_RESULT" '"ok":true' "switch_add accepted"

# --- List switches ---
LIST_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$LIST_RESULT" '"ok":true' "switch_list succeeds"
assert_match "$LIST_RESULT" "test-switch" "switch_list shows added switch"
assert_match "$LIST_RESULT" "192\.168\.1\.100" "switch_list shows host"
assert_match "$LIST_RESULT" "cisco_ios" "switch_list shows vendor profile"

# --- Set uplink port ---
# First we need the switch ID from the list result
# The list returns config_value with JSON array containing objects with "id" field
UPLINK_RESULT=$(vm_sudo router 'echo "{\"method\":\"switch_set_uplink\",\"name\":\"test-switch\",\"value\":\"Gi0/1\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$UPLINK_RESULT" '"ok":true' "switch_set_uplink succeeds"

# --- Verify uplink in list ---
LIST_AFTER=$(vm_sudo router 'echo "{\"method\":\"switch_list\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$LIST_AFTER" "Gi0/1" "switch_list shows uplink port"

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

echo "=== Test 55 complete ==="

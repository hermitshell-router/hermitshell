#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- list_interfaces returns interfaces ---
result=$(vm_exec router "echo '{\"method\":\"list_interfaces\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "list_interfaces succeeds"
assert_match "$result" '"interfaces":\[' "interfaces array present"
assert_match "$result" '"name"' "interface has name field"
assert_match "$result" '"mac"' "interface has mac field"

# --- list_interfaces excludes loopback ---
if echo "$result" | grep -q '"name":"lo"'; then
    echo -e "${RED}FAIL${NC}: lo should be excluded"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: lo excluded"
fi

# --- set_interfaces blocked after password is set ---
result=$(vm_exec router 'echo "{\"method\":\"set_interfaces\",\"key\":\"eth1\",\"value\":\"eth2\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "set_interfaces blocked after password set"
assert_match "$result" 'initial setup' "error mentions initial setup"

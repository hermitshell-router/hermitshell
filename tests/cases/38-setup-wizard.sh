#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- list_interfaces returns interfaces ---
result=$(vm_exec router "echo '{\"method\":\"list_interfaces\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "list_interfaces succeeds"
assert_match "$result" '"interfaces":\[' "interfaces array present"

# lo should be excluded
if echo "$result" | grep -q '"name":"lo"'; then
    echo -e "${RED}FAIL${NC}: lo should be excluded"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: lo excluded"
fi

# --- setup_wan_config works before setup complete ---
result=$(vm_exec router 'echo "{\"method\":\"setup_wan_config\",\"value\":\"dhcp\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "setup_wan_config (dhcp) succeeds"

# --- set_hostname works ---
result=$(vm_exec router 'echo "{\"method\":\"set_hostname\",\"value\":\"testrouter\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "set_hostname succeeds"

# --- set_timezone works ---
result=$(vm_exec router 'echo "{\"method\":\"set_timezone\",\"value\":\"UTC\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "set_timezone succeeds"

# --- set_timezone rejects path traversal ---
result=$(vm_exec router 'echo "{\"method\":\"set_timezone\",\"value\":\"../etc/passwd\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "set_timezone rejects path traversal"

# --- setup_get_summary returns config ---
result=$(vm_exec router 'echo "{\"method\":\"setup_get_summary\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "setup_get_summary succeeds"
assert_match "$result" '"hostname"' "summary contains hostname"

# --- finalize_setup fails without password ---
result=$(vm_exec router 'echo "{\"method\":\"finalize_setup\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "finalize_setup blocked without password"

# --- set_interfaces blocked after password set ---
result=$(vm_exec router 'echo "{\"method\":\"set_interfaces\",\"key\":\"eth1\",\"value\":\"eth2\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "set_interfaces blocked after password set"
assert_match "$result" 'initial setup' "error mentions initial setup"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

# --- Test 1: Non-root caller can access web-allowed methods ---
# Tests run as vagrant user with chmod 666 socket — this is the "web" role
result=$(vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "non-root can call get_status"

result=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "non-root can call list_devices"

# --- Test 2: Non-root caller cannot access admin-only methods ---
result=$(vm_exec router 'echo "{\"method\":\"dhcp_discover\",\"mac\":\"aa:bb:cc:dd:ee:ff\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "non-root cannot call dhcp_discover"
assert_contains "$result" "access denied" "dhcp_discover returns access denied"

result=$(vm_exec router 'echo "{\"method\":\"ingest_dns_logs\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "non-root cannot call ingest_dns_logs"
assert_contains "$result" "access denied" "ingest_dns_logs returns access denied"

# --- Test 3: Root caller can access admin-only methods ---
result=$(vm_sudo router 'echo "{\"method\":\"dhcp_discover\",\"mac\":\"aa:bb:cc:dd:ee:ff\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
# This should succeed (or fail for other reasons, but NOT "access denied")
if echo "$result" | grep -q "access denied"; then
    echo -e "${RED}FAIL${NC}: root caller got access denied for dhcp_discover"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: root caller can call dhcp_discover"
fi

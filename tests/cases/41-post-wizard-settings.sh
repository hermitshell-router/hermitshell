#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- update_hostname works post-setup ---
result=$(vm_exec router 'echo "{\"method\":\"update_hostname\",\"value\":\"testrouter\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "update_hostname works post-setup"

# Verify hostname stored
result=$(vm_exec router 'echo "{\"method\":\"get_config\",\"key\":\"router_hostname\"}" | socat - '"$SOCK")
assert_match "$result" 'testrouter' "hostname stored correctly"

# --- update_timezone works post-setup ---
result=$(vm_exec router 'echo "{\"method\":\"update_timezone\",\"value\":\"America/New_York\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "update_timezone works post-setup"

# --- update_timezone rejects path traversal ---
result=$(vm_exec router 'echo "{\"method\":\"update_timezone\",\"value\":\"../etc/passwd\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "update_timezone rejects traversal"

# --- update_upstream_dns works ---
result=$(vm_exec router 'echo "{\"method\":\"update_upstream_dns\",\"value\":\"1.1.1.1\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "update_upstream_dns works"

# --- update_upstream_dns rejects invalid ---
result=$(vm_exec router 'echo "{\"method\":\"update_upstream_dns\",\"value\":\"not-an-ip\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "update_upstream_dns rejects invalid IP"

# --- update_wan_config works ---
result=$(vm_exec router 'echo "{\"method\":\"update_wan_config\",\"value\":\"dhcp\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "update_wan_config works"

# --- update_wan_config rejects invalid mode ---
result=$(vm_exec router 'echo "{\"method\":\"update_wan_config\",\"value\":\"pppoe\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "update_wan_config rejects invalid mode"

# --- update_interfaces rejects same iface for both ---
result=$(vm_exec router 'echo "{\"method\":\"update_interfaces\",\"key\":\"eth1\",\"value\":\"eth1\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":false' "update_interfaces rejects same interface"

# --- password change works ---
result=$(vm_exec router 'echo "{\"method\":\"setup_password\",\"value\":\"newpassword123\",\"key\":\"admin123\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "password change works"

# Change back
result=$(vm_exec router 'echo "{\"method\":\"setup_password\",\"value\":\"admin123\",\"key\":\"newpassword123\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "password reverted"

# --- DNS blocklist CRUD ---
result=$(vm_exec router 'echo "{\"method\":\"add_dns_blocklist\",\"name\":\"test-list\",\"url\":\"https://example.com/hosts.txt\",\"key\":\"ads\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "add_dns_blocklist works"

result=$(vm_exec router 'echo "{\"method\":\"list_dns_blocklists\"}" | socat - '"$SOCK")
assert_match "$result" 'test-list' "blocklist appears in list"

# --- DNS forward CRUD ---
result=$(vm_exec router 'echo "{\"method\":\"add_dns_forward\",\"name\":\"internal.local\",\"value\":\"10.0.0.100\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "add_dns_forward works"

result=$(vm_exec router 'echo "{\"method\":\"list_dns_forwards\"}" | socat - '"$SOCK")
assert_match "$result" 'internal.local' "forward zone appears"

# --- DNS rule CRUD ---
result=$(vm_exec router 'echo "{\"method\":\"add_dns_rule\",\"name\":\"test.local\",\"key\":\"A\",\"value\":\"10.0.0.50\"}" | socat - '"$SOCK")
assert_match "$result" '"ok":true' "add_dns_rule works"

result=$(vm_exec router 'echo "{\"method\":\"list_dns_rules\"}" | socat - '"$SOCK")
assert_match "$result" 'test.local' "DNS rule appears"

# --- set_dns_config works ---
result=$(vm_exec router "echo '{\"method\":\"set_dns_config\",\"value\":\"{\\\\\"ratelimit_per_client\\\\\":\\\\\"100\\\\\",\\\\\"ratelimit_per_domain\\\\\":\\\\\"50\\\\\"}\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_dns_config works"

#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- wifi_list_aps defaults empty ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_list_aps succeeds"
assert_match "$result" '"wifi_aps":\[\]' "no APs adopted by default"

# --- wifi_adopt_ap ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"url\":\"192.168.1.100\",\"name\":\"Office AP\",\"key\":\"admin\",\"value\":\"testpass123\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "wifi_adopt_ap succeeds"

# --- wifi_list_aps shows adopted AP ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_list_aps after adopt succeeds"
assert_match "$result" 'Office AP' "adopted AP name appears"
assert_match "$result" 'aa:bb:cc:dd:ee:01' "adopted AP MAC appears"
assert_match "$result" 'eap_standalone' "provider is eap_standalone"

# --- wifi_adopt_ap validation ---
result=$(vm_exec router "echo '{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:02\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_adopt_ap without url fails"

result=$(vm_exec router "echo '{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"url\":\"192.168.1.101\",\"name\":\"Test\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_adopt_ap without password fails"

# --- wifi_get_clients (empty, no real APs) ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_clients\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_get_clients succeeds"

# --- wifi_remove_ap ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_remove_ap\",\"mac\":\"aa:bb:cc:dd:ee:01\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "wifi_remove_ap succeeds"

# --- verify removed ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
assert_match "$result" '"wifi_aps":\[\]' "AP removed from list"

# --- audit log recorded ---
result=$(vm_exec router "echo '{\"method\":\"list_audit_logs\",\"limit\":10}' | socat - $SOCK")
assert_match "$result" 'wifi_adopt_ap' "adopt audit logged"
assert_match "$result" 'wifi_remove_ap' "remove audit logged"

# --- AP password not readable via get_config ---
result=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"wifi_ap_password\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "get_config blocks wifi_ap_password"

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

# --- verify password is encrypted (not plaintext) ---
stored_pass=$(vm_exec router 'python3 -c "import sqlite3; r = sqlite3.connect(\"/data/hermitshell/db/hermitshell.db\").execute(\"SELECT password_enc FROM wifi_aps WHERE mac=\\\"aa:bb:cc:dd:ee:01\\\"\").fetchone(); print(r[0] if r else \"\")"')
if [ "$stored_pass" = "testpass123" ]; then
    fail "password stored as plaintext"
fi
assert_match "$stored_pass" '.' "password_enc is not empty"
echo "PASS: password is encrypted (not plaintext)"

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

# --- wifi_adopt_ap rejects invalid IP ---
result=$(vm_exec router "echo '{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"not-an-ip\",\"name\":\"Bad\",\"key\":\"admin\",\"value\":\"pass\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_adopt_ap rejects invalid IP"

# --- wifi_adopt_ap rejects invalid name ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"192.168.1.102\",\"name\":\"bad<name>\",\"key\":\"admin\",\"value\":\"pass\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_adopt_ap rejects name with special chars"

# --- wifi_adopt_ap rejects unknown provider ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_adopt_ap\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"192.168.1.102\",\"name\":\"Test\",\"key\":\"admin\",\"value\":\"pass\",\"protocol\":\"fake\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_adopt_ap rejects unknown provider"

# --- wifi_get_ssids requires mac ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_ssids\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_get_ssids without mac fails"

# --- wifi_set_ssid validates band ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_set_ssid\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ssid_name\":\"Test\",\"band\":\"invalid\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_set_ssid rejects invalid band"

# --- wifi_set_ssid validates ssid_name length ---
long_name=$(printf 'A%.0s' {1..33})
result=$(vm_exec router "echo '{\"method\":\"wifi_set_ssid\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ssid_name\":\"$long_name\",\"band\":\"5GHz\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_ssid rejects SSID >32 chars"

# --- wifi_get_radios for non-existent AP ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_radios\",\"mac\":\"ff:ff:ff:ff:ff:ff\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_get_radios for missing AP fails"

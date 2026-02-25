#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- #68: webhook_secret blocked in set_log_config ---
result=$(vm_exec router "echo '{\"method\":\"set_log_config\",\"value\":\"{\\\\\"webhook_secret\\\\\":\\\\\"hacked\\\\\",\\\\\"log_format\\\\\":\\\\\"json\\\\\"}\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_log_config accepts valid JSON"

# Verify webhook_secret was NOT written by trying to read it via get_config (blocked, so check differently)
# Instead: set_log_config should silently ignore webhook_secret since it's not in allowed_keys.
# Verify log_format WAS written (proving the handler works, just skips webhook_secret)
result=$(vm_exec router "echo '{\"method\":\"get_log_config\"}' | socat - $SOCK")
assert_contains "$result" '"log_format":"json"' "set_log_config wrote log_format"

# Restore log_format
vm_exec router "echo '{\"method\":\"set_log_config\",\"value\":\"{\\\\\"log_format\\\\\":\\\\\"text\\\\\"}\"}' | socat - $SOCK" >/dev/null

# --- #71: set_config value length limit ---
long_value=$(python3 -c "print('x' * 5000)")
result=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"test_long\",\"value\":\"$long_value\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "set_config rejects value over 4096 bytes"
assert_match "$result" 'too long' "set_config error says too long"

# Normal value still works
result=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"test_normal_41\",\"value\":\"hello\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_config accepts normal value"

# --- #14: port forward description length limit ---
long_desc=$(python3 -c "print('d' * 300)")
result=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"tcp\",\"external_port_start\":60000,\"external_port_end\":60000,\"internal_ip\":\"10.0.0.5\",\"internal_port\":80,\"description\":\"$long_desc\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "add_port_forward rejects long description"
assert_match "$result" 'too long' "port forward error says too long"

# --- #69: audit log injection limits ---
long_action=$(python3 -c "print('a' * 100)")
result=$(vm_exec router "echo '{\"method\":\"log_audit\",\"value\":\"$long_action\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "log_audit rejects long action"
assert_match "$result" 'too long' "audit action error says too long"

long_detail=$(python3 -c "print('d' * 600)")
result=$(vm_exec router "echo '{\"method\":\"log_audit\",\"value\":\"test\",\"key\":\"$long_detail\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "log_audit rejects long detail"
assert_match "$result" 'too long' "audit detail error says too long"

# Normal audit entry still works
result=$(vm_exec router "echo '{\"method\":\"log_audit\",\"value\":\"test_action\",\"key\":\"test detail\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "log_audit accepts normal entry"

# --- #65: WiFi SSID password validation ---
# Too short password for wpa-psk
WIFI_JSON='{"method":"wifi_set_ssid","mac":"FF:FF:FF:FF:FF:FF","ssid_name":"test","band":"2.4GHz","security":"wpa-psk","value":"short"}'
result=$(vm_exec router "echo '$WIFI_JSON' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_ssid rejects short WPA-PSK password"
assert_match "$result" '8-63' "wifi password error mentions 8-63"

# No password for wpa-psk
WIFI_JSON='{"method":"wifi_set_ssid","mac":"FF:FF:FF:FF:FF:FF","ssid_name":"test","band":"2.4GHz","security":"wpa-psk"}'
result=$(vm_exec router "echo '$WIFI_JSON' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_ssid rejects missing WPA-PSK password"
assert_match "$result" 'password required' "wifi error mentions password required"

# --- #66: import_config WiFi AP validation ---
ESCAPED_IMPORT=$(python3 -c "
import json
data = {
    'version': 2, 'devices': [], 'dhcp_reservations': [], 'port_forwards': [],
    'wg_peers': [], 'ipv6_pinholes': [],
    'wifi_aps': [
        {'mac': 'AA:BB:CC:DD:EE:01', 'ip': 'not-an-ip', 'name': 'bad-ap', 'provider': 'eap_standalone'},
        {'mac': 'AA:BB:CC:DD:EE:02', 'ip': '192.168.1.100', 'name': 'good-ap', 'provider': 'eap_standalone'}
    ],
    'config': {}
}
req = {'method': 'import_config', 'value': json.dumps(data)}
print(json.dumps(req))
")
result=$(vm_exec router "echo '$ESCAPED_IMPORT' | socat - $SOCK")
assert_match "$result" '"ok":true' "import_config succeeds (skips invalid AP)"

# Verify good AP was imported but bad AP was not
result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
if echo "$result" | grep -qF "AA:BB:CC:DD:EE:01"; then
    echo -e "${RED}FAIL${NC}: import_config imported AP with invalid IP"
else
    echo -e "${GREEN}PASS${NC}: import_config skipped AP with invalid IP"
fi
assert_contains "$result" "AA:BB:CC:DD:EE:02" "import_config imported valid AP"

# Clean up imported APs
vm_exec router "echo '{\"method\":\"wifi_remove_ap\",\"mac\":\"AA:BB:CC:DD:EE:02\"}' | socat - $SOCK" >/dev/null

# --- #73: device nickname control character stripping ---
# We test that the handler accepts the input (stripping happens silently)
result=$(vm_exec router "printf '{\"method\":\"set_device_nickname\",\"mac\":\"00:00:00:00:00:01\",\"nickname\":\"clean name\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_device_nickname accepts clean name"
